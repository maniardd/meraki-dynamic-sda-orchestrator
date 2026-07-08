"""Deterministic, reviewable IOS XE configuration rendering.

Rendering has no device side effects. Secret references remain placeholders and
are resolved only by a future bounded execution worker after approval.
"""

from __future__ import annotations

import re
from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Mapping, Sequence

from .store import sha256_json


class RenderError(ValueError):
    pass


SAFE_TEXT = re.compile(r"^[A-Za-z0-9_.:/ -]+$")
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/-]+$")


def _safe(value: Any, label: str, spaces: bool = False) -> str:
    rendered = str(value)
    pattern = SAFE_TEXT if spaces else SAFE_TOKEN
    if not rendered or not pattern.fullmatch(rendered) or "\n" in rendered or "\r" in rendered:
        raise RenderError("Unsafe value for {}".format(label))
    return rendered


def _policy_name(kind: str, value: Any) -> str:
    """Return a bounded deterministic IOS XE policy-object name."""

    safe_kind = _safe(kind, "policy kind")
    digest = sha256_json(str(value))[:12].upper()
    return "SDA-{}-{}".format(safe_kind, digest)


def _isis_net(loopback_ip: str, area: str = "49.0001") -> str:
    address = ip_address(loopback_ip)
    digits = "".join("{:03d}".format(int(octet)) for octet in str(address).split("."))
    system_id = "{}.{}.{}".format(digits[0:4], digits[4:8], digits[8:12])
    return "{}.{}.00".format(_safe(area, "IS-IS area"), system_id)


def _block(block_id: str, commands: Sequence[str], secret_refs: Sequence[str] = ()) -> Dict[str, Any]:
    filtered = [command for command in commands if command]
    return {
        "block_id": block_id,
        "commands": filtered,
        "command_hash": sha256_json(filtered),
        "secret_refs": sorted(set(secret_refs)),
    }


def _device_roles(intent: Mapping[str, Any], role: str) -> List[Mapping[str, Any]]:
    return sorted(
        [device for device in intent["devices"] if role in device.get("roles", [])],
        key=lambda device: str(device["id"]),
    )


def _underlay_blocks(intent: Mapping[str, Any], device: Mapping[str, Any]) -> List[Dict[str, Any]]:
    device_id = str(device["id"])
    fabric = intent["fabric"]
    area_tag = _safe(fabric.get("isis_process", "SDA-ISIS"), "IS-IS process")
    area = _safe(fabric.get("isis_area", "49.0001"), "IS-IS area")
    multicast = fabric.get("multicast") or {}
    multicast_intent = intent.get("multicast") or {}
    multicast_enabled = bool(multicast.get("enabled", True))
    system_commands = [
        "system mtu {}".format(int(fabric["mtu"])),
        "ip routing",
    ]
    if multicast_enabled:
        system_commands.append("ip multicast-routing")
        system_commands.append("ip pim register-source Loopback0")
        if multicast.get("ssm_default", True):
            system_commands.append("ip pim ssm default")
        if multicast.get("rp_address"):
            system_commands.append(
                "ip pim rp-address {}".format(
                    _safe(multicast["rp_address"], "multicast RP address")
                )
            )
    loopback0_commands = [
        "interface Loopback0",
        " description Fabric RLOC {}".format(_safe(device["hostname"], "hostname", True)),
        " ip address {} 255.255.255.255".format(
            _safe(device["loopback0_ip"], "loopback address")
        ),
    ]
    if multicast_enabled:
        loopback0_commands.append(" ip pim sparse-mode")
    loopback0_commands.extend(
        [
            " ip router isis {}".format(area_tag),
            " no shutdown",
        ]
    )
    blocks = [
        _block(
            "system",
            system_commands,
        ),
        _block("loopback0", loopback0_commands),
        _block(
            "router_isis",
            [
                "router isis {}".format(area_tag),
                " net {}".format(_isis_net(str(device["loopback0_ip"]), area)),
                " is-type level-2-only",
                " metric-style wide",
                " log-adjacency-changes",
                " bfd all-interfaces",
                " nsf ietf",
                " passive-interface Loopback0",
            ],
        ),
    ]
    rp_device_ids = set(
        str(item)
        for item in multicast_intent.get(
            "rp_device_ids", multicast.get("rp_device_ids", [])
        )
    )
    is_rp_device = (
        device_id in rp_device_ids
        if rp_device_ids
        else str(intent.get("schema_version")) != "1.2"
        and "border" in set(device.get("roles", []))
    )
    if multicast_enabled and is_rp_device and multicast.get("rp_address"):
        rp_loopback_id = int(multicast.get("rp_loopback_id", 60000))
        blocks.append(
            _block(
                "multicast_rp_loopback",
                [
                    "interface Loopback{}".format(rp_loopback_id),
                    " description Fabric multicast RP",
                    " ip address {} 255.255.255.255".format(
                        _safe(multicast["rp_address"], "multicast RP address")
                    ),
                    " ip pim sparse-mode",
                    " ip router isis {}".format(area_tag),
                    " no shutdown",
                ],
            )
        )
        if multicast_intent.get("rp_mode") == "anycast":
            devices_by_id = {
                str(item["id"]): item for item in intent.get("devices", [])
            }
            peer_addresses = sorted(
                str(devices_by_id[peer_id]["loopback0_ip"])
                for peer_id in rp_device_ids
                if peer_id != device_id and peer_id in devices_by_id
            )
            if peer_addresses:
                blocks.append(
                    _block(
                        "multicast_msdp",
                        [
                            *[
                                "ip msdp peer {} connect-source Loopback0".format(
                                    _safe(address, "MSDP peer")
                                )
                                for address in peer_addresses
                            ],
                            "ip msdp cache-sa-state",
                            "ip msdp originator-id Loopback0",
                        ],
                    )
                )
    for link in sorted(intent.get("links", []), key=lambda item: str(item["id"])):
        endpoints = link["endpoints"]
        local = next((item for item in endpoints if item["device_id"] == device_id), None)
        if local is None:
            continue
        peer = next(item for item in endpoints if item["device_id"] != device_id)
        network = ip_network(str(link["subnet"]))
        interface = _safe(local["interface"], "interface")
        pim_sparse_mode = bool(link.get("pim_sparse_mode", True))
        bfd = link.get("bfd") or {
            "enabled": True,
            "interval_ms": 100,
            "min_rx_ms": 100,
            "multiplier": 3,
        }
        link_commands = [
            "interface {}".format(interface),
            " description Fabric link to {}".format(
                _safe(peer["device_id"], "peer device", True)
            ),
            " no switchport",
            " ip address {} {}".format(
                _safe(local["ip"], "link address"), network.netmask
            ),
        ]
        if pim_sparse_mode:
            link_commands.append(" ip pim sparse-mode")
        link_commands.extend(
            [
                " ip router isis {}".format(area_tag),
                " isis network point-to-point",
            ]
        )
        if bfd.get("enabled", False):
            link_commands.append(
                " bfd interval {} min_rx {} multiplier {}".format(
                    int(bfd["interval_ms"]),
                    int(bfd["min_rx_ms"]),
                    int(bfd["multiplier"]),
                )
            )
        link_commands.append(" no shutdown")
        blocks.append(
            _block(
                "link_{}".format(_safe(link["id"], "link id")),
                link_commands,
            )
        )
    return blocks


def _locator_block(intent: Mapping[str, Any]) -> Dict[str, Any]:
    locator_name = _safe(intent.get("lisp", {}).get("locator_set", "rloc_fabric"), "locator set")
    return _block(
        "lisp_locator",
        [
            "router lisp",
            " locator-set {}".format(locator_name),
            "  IPv4-interface Loopback0 priority 10 weight 10",
            "  exit-locator-set",
            " exit-router-lisp",
        ],
    )


def _control_plane_blocks(
    intent: Mapping[str, Any], device: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    lisp = intent["lisp"]
    site_name = _safe(lisp["site_name"], "LISP site")
    auth_ref = str(lisp["auth_key_ref"])
    site_commands = [
        "router lisp",
        " site {}".format(site_name),
        "  authentication-key <secret:{}>".format(auth_ref),
        "  description Managed SDA-style fabric site",
    ]
    virtual_networks = {item["name"]: item for item in intent["virtual_networks"]}
    for pool in sorted(intent["endpoint_pools"], key=lambda item: str(item["id"])):
        vn = virtual_networks[pool["virtual_network"]]
        site_commands.append(
            "  eid-record instance-id {} {} accept-more-specifics".format(
                int(vn["l3_instance_id"]), _safe(pool["prefix"], "endpoint prefix")
            )
        )
        site_commands.append(
            "  eid-record instance-id {} any-mac".format(int(pool["l2_instance_id"]))
        )
    site_commands.extend(["  exit-site", " exit-router-lisp"])
    loopback = _safe(device["loopback0_ip"], "control-plane loopback")
    return [
        _locator_block(intent),
        _block("lisp_site", site_commands, [auth_ref]),
        _block(
            "lisp_control_plane",
            [
                "router lisp",
                " service ipv4",
                "  encapsulation vxlan",
                "  map-server",
                "  map-resolver",
                "  proxy-etr",
                "  proxy-itr {}".format(loopback),
                "  no map-cache away-eids send-map-request",
                "  exit-service-ipv4",
                " service ethernet",
                "  map-server",
                "  map-resolver",
                "  exit-service-ethernet",
                " exit-router-lisp",
            ],
        ),
    ]


def _edge_lisp_blocks(intent: Mapping[str, Any]) -> List[Dict[str, Any]]:
    auth_ref = str(intent["lisp"]["auth_key_ref"])
    map_servers = _device_roles(intent, "control_plane")
    commands = ["router lisp", " service ipv4", "  encapsulation vxlan"]
    for server in map_servers:
        address = _safe(server["loopback0_ip"], "map server address")
        commands.extend(
            [
                "  itr map-resolver {}".format(address),
                "  etr map-server {} key <secret:{}>".format(address, auth_ref),
                "  use-petr {}".format(address),
            ]
        )
    commands.extend(["  etr", "  exit-service-ipv4", " exit-router-lisp"])
    return [_locator_block(intent), _block("lisp_edge", commands, [auth_ref])]


def _pubsub_subscriber_blocks(
    intent: Mapping[str, Any], device: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    lisp = intent.get("lisp") or {}
    device_id = str(device["id"])
    if (
        lisp.get("control_plane_mode") != "lisp_pubsub"
        or device_id not in set(lisp.get("subscribers", []))
    ):
        return []

    identity_commands = [
        "router lisp",
        " domain-id {}".format(int(lisp["domain_id"])),
    ]
    multihoming_group = next(
        (
            group
            for group in lisp.get("multihoming_groups", [])
            if device_id in set(group.get("border_device_ids", []))
        ),
        None,
    )
    if multihoming_group is not None:
        identity_commands.append(
            " multihoming-id {}".format(
                int(multihoming_group["multihoming_id"])
            )
        )
    identity_commands.append(" exit-router-lisp")

    devices = {str(item["id"]): item for item in intent["devices"]}
    publishers = [
        devices[str(publisher_id)]
        for publisher_id in sorted(lisp.get("publishers", []))
    ]
    auth_ref = str(lisp["auth_key_ref"])
    colocated_control_plane = "control_plane" in set(device.get("roles", []))
    commands = [
        "router lisp",
        " service ipv4",
    ]
    if not colocated_control_plane:
        commands.append("  encapsulation vxlan")
    commands.append("  map-cache publications")
    for publisher in publishers:
        address = _safe(publisher["loopback0_ip"], "LISP publisher address")
        commands.extend(
            [
                "  import publication publisher {}".format(address),
                "  itr map-resolver {}".format(address),
                "  etr map-server {} key <secret:{}>".format(address, auth_ref),
                "  etr map-server {} proxy-reply".format(address),
            ]
        )
    commands.append("  etr")
    if (intent.get("policy_plane") or {}).get("mode") not in {None, "none"}:
        commands.append("  sgt")
    commands.extend(
        [
            "  route-export publications",
            "  distance publications 250",
        ]
    )
    if not colocated_control_plane:
        commands.extend(
            [
                "  no map-cache away-eids send-map-request",
                "  proxy-etr",
                "  proxy-itr {}".format(
                    _safe(device["loopback0_ip"], "subscriber loopback")
                ),
            ]
        )
    commands.extend(["  exit-service-ipv4", " exit-router-lisp"])
    return [
        _block("lisp_pubsub_identity", identity_commands),
        _block("lisp_pubsub_subscriber", commands, [auth_ref]),
    ]


def _vrf_blocks(intent: Mapping[str, Any]) -> List[Dict[str, Any]]:
    blocks: List[Dict[str, Any]] = []
    for vn in sorted(intent["virtual_networks"], key=lambda item: int(item["l3_instance_id"])):
        vrf = _safe(vn["vrf"], "VRF")
        commands = [
            "vrf definition {}".format(vrf),
            " rd {}".format(_safe(vn["rd"], "route distinguisher")),
            " address-family ipv4",
        ]
        for route_target in sorted(vn["route_targets"]):
            safe_rt = _safe(route_target, "route target")
            commands.extend(
                ["  route-target import {}".format(safe_rt), "  route-target export {}".format(safe_rt)]
            )
        commands.append("  exit-address-family")
        blocks.append(_block("vrf_{}".format(vrf), commands))
        blocks.append(
            _block(
                "lisp_l3_{}".format(int(vn["l3_instance_id"])),
                [
                    "router lisp",
                    " instance-id {}".format(int(vn["l3_instance_id"])),
                    "  service ipv4",
                    "   eid-table vrf {}".format(vrf),
                    "   database-mapping limit dynamic 5000",
                    "   exit-service-ipv4",
                    "  exit-instance-id",
                    " exit-router-lisp",
                ],
            )
        )
    return blocks


def _edge_overlay_blocks(intent: Mapping[str, Any]) -> List[Dict[str, Any]]:
    blocks = _vrf_blocks(intent)
    virtual_networks = {item["name"]: item for item in intent["virtual_networks"]}
    multicast = intent.get("multicast") or {}
    bum_groups = {
        str(item["endpoint_pool_id"]): str(item["group"])
        for item in multicast.get("l2_bum_groups", [])
    }
    locator_name = _safe(intent.get("lisp", {}).get("locator_set", "rloc_fabric"), "locator set")
    for pool in sorted(intent["endpoint_pools"], key=lambda item: int(item["vlan_id"])):
        vn = virtual_networks[pool["virtual_network"]]
        vlan = int(pool["vlan_id"])
        vrf = _safe(vn["vrf"], "VRF")
        prefix = ip_network(str(pool["prefix"]))
        blocks.append(
            _block(
                "vlan_{}".format(vlan),
                ["vlan {}".format(vlan), " name {}".format(_safe(pool["id"], "pool id", True))],
            )
        )
        svi = [
            "interface Vlan{}".format(vlan),
            " description Anycast gateway {}".format(_safe(pool["id"], "pool id", True)),
            " vrf forwarding {}".format(vrf),
            " ip address {} {}".format(_safe(pool["gateway"], "gateway"), prefix.netmask),
            " no ip redirects",
        ]
        for helper in pool.get("dhcp_helpers", []):
            svi.append(" ip helper-address {}".format(_safe(helper, "DHCP helper")))
        svi.append(" no shutdown")
        blocks.append(_block("svi_{}".format(vlan), svi))
        lisp_pool_commands = [
            "router lisp",
            " instance-id {}".format(int(vn["l3_instance_id"])),
            "  dynamic-eid {}".format(_safe(pool["id"], "dynamic EID")),
            "   database-mapping {} locator-set {}".format(prefix, locator_name),
            "   exit-dynamic-eid",
            "  exit-instance-id",
            " instance-id {}".format(int(pool["l2_instance_id"])),
            "  service ethernet",
            "   eid-table vlan {}".format(vlan),
        ]
        bum_group = bum_groups.get(str(pool["id"]))
        if bum_group:
            lisp_pool_commands.append(
                "   broadcast-underlay {}".format(
                    _safe(bum_group, "L2 BUM multicast group")
                )
            )
        elif str(intent.get("schema_version")) != "1.2":
            lisp_pool_commands.append("   broadcast-underlay 232.0.0.1")
        lisp_pool_commands.extend(
            [
                "   database-mapping mac locator-set {}".format(locator_name),
                "   exit-service-ethernet",
                "  exit-instance-id",
                " exit-router-lisp",
            ]
        )
        blocks.append(
            _block(
                "lisp_pool_{}".format(_safe(pool["id"], "pool id")),
                lisp_pool_commands,
            )
        )
    return blocks


def _multicast_overlay_blocks(
    intent: Mapping[str, Any], device: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    """Render the native LISP/VXLAN Layer-3 multicast contract."""

    multicast = intent.get("multicast") or {}
    if not multicast.get("enabled"):
        return []
    if multicast.get("transport") != "native":
        return []
    device_id = str(device["id"])
    roles = set(device.get("roles", []))
    locator_name = _safe(
        intent.get("lisp", {}).get("locator_set", "rloc_fabric"),
        "locator set",
    )
    endpoint_pools_by_vn: Dict[str, List[Mapping[str, Any]]] = {}
    for pool in intent.get("endpoint_pools", []):
        endpoint_pools_by_vn.setdefault(str(pool["virtual_network"]), []).append(
            pool
        )
    handoff_peers_by_vrf: Dict[str, List[Mapping[str, Any]]] = {}
    for peer in (intent.get("border_handoff") or {}).get("peers", []):
        if str(peer.get("device_id")) == device_id:
            handoff_peers_by_vrf.setdefault(str(peer["vrf"]), []).append(peer)

    blocks: List[Dict[str, Any]] = []
    for policy in sorted(
        multicast.get("overlay_policies", []),
        key=lambda item: int(item["l3_instance_id"]),
    ):
        loopback = next(
            (
                item
                for item in policy.get("segment_loopbacks", [])
                if str(item.get("device_id")) == device_id
            ),
            None,
        )
        if loopback is None:
            continue
        virtual_network = str(policy["virtual_network"])
        vrf = _safe(policy["vrf"], "multicast VRF")
        instance_id = int(policy["l3_instance_id"])
        segment_address = _safe(loopback["address"], "multicast segment address")
        group_range = ip_network(str(policy["group_range"]))
        access_list = _safe(policy["access_list"], "multicast access list")

        policy_commands = [
            "ip multicast-routing vrf {}".format(vrf),
            "no ip access-list standard {}".format(access_list),
            "ip access-list standard {}".format(access_list),
            " 10 permit {} {}".format(group_range.network_address, group_range.hostmask),
        ]
        if policy["mode"] == "ssm":
            policy_commands.append(
                "ip pim vrf {} ssm range {}".format(vrf, access_list)
            )
        else:
            policy_commands.extend(
                [
                    "ip pim vrf {} register-source Loopback{}".format(
                        vrf, instance_id
                    ),
                    "ip pim vrf {} rp-address {} {}".format(
                        vrf,
                        _safe(policy["rp_address"], "overlay RP address"),
                        access_list,
                    ),
                ]
            )
        blocks.append(
            _block(
                "multicast_policy_{}".format(instance_id), policy_commands
            )
        )
        blocks.append(
            _block(
                "multicast_segment_{}".format(instance_id),
                [
                    "interface Loopback{}".format(instance_id),
                    " description SDA multicast segment {}".format(
                        _safe(virtual_network, "virtual network", True)
                    ),
                    " vrf forwarding {}".format(vrf),
                    " ip address {} 255.255.255.255".format(segment_address),
                    " ip pim sparse-mode",
                    " no shutdown",
                ],
            )
        )
        core_group = policy["core_group"]
        blocks.append(
            _block(
                "multicast_lisp_{}".format(instance_id),
                [
                    "interface LISP0.{}".format(instance_id),
                    " vrf forwarding {}".format(vrf),
                    " ip pim lisp transport multicast",
                    " ip pim lisp core-group-range {} {}".format(
                        _safe(core_group["start"], "core group start"),
                        int(core_group["count"]),
                    ),
                ],
            )
        )
        blocks.append(
            _block(
                "multicast_lisp_database_{}".format(instance_id),
                [
                    "router lisp",
                    " instance-id {}".format(instance_id),
                    "  service ipv4",
                    "   database-mapping {}/32 locator-set {}".format(
                        segment_address, locator_name
                    ),
                    "   exit-service-ipv4",
                    "  exit-instance-id",
                    " exit-router-lisp",
                ],
            )
        )

        if "fabric_edge" in roles:
            for pool in sorted(
                endpoint_pools_by_vn.get(virtual_network, []),
                key=lambda item: int(item["vlan_id"]),
            ):
                vlan_id = int(pool["vlan_id"])
                blocks.append(
                    _block(
                        "multicast_edge_svi_{}".format(vlan_id),
                        [
                            "interface Vlan{}".format(vlan_id),
                            " ip pim passive",
                            " ip igmp version 3",
                            " ip igmp explicit-tracking",
                        ],
                    )
                )
        if "border" in roles:
            for peer in sorted(
                handoff_peers_by_vrf.get(vrf, []),
                key=lambda item: int(item["vlan_id"]),
            ):
                blocks.append(
                    _block(
                        "multicast_border_handoff_{}".format(int(peer["vlan_id"])),
                        [
                            "interface {}".format(
                                _safe(peer["interface"], "multicast handoff interface")
                            ),
                            " ip pim sparse-mode",
                        ],
                    )
                )
    return blocks


def _fusion_multicast_blocks(
    intent: Mapping[str, Any], fusion: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    """Render the fusion side of each native multicast VRF handoff."""

    multicast = intent.get("multicast") or {}
    if not multicast.get("enabled") or multicast.get("transport") != "native":
        return []
    fusion_id = str(fusion["id"])
    handoff_peers = list((intent.get("border_handoff") or {}).get("peers", []))
    blocks: List[Dict[str, Any]] = []
    for policy in sorted(
        multicast.get("overlay_policies", []),
        key=lambda item: int(item["l3_instance_id"]),
    ):
        vrf = _safe(policy["vrf"], "multicast VRF")
        peers = sorted(
            (
                peer
                for peer in handoff_peers
                if str(peer.get("fusion_node_id")) == fusion_id
                and str(peer.get("vrf")) == str(policy["vrf"])
            ),
            key=lambda item: int(item["vlan_id"]),
        )
        if not peers:
            continue
        group_range = ip_network(str(policy["group_range"]))
        access_list = _safe(policy["access_list"], "multicast access list")
        policy_commands = [
            "ip multicast-routing vrf {}".format(vrf),
            "no ip access-list standard {}".format(access_list),
            "ip access-list standard {}".format(access_list),
            " 10 permit {} {}".format(
                group_range.network_address, group_range.hostmask
            ),
        ]
        if policy["mode"] == "ssm":
            policy_commands.append(
                "ip pim vrf {} ssm range {}".format(vrf, access_list)
            )
        else:
            policy_commands.append(
                "ip pim vrf {} rp-address {} {}".format(
                    vrf,
                    _safe(policy["rp_address"], "overlay RP address"),
                    access_list,
                )
            )
        blocks.append(
            _block(
                "fusion_multicast_policy_{}".format(
                    int(policy["l3_instance_id"])
                ),
                policy_commands,
            )
        )
        for peer in peers:
            vlan_id = int(peer["vlan_id"])
            blocks.append(
                _block(
                    "fusion_multicast_handoff_{}".format(vlan_id),
                    [
                        "interface Vlan{}".format(vlan_id),
                        " ip pim sparse-mode",
                    ],
                )
            )
    return blocks


def _border_handoff_blocks(
    intent: Mapping[str, Any], device: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    handoff = intent.get("border_handoff") or {}
    if not handoff.get("enabled"):
        return []
    local_as = int(handoff["local_as"])
    blocks: List[Dict[str, Any]] = []
    trunk_vlans: Dict[str, List[int]] = {}
    for peer in handoff.get("peers", []):
        if peer.get("device_id") != device["id"]:
            continue
        vrf = _safe(peer["vrf"], "handoff VRF")
        neighbor = _safe(peer["neighbor_ip"], "BGP neighbor")
        remote_as = int(peer["remote_as"])
        interface = _safe(peer["interface"], "handoff interface")
        prefix = ip_network(str(peer["prefix"]))
        local_ip = _safe(peer["local_ip"], "handoff local IP")
        vlan_id = int(peer["vlan_id"])
        if peer.get("border_interface"):
            physical_interface = _safe(
                peer["border_interface"], "border physical interface"
            )
            trunk_vlans.setdefault(physical_interface, []).append(vlan_id)
        blocks.append(
            _block(
                "handoff_{}_{}".format(vrf, vlan_id),
                [
                    "vlan {}".format(vlan_id),
                    " name SDA-HANDOFF-{}".format(vrf),
                    "interface {}".format(interface),
                    " description BGP fusion handoff {}".format(vrf),
                    " vrf forwarding {}".format(vrf),
                    " ip address {} {}".format(local_ip, prefix.netmask),
                    " no shutdown",
                ],
            )
        )
        blocks.append(
            _block(
                "bgp_{}_{}".format(vrf, neighbor.replace(".", "_")),
                [
                    "router bgp {}".format(local_as),
                    " bgp router-id {}".format(_safe(device["loopback0_ip"], "BGP router ID")),
                    " address-family ipv4 vrf {}".format(vrf),
                    "  neighbor {} remote-as {}".format(neighbor, remote_as),
                    "  neighbor {} activate".format(neighbor),
                    "  redistribute lisp metric 10",
                    "  exit-address-family",
                ],
            )
        )
    for interface, vlans in sorted(trunk_vlans.items()):
        blocks.insert(
            0,
            _block(
                "border_trunk_{}".format(interface.replace("/", "_")),
                [
                    "interface {}".format(interface),
                    " description SDA fusion handoff trunk",
                    " switchport mode trunk",
                    " switchport trunk allowed vlan {}".format(
                        ",".join(str(item) for item in sorted(vlans))
                    ),
                    " no shutdown",
                ],
            ),
        )
    return blocks


def _fusion_handoff_blocks(
    intent: Mapping[str, Any], fusion: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    """Render the deterministic VRF-lite/BGP side owned by a fusion node.

    Shared-service route leaking remains a separately blocked phase until its
    prefix-list and route-map failure/rollback acceptance tests are complete.
    """

    handoff = intent.get("border_handoff") or {}
    if not handoff.get("enabled"):
        return []
    fusion_id = str(fusion["id"])
    local_as = int(fusion["bgp_asn"])
    border_as = int(handoff["local_as"])
    virtual_networks = {item["vrf"]: item for item in intent["virtual_networks"]}
    peers = sorted(
        (
            item
            for item in handoff.get("peers", [])
            if str(item.get("fusion_node_id", "")) == fusion_id
        ),
        key=lambda item: (str(item["vrf"]), int(item["vlan_id"])),
    )
    blocks: List[Dict[str, Any]] = []
    rendered_vrfs = set()
    trunk_vlans: Dict[str, List[int]] = {}
    for peer in peers:
        vrf = _safe(peer["vrf"], "fusion VRF")
        vn = virtual_networks[peer["vrf"]]
        if vrf not in rendered_vrfs:
            rendered_vrfs.add(vrf)
            blocks.append(
                _block(
                    "fusion_vrf_{}".format(vrf),
                    [
                        "vrf definition {}".format(vrf),
                        " rd {}".format(_safe(vn["rd"], "route distinguisher")),
                        " address-family ipv4",
                        "  exit-address-family",
                    ],
                )
            )
        vlan_id = int(peer["vlan_id"])
        fusion_interface = _safe(peer["fusion_interface"], "fusion physical interface")
        trunk_vlans.setdefault(fusion_interface, []).append(vlan_id)
        prefix = ip_network(str(peer["prefix"]))
        local_ip = _safe(peer["neighbor_ip"], "fusion local IP")
        neighbor_ip = _safe(peer["local_ip"], "border neighbor IP")
        blocks.append(
            _block(
                "fusion_handoff_{}_{}".format(vrf, vlan_id),
                [
                    "vlan {}".format(vlan_id),
                    " name SDA-HANDOFF-{}".format(vrf),
                    "interface Vlan{}".format(vlan_id),
                    " description SDA border handoff {}".format(vrf),
                    " vrf forwarding {}".format(vrf),
                    " ip address {} {}".format(local_ip, prefix.netmask),
                    " no shutdown",
                ],
            )
        )
        blocks.append(
            _block(
                "fusion_bgp_{}_{}".format(vrf, neighbor_ip.replace(".", "_")),
                [
                    "router bgp {}".format(local_as),
                    " address-family ipv4 vrf {}".format(vrf),
                    "  neighbor {} remote-as {}".format(neighbor_ip, border_as),
                    "  neighbor {} activate".format(neighbor_ip),
                    "  exit-address-family",
                ],
            )
        )
    for interface, vlans in sorted(trunk_vlans.items()):
        blocks.insert(
            0,
            _block(
                "fusion_trunk_{}".format(interface.replace("/", "_")),
                [
                    "interface {}".format(interface),
                    " description SDA border handoff trunk",
                    " switchport mode trunk",
                    " switchport trunk allowed vlan {}".format(
                        ",".join(str(item) for item in sorted(vlans))
                    ),
                    " no shutdown",
                ],
            ),
        )
    return blocks


def _fusion_shared_service_blocks(
    intent: Mapping[str, Any], fusion: Mapping[str, Any]
) -> List[Dict[str, Any]]:
    """Render deny-by-default filtered route leaking on one fusion node."""

    shared = intent.get("shared_services") or {}
    if not shared:
        return []
    fusion_id = str(fusion["id"])
    attachment = next(
        (
            item
            for item in shared.get("attachments", [])
            if str(item.get("fusion_node_id", "")) == fusion_id
        ),
        None,
    )
    if not attachment:
        raise RenderError(
            "Fusion node {} has no shared-service attachment".format(fusion_id)
        )

    virtual_networks = {item["vrf"]: item for item in intent["virtual_networks"]}
    service_vrf = _safe(shared["vrf"], "shared-services VRF")
    if service_vrf not in virtual_networks:
        raise RenderError("Shared-services VRF is not a virtual network")
    service_rt = _safe(
        virtual_networks[service_vrf]["route_targets"][0],
        "shared-services route target",
    )
    route_leaks = sorted(
        shared.get("route_leaks", []), key=lambda item: str(item["consumer_vrf"])
    )
    service_prefixes = sorted(
        {
            str(prefix)
            for service in shared.get("services", [])
            for prefix in service.get("prefixes", [])
        }
    )
    consumer_prefixes = sorted(
        {
            str(prefix)
            for leak in route_leaks
            for prefix in leak.get("export_prefixes", [])
        }
    )
    if not service_prefixes or not consumer_prefixes:
        raise RenderError("Shared-services route policy has no approved prefixes")

    def policy_blocks(label: str, prefixes: Sequence[str]) -> List[Dict[str, Any]]:
        prefix_name = _policy_name("PFX", label)
        route_map_name = _policy_name("RMAP", label)
        prefix_commands = ["no ip prefix-list {}".format(prefix_name)] + [
            "ip prefix-list {} seq {} permit {}".format(
                prefix_name, index * 10, _safe(prefix, "route-leak prefix")
            )
            for index, prefix in enumerate(sorted(set(prefixes)), start=1)
        ]
        return [
            _block("prefix_list_{}".format(label), prefix_commands),
            _block(
                "route_map_{}".format(label),
                [
                    "no route-map {}".format(route_map_name),
                    "route-map {} permit 10".format(route_map_name),
                    " match ip address prefix-list {}".format(prefix_name),
                ],
            ),
        ]

    blocks: List[Dict[str, Any]] = []
    service_export_label = "service_export"
    service_import_label = "service_import"
    blocks.extend(policy_blocks(service_export_label, service_prefixes))
    blocks.extend(policy_blocks(service_import_label, consumer_prefixes))

    consumer_route_targets = []
    for leak in route_leaks:
        consumer_vrf = _safe(leak["consumer_vrf"], "consumer VRF")
        if consumer_vrf not in virtual_networks:
            raise RenderError("Shared-services consumer VRF is unknown")
        consumer_rt = _safe(
            virtual_networks[consumer_vrf]["route_targets"][0],
            "consumer route target",
        )
        consumer_route_targets.append(consumer_rt)
        export_label = "{}_export".format(consumer_vrf)
        import_label = "{}_import".format(consumer_vrf)
        blocks.extend(policy_blocks(export_label, leak["export_prefixes"]))
        blocks.extend(policy_blocks(import_label, leak["import_prefixes"]))
        blocks.append(
            _block(
                "shared_leak_vrf_{}".format(consumer_vrf),
                [
                    "vrf definition {}".format(consumer_vrf),
                    " address-family ipv4",
                    "  route-target export {}".format(consumer_rt),
                    "  route-target import {}".format(service_rt),
                    "  export map {}".format(_policy_name("RMAP", export_label)),
                    "  import map {}".format(_policy_name("RMAP", import_label)),
                    "  exit-address-family",
                ],
            )
        )

    shared_vrf_commands = [
        "vrf definition {}".format(service_vrf),
        " address-family ipv4",
        "  route-target export {}".format(service_rt),
    ]
    shared_vrf_commands.extend(
        "  route-target import {}".format(item)
        for item in sorted(set(consumer_route_targets))
    )
    shared_vrf_commands.extend(
        [
            "  export map {}".format(
                _policy_name("RMAP", service_export_label)
            ),
            "  import map {}".format(
                _policy_name("RMAP", service_import_label)
            ),
            "  exit-address-family",
        ]
    )
    blocks.append(_block("shared_service_vrf_policy", shared_vrf_commands))

    vlan_id = int(attachment["vlan_id"])
    interface = _safe(attachment["interface"], "shared-service interface")
    prefix = ip_network(str(attachment["prefix"]))
    local_ip = _safe(attachment["local_ip"], "shared-service local IP")
    next_hop = _safe(attachment["next_hop"], "shared-service next hop")
    blocks.append(
        _block(
            "shared_service_attachment",
            [
                "vlan {}".format(vlan_id),
                " name SDA-SHARED-SERVICES",
                "interface {}".format(interface),
                " description SDA shared-services handoff",
                " switchport mode trunk",
                " switchport trunk allowed vlan {}".format(vlan_id),
                " no shutdown",
                "interface Vlan{}".format(vlan_id),
                " description SDA shared-services routed handoff",
                " vrf forwarding {}".format(service_vrf),
                " ip address {} {}".format(local_ip, prefix.netmask),
                " no shutdown",
            ],
        )
    )
    blocks.append(
        _block(
            "shared_service_static_routes",
            [
                "ip route vrf {} {} {} {}".format(
                    service_vrf,
                    ip_network(item).network_address,
                    ip_network(item).netmask,
                    next_hop,
                )
                for item in service_prefixes
            ],
        )
    )
    blocks.append(
        _block(
            "shared_service_bgp_redistribution",
            [
                "router bgp {}".format(int(fusion["bgp_asn"])),
                " address-family ipv4 vrf {}".format(service_vrf),
                "  redistribute static",
                "  exit-address-family",
            ],
        )
    )
    return blocks


def render_configuration(intent: Mapping[str, Any], plan: Mapping[str, Any]) -> Dict[str, Any]:
    """Render deterministic per-device phase artifacts for human review."""
    if str(plan["intent_hash"]) != sha256_json(intent):
        raise RenderError("Plan intent hash does not match the supplied intent")

    artifacts: Dict[str, Any] = {}
    blockers: List[Dict[str, str]] = []
    handoff = intent.get("border_handoff") or {}
    if not handoff.get("enabled") and handoff.get("mode") != "isolated":
        blockers.append(
            {
                "code": "border_handoff.missing",
                "message": "BGP/fusion handoff is not defined; apply remains disabled",
            }
        )
    if intent.get("fabric", {}).get("control_plane_mode") == "lisp_pubsub":
        blockers.append(
            {
                "code": "lisp_pubsub.hardware_acceptance_pending",
                "message": "LISP Pub/Sub subscriber CLI and operational gates are rendered and rollback-tested but await compatible IOS XE hardware acceptance",
            }
        )
    if intent.get("shared_services"):
        blockers.append(
            {
                "code": "shared_services.hardware_acceptance_pending",
                "message": "Shared-service route leaking is rendered and rollback-tested but awaits compatible IOS XE fusion hardware acceptance",
            }
        )
    multicast = intent.get("multicast") or {}
    if multicast.get("enabled") and multicast.get("transport") == "native":
        blockers.append(
            {
                "code": "multicast.hardware_acceptance_pending",
                "message": "Native overlay ASM/SSM fabric and fusion CLI plus operational gates are rendered but await compatible IOS XE hardware acceptance and traffic-flow proof",
            }
        )
    elif multicast.get("enabled"):
        blockers.append(
            {
                "code": "multicast.head_end_replication_renderer_pending",
                "message": "Head-end replication remains disabled until its release-specific renderer and acceptance suite are complete",
            }
        )
    if (intent.get("policy_plane") or {}).get("mode") not in {None, "none"}:
        blockers.append(
            {
                "code": "policy_plane.renderer_pending",
                "message": "ISE/SGT/SXP publishing remains disabled until API and rollback acceptance passes",
            }
        )

    for device in sorted(intent["devices"], key=lambda item: str(item["id"])):
        roles = set(device.get("roles", []))
        phases: List[Dict[str, Any]] = [
            {"phase_id": "underlay", "blocks": _underlay_blocks(intent, device)}
        ]
        if "control_plane" in roles:
            phases.append(
                {
                    "phase_id": "lisp_control_plane",
                    "blocks": _control_plane_blocks(intent, device),
                }
            )
        if "fabric_edge" in roles:
            phases.append({"phase_id": "lisp_edges", "blocks": _edge_lisp_blocks(intent)})
            overlay_blocks = _edge_overlay_blocks(intent)
            if "border" in roles:
                overlay_blocks.extend(_pubsub_subscriber_blocks(intent, device))
            phases.append({"phase_id": "overlay", "blocks": overlay_blocks})
        elif "border" in roles:
            phases.append(
                {
                    "phase_id": "overlay",
                    "blocks": _vrf_blocks(intent)
                    + _pubsub_subscriber_blocks(intent, device),
                }
            )
        multicast_blocks = _multicast_overlay_blocks(intent, device)
        if multicast_blocks:
            phases.append(
                {"phase_id": "multicast", "blocks": multicast_blocks}
            )
        if "border" in roles:
            phases.append(
                {
                    "phase_id": "border_handoff",
                    "blocks": _border_handoff_blocks(intent, device),
                }
            )
        artifacts[str(device["id"])] = {
            "hostname": str(device["hostname"]),
            "platform": str(device["platform"]),
            "software_version": str(device["software_version"]),
            "roles": sorted(roles),
            "phases": phases,
        }

    for fusion in sorted(intent.get("fusion_nodes", []), key=lambda item: str(item["id"])):
        fusion_multicast_blocks = _fusion_multicast_blocks(intent, fusion)
        fusion_phases = [
            {
                "phase_id": "border_handoff",
                "blocks": _fusion_handoff_blocks(intent, fusion),
            },
            {
                "phase_id": "shared_services",
                "blocks": _fusion_shared_service_blocks(intent, fusion),
            },
        ]
        if fusion_multicast_blocks:
            fusion_phases.append(
                {"phase_id": "multicast", "blocks": fusion_multicast_blocks}
            )
        artifacts[str(fusion["id"])] = {
            "hostname": str(fusion["hostname"]),
            "platform": str(fusion["platform"]),
            "software_version": str(fusion["software_version"]),
            "roles": ["fusion"],
            "phases": fusion_phases,
        }

    body = {
        "artifact_schema_version": "1.0",
        "intent_schema_version": str(intent["schema_version"]),
        "plan_id": str(plan["plan_id"]),
        "plan_hash": str(plan["plan_hash"]),
        "intent_hash": str(plan["intent_hash"]),
        "fabric_id": str(intent["fabric"]["id"]),
        "devices": artifacts,
        "blocking_requirements": blockers,
        "contains_secret_values": False,
        "review_required": True,
        "executable": False,
    }
    body["artifact_hash"] = sha256_json(body)
    return body
