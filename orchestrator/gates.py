"""Intent-derived operational gate specifications and evaluators."""

from __future__ import annotations

from ipaddress import ip_network
from typing import Any, Dict, List, Mapping

from .parsers import (
    GateResult,
    verify_config_lines_absent,
    verify_bgp_neighbors,
    verify_exact_config_lines,
    verify_isis_neighbors,
    verify_ios_xe_license_level,
    verify_ios_xe_version,
    verify_lisp_identity,
    verify_lisp_publishers,
    verify_lisp_sessions,
    verify_msdp_peers,
    verify_nve_peers,
    verify_pim_interfaces,
    verify_role_permission,
    verify_route_prefix,
    verify_sxp_connections,
)


def build_gate_plan(
    intent: Mapping[str, Any], artifact: Mapping[str, Any] | None = None
) -> List[Dict[str, Any]]:
    gates: List[Dict[str, Any]] = []
    if artifact is not None:
        reconciliation = artifact.get("reconciliation") or {}
        active_device_ids = {
            str(item["id"])
            for item in list(intent.get("devices", []))
            + list(intent.get("fusion_nodes", []))
        }
        for device_id, device in sorted(
            reconciliation.get("devices", {}).items()
        ):
            if str(device_id) not in active_device_ids:
                descriptor = device.get("device") or {}
                gates.append(
                    {
                        "gate_id": "precheck.version.{}".format(device_id),
                        "phase_id": "precheck",
                        "device_id": str(device_id),
                        "command": "show version",
                        "evaluator": "ios_xe_version",
                        "expected": {
                            "version": str(descriptor["software_version"])
                        },
                        "blocking": True,
                    }
                )
            for gate in device.get("gates", []):
                if str(gate.get("device_id")) != str(device_id):
                    raise ValueError("Reconciliation gate device identity mismatch")
                gates.append(dict(gate))
    incident_links: Dict[str, int] = {str(device["id"]): 0 for device in intent["devices"]}
    for link in intent.get("links", []):
        for endpoint in link["endpoints"]:
            incident_links[str(endpoint["device_id"])] += 1

    map_server_count = len(intent["lisp"]["map_servers"])
    devices_by_id = {str(device["id"]): device for device in intent["devices"]}
    lisp = intent.get("lisp") or {}
    pubsub_publishers = [
        str(devices_by_id[str(device_id)]["loopback0_ip"])
        for device_id in sorted(lisp.get("publishers", []))
    ]
    pubsub_subscribers = set(str(item) for item in lisp.get("subscribers", []))
    pubsub_multihoming_by_device = {
        str(device_id): int(group["multihoming_id"])
        for group in lisp.get("multihoming_groups", [])
        for device_id in group.get("border_device_ids", [])
    }
    handoff = intent.get("border_handoff") or {}
    peers_by_device: Dict[str, List[str]] = {}
    peers_by_fusion: Dict[str, List[str]] = {}
    for peer in handoff.get("peers", []):
        peers_by_device.setdefault(str(peer["device_id"]), []).append(str(peer["neighbor_ip"]))
        if peer.get("fusion_node_id"):
            peers_by_fusion.setdefault(str(peer["fusion_node_id"]), []).append(
                str(peer["local_ip"])
            )

    for device in sorted(intent["devices"], key=lambda item: str(item["id"])):
        device_id = str(device["id"])
        roles = set(device.get("roles", []))
        gates.append(
            {
                "gate_id": "precheck.version.{}".format(device_id),
                "phase_id": "precheck",
                "device_id": device_id,
                "command": "show version",
                "evaluator": "ios_xe_version",
                "expected": {"version": str(device["software_version"])},
                "blocking": True,
            }
        )
        gates.append(
            {
                "gate_id": "precheck.license.{}".format(device_id),
                "phase_id": "precheck",
                "device_id": device_id,
                "command": "show version",
                "evaluator": "ios_xe_license_level",
                "expected": {
                    "network_package": "network-advantage",
                    "subscription_packages": [
                        "catalyst-advantage",
                        "dna-advantage",
                    ],
                },
                "blocking": True,
            }
        )
        multicast = intent.get("multicast") or {}
        rp_device_ids = set(str(item) for item in multicast.get("rp_device_ids", []))
        if (
            multicast.get("enabled")
            and multicast.get("rp_mode") == "anycast"
            and device_id in rp_device_ids
        ):
            devices = {
                str(item["id"]): item for item in intent.get("devices", [])
            }
            expected_msdp_peers = sorted(
                str(devices[peer_id]["loopback0_ip"])
                for peer_id in rp_device_ids
                if peer_id != device_id and peer_id in devices
            )
            gates.append(
                {
                    "gate_id": "underlay.msdp.{}".format(device_id),
                    "phase_id": "underlay",
                    "device_id": device_id,
                    "command": "show ip msdp peer",
                    "evaluator": "msdp_peers",
                    "expected": {"peers": expected_msdp_peers},
                    "blocking": True,
                }
            )
        gates.append(
            {
                "gate_id": "underlay.isis.{}".format(device_id),
                "phase_id": "underlay",
                "device_id": device_id,
                "command": "show isis neighbors",
                "evaluator": "isis_neighbors",
                "expected": {"minimum_up": incident_links[device_id]},
                "blocking": True,
            }
        )
        if "fabric_edge" in roles:
            gates.append(
                {
                    "gate_id": "lisp.sessions.{}".format(device_id),
                    "phase_id": "lisp_edges",
                    "device_id": device_id,
                    "command": "show lisp session",
                    "evaluator": "lisp_sessions",
                    "expected": {"minimum_established": map_server_count},
                    "blocking": True,
                }
            )
            gates.append(
                {
                    "gate_id": "overlay.nve.{}".format(device_id),
                    "phase_id": "overlay",
                    "device_id": device_id,
                    "command": "show nve peers",
                    "evaluator": "nve_peers",
                    "expected": {"minimum_up": max(1, map_server_count)},
                    "blocking": True,
                }
            )
        if "border" in roles and handoff.get("enabled"):
            gates.append(
                {
                    "gate_id": "border.bgp.{}".format(device_id),
                    "phase_id": "border_handoff",
                    "device_id": device_id,
                    "command": "show bgp ipv4 unicast vrf all summary",
                    "evaluator": "bgp_neighbors",
                    "expected": {"neighbors": sorted(peers_by_device.get(device_id, []))},
                    "blocking": True,
                }
            )
        if (
            lisp.get("control_plane_mode") == "lisp_pubsub"
            and device_id in pubsub_subscribers
        ):
            gates.append(
                {
                    "gate_id": "lisp.identity.{}".format(device_id),
                    "phase_id": "overlay",
                    "device_id": device_id,
                    "command": "show running-config | section ^router lisp",
                    "evaluator": "lisp_identity",
                    "expected": {
                        "domain_id": int(lisp["domain_id"]),
                        "multihoming_id": pubsub_multihoming_by_device.get(device_id),
                    },
                    "blocking": True,
                }
            )
            for virtual_network in sorted(
                intent.get("virtual_networks", []),
                key=lambda item: int(item["l3_instance_id"]),
            ):
                instance_id = int(virtual_network["l3_instance_id"])
                gates.append(
                    {
                        "gate_id": "lisp.pubsub.{}.{}".format(
                            device_id, instance_id
                        ),
                        "phase_id": "overlay",
                        "device_id": device_id,
                        "command": "show lisp instance-id {} ipv4 publisher config-propagation".format(
                            instance_id
                        ),
                        "evaluator": "lisp_publishers",
                        "expected": {"publishers": pubsub_publishers},
                        "blocking": True,
                    }
                )
        multicast = intent.get("multicast") or {}
        if multicast.get("enabled") and multicast.get("transport") == "native":
            endpoint_pools_by_vn: Dict[str, List[Mapping[str, Any]]] = {}
            for pool in intent.get("endpoint_pools", []):
                endpoint_pools_by_vn.setdefault(
                    str(pool["virtual_network"]), []
                ).append(pool)
            for policy in sorted(
                multicast.get("overlay_policies", []),
                key=lambda item: int(item["l3_instance_id"]),
            ):
                if device_id not in {
                    str(item["device_id"])
                    for item in policy.get("segment_loopbacks", [])
                }:
                    continue
                vrf = str(policy["vrf"])
                instance_id = int(policy["l3_instance_id"])
                access_list = str(policy["access_list"])
                expected_interfaces = [
                    "Loopback{}".format(instance_id),
                    "LISP0.{}".format(instance_id),
                ]
                passive_svis = (
                    sorted(
                        int(pool["vlan_id"])
                        for pool in endpoint_pools_by_vn.get(
                            str(policy["virtual_network"]), []
                        )
                    )
                    if "fabric_edge" in roles
                    else []
                )
                if "border" in roles:
                    expected_interfaces.extend(
                        str(peer["interface"])
                        for peer in handoff.get("peers", [])
                        if str(peer.get("device_id")) == device_id
                        and str(peer.get("vrf")) == vrf
                    )
                expected_policy_lines = ["ip multicast-routing vrf {}".format(vrf)]
                if policy["mode"] == "ssm":
                    expected_policy_lines.append(
                        "ip pim vrf {} ssm range {}".format(vrf, access_list)
                    )
                else:
                    expected_policy_lines.extend(
                        [
                            "ip pim vrf {} register-source Loopback{}".format(
                                vrf, instance_id
                            ),
                            "ip pim vrf {} rp-address {} {}".format(
                                vrf, policy["rp_address"], access_list
                            ),
                        ]
                    )
                gates.extend(
                    [
                        {
                            "gate_id": "multicast.policy.{}.{}".format(
                                device_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": device_id,
                            "command": "show running-config | include ^ip multicast-routing vrf {}|^ip pim vrf {}".format(
                                vrf, vrf
                            ),
                            "evaluator": "exact_config_lines",
                            "expected": {"lines": expected_policy_lines},
                            "blocking": True,
                        },
                        {
                            "gate_id": "multicast.acl.{}.{}".format(
                                device_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": device_id,
                            "command": "show running-config | section ^ip access-list standard {}$".format(
                                access_list
                            ),
                            "evaluator": "exact_config_lines",
                            "expected": {
                                "lines": [
                                    "ip access-list standard {}".format(access_list),
                                    "10 permit {} {}".format(
                                        ip_network(
                                            str(policy["group_range"])
                                        ).network_address,
                                        ip_network(
                                            str(policy["group_range"])
                                        ).hostmask,
                                    ),
                                ]
                            },
                            "blocking": True,
                        },
                        {
                            "gate_id": "multicast.pim.{}.{}".format(
                                device_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": device_id,
                            "command": "show ip pim vrf {} interface".format(vrf),
                            "evaluator": "pim_interfaces",
                            "expected": {
                                "interfaces": sorted(set(expected_interfaces))
                            },
                            "blocking": True,
                        },
                    ]
                )
                for vlan_id in passive_svis:
                    gates.append(
                        {
                            "gate_id": "multicast.passive_svi.{}.{}".format(
                                device_id, vlan_id
                            ),
                            "phase_id": "multicast",
                            "device_id": device_id,
                            "command": "show running-config | section ^interface Vlan{}$".format(
                                vlan_id
                            ),
                            "evaluator": "exact_config_lines",
                            "expected": {
                                "lines": [
                                    "interface Vlan{}".format(vlan_id),
                                    "ip pim passive",
                                    "ip igmp version 3",
                                    "ip igmp explicit-tracking",
                                ]
                            },
                            "blocking": True,
                        }
                    )
                if policy["mode"] == "asm":
                    gates.append(
                        {
                            "gate_id": "multicast.rp_route.{}.{}".format(
                                device_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": device_id,
                            "command": "show ip route vrf {} {}".format(
                                vrf, policy["rp_prefix"]
                            ),
                            "evaluator": "route_prefix",
                            "expected": {"prefix": str(policy["rp_prefix"])},
                            "blocking": True,
                        }
                    )
        policy_plane = intent.get("policy_plane") or {}
        if policy_plane.get("mode") not in {None, "none"}:
            if device_id in set(
                str(item)
                for item in policy_plane.get("enforcement_device_ids", [])
            ):
                vlan_ids = sorted(
                    set(int(item) for item in policy_plane.get("enforcement_vlan_ids", []))
                )
                ranges = []
                range_index = 0
                while range_index < len(vlan_ids):
                    start = vlan_ids[range_index]
                    end = start
                    while (
                        range_index + 1 < len(vlan_ids)
                        and vlan_ids[range_index + 1] == end + 1
                    ):
                        range_index += 1
                        end = vlan_ids[range_index]
                    ranges.append(
                        str(start) if start == end else "{}-{}".format(start, end)
                    )
                    range_index += 1
                gates.append(
                    {
                        "gate_id": "policy.enforcement.{}".format(device_id),
                        "phase_id": "policy_plane",
                        "device_id": device_id,
                        "command": "show running-config | include ^cts role-based permissions default|^cts role-based enforcement vlan-list",
                        "evaluator": "exact_config_lines",
                        "expected": {
                            "lines": [
                                "cts role-based permissions default SDA-SGACL-DEFAULT-DENY",
                                "cts role-based enforcement vlan-list {}".format(
                                    ",".join(ranges)
                                ),
                            ]
                        },
                        "blocking": True,
                    }
                )
                for contract in sorted(
                    policy_plane.get("contracts", []),
                    key=lambda item: str(item["name"]),
                ):
                    gates.append(
                        {
                            "gate_id": "policy.permission.{}.{}".format(
                                device_id, str(contract["name"])
                            ),
                            "phase_id": "policy_plane",
                            "device_id": device_id,
                            "command": "show cts role-based permissions from {} to {} details".format(
                                int(contract["source_tag"]),
                                int(contract["destination_tag"]),
                            ),
                            "evaluator": "role_permission",
                            "expected": {
                                "source_tag": int(contract["source_tag"]),
                                "destination_tag": int(contract["destination_tag"]),
                                "sgacl_name": str(contract["sgacl_name"]),
                            },
                            "blocking": True,
                        }
                    )
            sxp_connections = [
                item
                for item in (policy_plane.get("sxp") or {}).get("connections", [])
                if str(item.get("speaker_id")) == device_id
            ]
            if sxp_connections:
                transport_vrfs = sorted(
                    set(str(item["transport_vrf"]) for item in sxp_connections)
                )
                if len(transport_vrfs) != 1:
                    raise ValueError(
                        "One SXP speaker cannot verify multiple transport VRFs"
                    )
                transport_vrf = transport_vrfs[0]
                route_commands = {
                    str(item["listener_prefix"]): (
                        "show ip route {}".format(item["listener_prefix"])
                        if transport_vrf == "global"
                        else "show ip route vrf {} {}".format(
                            transport_vrf, item["listener_prefix"]
                        )
                    )
                    for item in sxp_connections
                }
                for listener_prefix, route_command in sorted(
                    route_commands.items()
                ):
                    suffix = listener_prefix.replace(".", "_").replace("/", "_")
                    gates.append(
                        {
                            "gate_id": "policy.sxp_route.{}.{}".format(
                                device_id, suffix
                            ),
                            "phase_id": "policy_plane",
                            "device_id": device_id,
                            "command": route_command,
                            "evaluator": "route_prefix",
                            "expected": {"prefix": listener_prefix},
                            "blocking": True,
                        }
                    )
                gates.append(
                    {
                        "gate_id": "policy.sxp.{}".format(device_id),
                        "phase_id": "policy_plane",
                        "device_id": device_id,
                        "command": (
                            "show cts sxp connections"
                            if transport_vrf == "global"
                            else "show cts sxp connections vrf {}".format(
                                transport_vrf
                            )
                        ),
                        "evaluator": "sxp_connections",
                        "expected": {
                            "connections": [
                                {
                                    "peer": str(item["listener_ip"]),
                                    "source_ip": str(item["source_ip"]),
                                }
                                for item in sorted(
                                    sxp_connections,
                                    key=lambda entry: str(entry["listener_ip"]),
                                )
                            ]
                        },
                        "blocking": True,
                    }
                )
    for fusion in sorted(intent.get("fusion_nodes", []), key=lambda item: str(item["id"])):
        fusion_id = str(fusion["id"])
        gates.append(
            {
                "gate_id": "precheck.version.{}".format(fusion_id),
                "phase_id": "precheck",
                "device_id": fusion_id,
                "command": "show version",
                "evaluator": "ios_xe_version",
                "expected": {"version": str(fusion["software_version"])},
                "blocking": True,
            }
        )
        if handoff.get("enabled"):
            gates.append(
                {
                    "gate_id": "fusion.bgp.{}".format(fusion_id),
                    "phase_id": "border_handoff",
                    "device_id": fusion_id,
                    "command": "show bgp ipv4 unicast vrf all summary",
                    "evaluator": "bgp_neighbors",
                    "expected": {"neighbors": sorted(peers_by_fusion.get(fusion_id, []))},
                    "blocking": True,
                }
            )
        multicast = intent.get("multicast") or {}
        if multicast.get("enabled") and multicast.get("transport") == "native":
            for policy in sorted(
                multicast.get("overlay_policies", []),
                key=lambda item: int(item["l3_instance_id"]),
            ):
                vrf = str(policy["vrf"])
                peers = [
                    peer
                    for peer in handoff.get("peers", [])
                    if str(peer.get("fusion_node_id")) == fusion_id
                    and str(peer.get("vrf")) == vrf
                ]
                if not peers:
                    continue
                instance_id = int(policy["l3_instance_id"])
                access_list = str(policy["access_list"])
                expected_policy_lines = [
                    "ip multicast-routing vrf {}".format(vrf)
                ]
                if policy["mode"] == "ssm":
                    expected_policy_lines.append(
                        "ip pim vrf {} ssm range {}".format(vrf, access_list)
                    )
                else:
                    expected_policy_lines.append(
                        "ip pim vrf {} rp-address {} {}".format(
                            vrf, policy["rp_address"], access_list
                        )
                    )
                group_range = ip_network(str(policy["group_range"]))
                gates.extend(
                    [
                        {
                            "gate_id": "multicast.policy.{}.{}".format(
                                fusion_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": fusion_id,
                            "command": "show running-config | include ^ip multicast-routing vrf {}|^ip pim vrf {}".format(
                                vrf, vrf
                            ),
                            "evaluator": "exact_config_lines",
                            "expected": {"lines": expected_policy_lines},
                            "blocking": True,
                        },
                        {
                            "gate_id": "multicast.acl.{}.{}".format(
                                fusion_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": fusion_id,
                            "command": "show running-config | section ^ip access-list standard {}$".format(
                                access_list
                            ),
                            "evaluator": "exact_config_lines",
                            "expected": {
                                "lines": [
                                    "ip access-list standard {}".format(access_list),
                                    "10 permit {} {}".format(
                                        group_range.network_address,
                                        group_range.hostmask,
                                    ),
                                ]
                            },
                            "blocking": True,
                        },
                        {
                            "gate_id": "multicast.pim.{}.{}".format(
                                fusion_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": fusion_id,
                            "command": "show ip pim vrf {} interface".format(vrf),
                            "evaluator": "pim_interfaces",
                            "expected": {
                                "interfaces": sorted(
                                    {
                                        "Vlan{}".format(int(peer["vlan_id"]))
                                        for peer in peers
                                    }
                                )
                            },
                            "blocking": True,
                        },
                    ]
                )
                if policy["mode"] == "asm":
                    gates.append(
                        {
                            "gate_id": "multicast.rp_route.{}.{}".format(
                                fusion_id, instance_id
                            ),
                            "phase_id": "multicast",
                            "device_id": fusion_id,
                            "command": "show ip route vrf {} {}".format(
                                vrf, policy["rp_prefix"]
                            ),
                            "evaluator": "route_prefix",
                            "expected": {"prefix": str(policy["rp_prefix"])},
                            "blocking": True,
                        }
                    )
        shared = intent.get("shared_services") or {}
        if shared:
            service_vrf = str(shared["vrf"])
            for leak in sorted(
                shared.get("route_leaks", []),
                key=lambda item: str(item["consumer_vrf"]),
            ):
                consumer_vrf = str(leak["consumer_vrf"])
                for prefix in sorted(leak.get("import_prefixes", [])):
                    suffix = str(prefix).replace(".", "_").replace("/", "_")
                    gates.append(
                        {
                            "gate_id": "shared.consumer.{}.{}.{}".format(
                                fusion_id, consumer_vrf, suffix
                            ),
                            "phase_id": "shared_services",
                            "device_id": fusion_id,
                            "command": "show ip route vrf {} {}".format(
                                consumer_vrf, prefix
                            ),
                            "evaluator": "route_prefix",
                            "expected": {"prefix": str(prefix)},
                            "blocking": True,
                        }
                    )
                for prefix in sorted(leak.get("export_prefixes", [])):
                    suffix = str(prefix).replace(".", "_").replace("/", "_")
                    gates.append(
                        {
                            "gate_id": "shared.service.{}.{}.{}.{}".format(
                                fusion_id, service_vrf, consumer_vrf, suffix
                            ),
                            "phase_id": "shared_services",
                            "device_id": fusion_id,
                            "command": "show ip route vrf {} {}".format(
                                service_vrf, prefix
                            ),
                            "evaluator": "route_prefix",
                            "expected": {"prefix": str(prefix)},
                            "blocking": True,
                        }
                    )
    return gates


def evaluate_gate(gate: Mapping[str, Any], output: str) -> GateResult:
    evaluator = gate["evaluator"]
    expected = gate["expected"]
    if evaluator == "ios_xe_version":
        return verify_ios_xe_version(output, str(expected["version"]))
    if evaluator == "ios_xe_license_level":
        return verify_ios_xe_license_level(
            output,
            str(expected["network_package"]),
            list(expected["subscription_packages"]),
        )
    if evaluator == "isis_neighbors":
        return verify_isis_neighbors(output, int(expected["minimum_up"]))
    if evaluator == "lisp_sessions":
        return verify_lisp_sessions(output, int(expected["minimum_established"]))
    if evaluator == "lisp_publishers":
        return verify_lisp_publishers(output, list(expected["publishers"]))
    if evaluator == "lisp_identity":
        return verify_lisp_identity(
            output,
            int(expected["domain_id"]),
            (
                None
                if expected.get("multihoming_id") is None
                else int(expected["multihoming_id"])
            ),
        )
    if evaluator == "exact_config_lines":
        return verify_exact_config_lines(output, list(expected["lines"]))
    if evaluator == "config_lines_absent":
        return verify_config_lines_absent(output, list(expected["lines"]))
    if evaluator == "pim_interfaces":
        return verify_pim_interfaces(output, list(expected["interfaces"]))
    if evaluator == "msdp_peers":
        return verify_msdp_peers(output, list(expected["peers"]))
    if evaluator == "sxp_connections":
        return verify_sxp_connections(output, list(expected["connections"]))
    if evaluator == "role_permission":
        return verify_role_permission(
            output,
            int(expected["source_tag"]),
            int(expected["destination_tag"]),
            str(expected["sgacl_name"]),
        )
    if evaluator == "nve_peers":
        return verify_nve_peers(output, int(expected["minimum_up"]))
    if evaluator == "bgp_neighbors":
        return verify_bgp_neighbors(output, list(expected["neighbors"]))
    if evaluator == "route_prefix":
        return verify_route_prefix(output, str(expected["prefix"]))
    return GateResult(False, "Unknown evaluator {}".format(evaluator), {"evaluator": evaluator})
