"""Deterministic, ownership-scoped reconciliation for rendered device state.

The module deliberately stores exact removal commands in an immutable manifest.
Only resources present in a trusted, approval-bound baseline may be removed.
Candidate intent alone is never treated as proof that configuration is owned.
"""

from __future__ import annotations

import re
from ipaddress import ip_network
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .store import sha256_json


class ReconciliationError(ValueError):
    pass


OWNED_STATE_SCHEMA_VERSION = "1.0"
BASELINE_SCHEMA_VERSION = "1.0"
SHA256_HEX = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)


def _commands_hash(commands: List[str]) -> str:
    return sha256_json(commands)


def _resource(
    key: str,
    kind: str,
    configured_lines: List[str],
    remove_commands: List[str],
    gate_command: str,
    forbidden_lines: List[str],
    remove_order: int,
) -> Dict[str, Any]:
    state = {
        "configured_lines": configured_lines,
        "remove_commands": remove_commands,
        "gate_command": gate_command,
        "forbidden_lines": forbidden_lines,
    }
    return {
        "key": key,
        "kind": kind,
        **state,
        "remove_order": int(remove_order),
        "state_hash": sha256_json(state),
        "remove_command_hash": _commands_hash(remove_commands),
    }


def _add(resources: Dict[str, List[Dict[str, Any]]], device_id: str, item: Dict[str, Any]) -> None:
    resources.setdefault(device_id, []).append(item)


def _router_lisp_mapping_remove(instance_id: int, mapping: str) -> List[str]:
    return [
        "router lisp",
        " instance-id {}".format(instance_id),
        "  service ipv4",
        "   no {}".format(mapping),
        "   exit-service-ipv4",
        "  exit-instance-id",
        " exit-router-lisp",
    ]


def _router_lisp_bum_remove(instance_id: int, group: str) -> List[str]:
    return [
        "router lisp",
        " instance-id {}".format(instance_id),
        "  service ethernet",
        "   no broadcast-underlay {}".format(group),
        "   exit-service-ethernet",
        "  exit-instance-id",
        " exit-router-lisp",
    ]


def _interface_remove(interface: str, lines: List[str]) -> List[str]:
    return ["interface {}".format(interface)] + [" no {}".format(line) for line in lines]


def build_multicast_owned_state(intent: Mapping[str, Any]) -> Dict[str, Any]:
    """Build the exact multicast state that the candidate artifact will own."""

    fabric_id = str(intent["fabric"]["id"])
    resources: Dict[str, List[Dict[str, Any]]] = {}
    multicast = intent.get("multicast") or {}
    if (
        str(intent.get("schema_version")) == "1.2"
        and multicast.get("enabled")
        and multicast.get("transport") == "native"
    ):
        devices = {str(item["id"]): item for item in intent.get("devices", [])}
        fusion_nodes = {
            str(item["id"]): {**item, "roles": ["fusion"]}
            for item in intent.get("fusion_nodes", [])
        }
        all_nodes = {**devices, **fusion_nodes}
        fabric_multicast = intent.get("fabric", {}).get("multicast") or {}
        rp_device_ids = sorted(str(item) for item in multicast.get("rp_device_ids", []))
        rp_address = fabric_multicast.get("rp_address")
        rp_loopback_id = int(fabric_multicast.get("rp_loopback_id", 60000))
        if fabric_multicast.get("enabled", True) and rp_address:
            for device_id in rp_device_ids:
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.underlay.rp_loopback",
                        "multicast_rp_loopback",
                        [
                            "interface Loopback{}".format(rp_loopback_id),
                            "ip address {} 255.255.255.255".format(rp_address),
                        ],
                        ["no interface Loopback{}".format(rp_loopback_id)],
                        "show running-config | section ^interface Loopback{}$".format(
                            rp_loopback_id
                        ),
                        ["interface Loopback{}".format(rp_loopback_id)],
                        200,
                    ),
                )
                if multicast.get("rp_mode") == "anycast":
                    peers = [
                        str(devices[peer_id]["loopback0_ip"])
                        for peer_id in rp_device_ids
                        if peer_id != device_id and peer_id in devices
                    ]
                    for peer in sorted(peers):
                        line = "ip msdp peer {} connect-source Loopback0".format(peer)
                        _add(
                            resources,
                            device_id,
                            _resource(
                                "multicast.underlay.msdp_peer:{}".format(peer),
                                "msdp_peer",
                                [line],
                                ["no " + line],
                                "show running-config | include ^ip msdp peer {} ".format(
                                    peer
                                ),
                                [line],
                                300,
                            ),
                        )
                    if peers:
                        for suffix, line in (
                            ("cache", "ip msdp cache-sa-state"),
                            ("originator", "ip msdp originator-id Loopback0"),
                        ):
                            _add(
                                resources,
                                device_id,
                                _resource(
                                    "multicast.underlay.msdp_{}".format(suffix),
                                    "msdp_global",
                                    [line],
                                    ["no " + line],
                                    "show running-config | include ^{}$".format(line),
                                    [line],
                                    250,
                                ),
                            )

        endpoint_pools_by_vn: Dict[str, List[Mapping[str, Any]]] = {}
        for pool in intent.get("endpoint_pools", []):
            endpoint_pools_by_vn.setdefault(str(pool["virtual_network"]), []).append(pool)
        handoff = intent.get("border_handoff") or {}
        locator_name = str((intent.get("lisp") or {}).get("locator_set", "rloc_fabric"))

        for policy in sorted(
            multicast.get("overlay_policies", []),
            key=lambda item: int(item["l3_instance_id"]),
        ):
            vrf = str(policy["vrf"])
            vn = str(policy["virtual_network"])
            instance_id = int(policy["l3_instance_id"])
            acl = str(policy["access_list"])
            group_range = ip_network(str(policy["group_range"]))
            acl_lines = [
                "ip access-list standard {}".format(acl),
                "10 permit {} {}".format(group_range.network_address, group_range.hostmask),
            ]
            segment_by_device = {
                str(item["device_id"]): str(item["address"])
                for item in policy.get("segment_loopbacks", [])
            }
            participating_fusion = {
                str(peer["fusion_node_id"])
                for peer in handoff.get("peers", [])
                if peer.get("fusion_node_id") and str(peer.get("vrf")) == vrf
            }
            participants = sorted(set(segment_by_device) | participating_fusion)
            for device_id in participants:
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.routing:{}".format(vrf),
                        "multicast_routing",
                        ["ip multicast-routing vrf {}".format(vrf)],
                        ["no ip multicast-routing vrf {}".format(vrf)],
                        "show running-config | include ^ip multicast-routing vrf {}$".format(
                            vrf
                        ),
                        ["ip multicast-routing vrf {}".format(vrf)],
                        400,
                    ),
                )
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.acl:{}".format(vrf),
                        "overlay_acl",
                        acl_lines,
                        ["no ip access-list standard {}".format(acl)],
                        "show running-config | section ^ip access-list standard {}$".format(
                            acl
                        ),
                        acl_lines,
                        500,
                    ),
                )
                policy_lines: List[str]
                if policy["mode"] == "ssm":
                    policy_lines = ["ip pim vrf {} ssm range {}".format(vrf, acl)]
                else:
                    policy_lines = []
                    if device_id in segment_by_device:
                        policy_lines.append(
                            "ip pim vrf {} register-source Loopback{}".format(
                                vrf, instance_id
                            )
                        )
                    policy_lines.append(
                        "ip pim vrf {} rp-address {} {}".format(
                            vrf, policy["rp_address"], acl
                        )
                    )
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.policy:{}".format(vrf),
                        "overlay_policy",
                        policy_lines,
                        ["no " + line for line in policy_lines],
                        "show running-config | include ^ip pim vrf {} ".format(vrf),
                        policy_lines,
                        600,
                    ),
                )

            for device_id, address in sorted(segment_by_device.items()):
                loopback = "Loopback{}".format(instance_id)
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.segment_loopback:{}".format(instance_id),
                        "segment_loopback",
                        [
                            "interface {}".format(loopback),
                            "ip address {} 255.255.255.255".format(address),
                        ],
                        ["no interface {}".format(loopback)],
                        "show running-config | section ^interface {}$".format(loopback),
                        ["interface {}".format(loopback)],
                        700,
                    ),
                )
                lisp_interface = "LISP0.{}".format(instance_id)
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.lisp_interface:{}".format(instance_id),
                        "lisp_interface",
                        [
                            "interface {}".format(lisp_interface),
                            "ip pim lisp transport multicast",
                            "ip pim lisp core-group-range {} {}".format(
                                policy["core_group"]["start"],
                                int(policy["core_group"]["count"]),
                            ),
                        ],
                        ["no interface {}".format(lisp_interface)],
                        "show running-config | section ^interface {}$".format(
                            lisp_interface
                        ),
                        ["interface {}".format(lisp_interface)],
                        750,
                    ),
                )
                mapping = "database-mapping {}/32 locator-set {}".format(
                    address, locator_name
                )
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.lisp_mapping:{}".format(instance_id),
                        "lisp_mapping",
                        [mapping],
                        _router_lisp_mapping_remove(instance_id, mapping),
                        "show running-config | section ^router lisp",
                        [mapping],
                        800,
                    ),
                )
                roles = set(all_nodes[device_id].get("roles", []))
                if "fabric_edge" in roles:
                    for pool in sorted(
                        endpoint_pools_by_vn.get(vn, []),
                        key=lambda item: int(item["vlan_id"]),
                    ):
                        vlan = int(pool["vlan_id"])
                        lines = [
                            "ip pim passive",
                            "ip igmp version 3",
                            "ip igmp explicit-tracking",
                        ]
                        _add(
                            resources,
                            device_id,
                            _resource(
                                "multicast.overlay.edge_svi:{}".format(vlan),
                                "edge_svi",
                                lines,
                                _interface_remove("Vlan{}".format(vlan), lines),
                                "show running-config | section ^interface Vlan{}$".format(
                                    vlan
                                ),
                                lines,
                                900,
                            ),
                        )
                if "border" in roles:
                    for peer in sorted(
                        (
                            item
                            for item in handoff.get("peers", [])
                            if str(item.get("device_id")) == device_id
                            and str(item.get("vrf")) == vrf
                        ),
                        key=lambda item: int(item["vlan_id"]),
                    ):
                        interface = str(peer["interface"])
                        _add(
                            resources,
                            device_id,
                            _resource(
                                "multicast.overlay.border_handoff:{}:{}".format(
                                    vrf, int(peer["vlan_id"])
                                ),
                                "handoff_pim",
                                ["ip pim sparse-mode"],
                                _interface_remove(interface, ["ip pim sparse-mode"]),
                                "show running-config | section ^interface {}$".format(
                                    interface
                                ),
                                ["ip pim sparse-mode"],
                                900,
                            ),
                        )

            for fusion_id in sorted(participating_fusion):
                for peer in sorted(
                    (
                        item
                        for item in handoff.get("peers", [])
                        if str(item.get("fusion_node_id")) == fusion_id
                        and str(item.get("vrf")) == vrf
                    ),
                    key=lambda item: int(item["vlan_id"]),
                ):
                    vlan = int(peer["vlan_id"])
                    _add(
                        resources,
                        fusion_id,
                        _resource(
                            "multicast.overlay.fusion_handoff:{}:{}".format(vrf, vlan),
                            "handoff_pim",
                            ["ip pim sparse-mode"],
                            _interface_remove("Vlan{}".format(vlan), ["ip pim sparse-mode"]),
                            "show running-config | section ^interface Vlan{}$".format(vlan),
                            ["ip pim sparse-mode"],
                            900,
                        ),
                    )

        bum_groups = {
            str(item["endpoint_pool_id"]): str(item["group"])
            for item in multicast.get("l2_bum_groups", [])
        }
        edge_ids = sorted(
            str(item["id"])
            for item in intent.get("devices", [])
            if "fabric_edge" in set(item.get("roles", []))
        )
        for pool in sorted(intent.get("endpoint_pools", []), key=lambda item: int(item["vlan_id"])):
            group = bum_groups.get(str(pool["id"]))
            if not group:
                continue
            l2_instance_id = int(pool["l2_instance_id"])
            line = "broadcast-underlay {}".format(group)
            for device_id in edge_ids:
                _add(
                    resources,
                    device_id,
                    _resource(
                        "multicast.overlay.bum:{}".format(l2_instance_id),
                        "l2_bum",
                        [line],
                        _router_lisp_bum_remove(l2_instance_id, group),
                        "show running-config | section ^router lisp",
                        [line],
                        850,
                    ),
                )

    normalized_devices: Dict[str, Any] = {}
    for device_id in sorted(resources):
        ordered = sorted(resources[device_id], key=lambda item: str(item["key"]))
        keys = [str(item["key"]) for item in ordered]
        if len(keys) != len(set(keys)):
            raise ReconciliationError(
                "Duplicate owned multicast resource key on {}".format(device_id)
            )
        descriptor = dict(all_nodes[device_id])
        descriptor["roles"] = sorted(set(descriptor.get("roles", [])))
        normalized_devices[device_id] = {
            "device": descriptor,
            "resources": ordered,
        }
    body = {
        "owned_state_schema_version": OWNED_STATE_SCHEMA_VERSION,
        "scope": "multicast",
        "fabric_id": fabric_id,
        "intent_hash": sha256_json(intent),
        "devices": normalized_devices,
    }
    body["manifest_hash"] = sha256_json(body)
    return body


_SAFE_REMOVE_PATTERNS = [
    re.compile(
        r"^(?:no )?interface "
        r"(?:Loopback\d+|LISP0\.\d+|Vlan\d+|[A-Za-z][A-Za-z0-9./-]*)$"
    ),
    re.compile(
        r"^ no (?:ip pim passive|ip igmp version 3|"
        r"ip igmp explicit-tracking|ip pim sparse-mode)$"
    ),
    re.compile(r"^no ip multicast-routing vrf [A-Za-z0-9_.:-]+$"),
    re.compile(r"^no ip access-list standard [A-Za-z0-9_.:-]+$"),
    re.compile(
        r"^no ip pim vrf [A-Za-z0-9_.:-]+ "
        r"(?:ssm range [A-Za-z0-9_.:-]+|register-source Loopback\d+|"
        r"rp-address [0-9.]+ [A-Za-z0-9_.:-]+)$"
    ),
    re.compile(
        r"^no ip msdp (?:peer [0-9.]+ connect-source Loopback0|"
        r"cache-sa-state|originator-id Loopback0)$"
    ),
    re.compile(r"^router lisp$"),
    re.compile(r"^ instance-id \d+$"),
    re.compile(r"^  service (?:ipv4|ethernet)$"),
    re.compile(
        r"^   no (?:database-mapping [0-9.]+/32 locator-set "
        r"[A-Za-z0-9_.:/-]+|broadcast-underlay [0-9.]+)$"
    ),
    re.compile(r"^   exit-service-(?:ipv4|ethernet)$"),
    re.compile(r"^  exit-instance-id$"),
    re.compile(r"^ exit-router-lisp$"),
]
_OWNED_RESOURCE_KINDS = {
    "multicast_rp_loopback",
    "msdp_peer",
    "msdp_global",
    "multicast_routing",
    "overlay_acl",
    "overlay_policy",
    "segment_loopback",
    "lisp_interface",
    "lisp_mapping",
    "edge_svi",
    "handoff_pim",
    "l2_bum",
}
_DEVICE_DESCRIPTOR_FIELDS = {
    "id",
    "hostname",
    "site",
    "platform",
    "software_version",
    "management_ip",
    "dashboard_management_ip",
    "loopback0_ip",
    "roles",
    "credential_ref",
    "bgp_asn",
}
_REQUIRED_DEVICE_DESCRIPTOR_FIELDS = {
    "id",
    "hostname",
    "platform",
    "software_version",
    "management_ip",
    "roles",
    "credential_ref",
}
_SAFE_SHOW_COMMAND = re.compile(r"^[A-Za-z0-9 ._:/|^$-]+$")


def _validate_remove_commands(commands: Any) -> List[str]:
    if not isinstance(commands, list) or not commands:
        raise ReconciliationError("Owned resource removal commands are required")
    normalized = [str(item) for item in commands]
    for command in normalized:
        if "\n" in command or "\r" in command or "<secret:" in command:
            raise ReconciliationError("Unsafe owned-state removal command")
        if not any(pattern.fullmatch(command) for pattern in _SAFE_REMOVE_PATTERNS):
            raise ReconciliationError(
                "Unsupported owned-state removal command: {}".format(command)
            )
    if not any(line.lstrip().startswith("no ") for line in normalized):
        raise ReconciliationError("Removal block contains no negation")
    return normalized


def validate_owned_state(manifest: Mapping[str, Any], fabric_id: Optional[str] = None) -> None:
    if str(manifest.get("owned_state_schema_version")) != OWNED_STATE_SCHEMA_VERSION:
        raise ReconciliationError("Unsupported owned-state manifest version")
    if manifest.get("scope") != "multicast":
        raise ReconciliationError("Owned-state manifest scope must be multicast")
    if fabric_id is not None and str(manifest.get("fabric_id")) != str(fabric_id):
        raise ReconciliationError("Owned-state manifest belongs to another fabric")
    supplied_hash = str(manifest.get("manifest_hash", ""))
    body = dict(manifest)
    body.pop("manifest_hash", None)
    if not SHA256_HEX.fullmatch(supplied_hash) or sha256_json(body) != supplied_hash:
        raise ReconciliationError("Owned-state manifest hash is invalid")
    devices = manifest.get("devices")
    if not isinstance(devices, dict):
        raise ReconciliationError("Owned-state devices must be an object")
    for device_id, device in devices.items():
        if not isinstance(device, dict) or not isinstance(device.get("resources"), list):
            raise ReconciliationError("Owned-state device resources are invalid")
        descriptor = device.get("device")
        if not isinstance(descriptor, dict) or str(descriptor.get("id")) != str(device_id):
            raise ReconciliationError("Owned-state device descriptor is invalid")
        unexpected_descriptor_fields = set(descriptor) - _DEVICE_DESCRIPTOR_FIELDS
        if unexpected_descriptor_fields:
            raise ReconciliationError("Owned-state device descriptor has unsupported fields")
        missing_descriptor_fields = _REQUIRED_DEVICE_DESCRIPTOR_FIELDS - set(descriptor)
        if missing_descriptor_fields:
            raise ReconciliationError(
                "Owned-state device descriptor is missing required fields: {}".format(
                    ", ".join(sorted(missing_descriptor_fields))
                )
            )
        for field in (
            "id",
            "hostname",
            "platform",
            "software_version",
            "management_ip",
        ):
            value = descriptor[field]
            if not isinstance(value, str) or not value or "\n" in value or "\r" in value:
                raise ReconciliationError(
                    "Owned-state device descriptor field {} is invalid".format(field)
                )
        roles = descriptor["roles"]
        if (
            not isinstance(roles, list)
            or not roles
            or any(not isinstance(role, str) or not role for role in roles)
        ):
            raise ReconciliationError("Owned-state device roles are invalid")
        credential_ref = str(descriptor.get("credential_ref", ""))
        if not credential_ref.startswith("secret://"):
            raise ReconciliationError("Owned-state device credential must be a secret reference")
        keys = []
        for item in device["resources"]:
            if not isinstance(item, dict):
                raise ReconciliationError("Owned-state resource must be an object")
            key = str(item.get("key", ""))
            if not key or not re.fullmatch(r"[A-Za-z0-9_.:-]+", key):
                raise ReconciliationError("Owned-state resource key is invalid")
            if str(item.get("kind", "")) not in _OWNED_RESOURCE_KINDS:
                raise ReconciliationError("Owned-state resource kind is unsupported")
            keys.append(key)
            commands = _validate_remove_commands(item.get("remove_commands"))
            if _commands_hash(commands) != str(item.get("remove_command_hash", "")):
                raise ReconciliationError("Owned-state removal command hash is invalid")
            state = {
                "configured_lines": item.get("configured_lines"),
                "remove_commands": commands,
                "gate_command": item.get("gate_command"),
                "forbidden_lines": item.get("forbidden_lines"),
            }
            if sha256_json(state) != str(item.get("state_hash", "")):
                raise ReconciliationError("Owned-state resource hash is invalid")
            configured_lines = item.get("configured_lines")
            forbidden_lines = item.get("forbidden_lines")
            if not isinstance(configured_lines, list) or not configured_lines:
                raise ReconciliationError("Owned-state configured lines are required")
            if not isinstance(forbidden_lines, list) or not forbidden_lines:
                raise ReconciliationError("Owned-state absence gate is required")
            for line in list(configured_lines) + list(forbidden_lines):
                if not isinstance(line, str) or not line or "\n" in line or "\r" in line:
                    raise ReconciliationError("Owned-state configuration line is invalid")
                if "<secret:" in line:
                    raise ReconciliationError("Owned-state configuration line contains a secret")
            gate_command = str(item.get("gate_command", ""))
            if (
                not gate_command.startswith("show running-config ")
                or not _SAFE_SHOW_COMMAND.fullmatch(gate_command)
            ):
                raise ReconciliationError("Owned-state gate command is invalid")
        if len(keys) != len(set(keys)):
            raise ReconciliationError(
                "Duplicate owned-state resource key on {}".format(device_id)
            )


def make_baseline(
    manifest: Mapping[str, Any],
    source_type: str,
    source_reference: str,
    source_artifact_hash: Optional[str] = None,
    evidence_hash: Optional[str] = None,
) -> Dict[str, Any]:
    validate_owned_state(manifest)
    if source_type not in {"successful_apply", "adopted_discovery"}:
        raise ReconciliationError("Unsupported owned-state baseline source")
    if not source_reference:
        raise ReconciliationError("Owned-state baseline source reference is required")
    body: Dict[str, Any] = {
        "baseline_schema_version": BASELINE_SCHEMA_VERSION,
        "source_type": source_type,
        "source_reference": source_reference,
        "manifest": dict(manifest),
        "manifest_hash": str(manifest["manifest_hash"]),
    }
    if source_artifact_hash:
        body["source_artifact_hash"] = str(source_artifact_hash)
    if evidence_hash:
        body["evidence_hash"] = str(evidence_hash)
    body["baseline_hash"] = sha256_json(body)
    return body


def validate_baseline(baseline: Mapping[str, Any], fabric_id: str) -> None:
    if str(baseline.get("baseline_schema_version")) != BASELINE_SCHEMA_VERSION:
        raise ReconciliationError("Unsupported owned-state baseline version")
    source_type = str(baseline.get("source_type", ""))
    if source_type not in {"successful_apply", "adopted_discovery"}:
        raise ReconciliationError("Unsupported owned-state baseline source")
    if not str(baseline.get("source_reference", "")):
        raise ReconciliationError("Owned-state baseline source reference is required")
    body = dict(baseline)
    supplied_hash = str(body.pop("baseline_hash", ""))
    if not SHA256_HEX.fullmatch(supplied_hash) or sha256_json(body) != supplied_hash:
        raise ReconciliationError("Owned-state baseline hash is invalid")
    manifest = baseline.get("manifest")
    if not isinstance(manifest, dict):
        raise ReconciliationError("Owned-state baseline manifest is required")
    validate_owned_state(manifest, fabric_id)
    if str(baseline.get("manifest_hash")) != str(manifest.get("manifest_hash")):
        raise ReconciliationError("Owned-state baseline manifest hash does not match")
    if source_type == "successful_apply":
        artifact_hash = str(baseline.get("source_artifact_hash", ""))
        if not SHA256_HEX.fullmatch(artifact_hash):
            raise ReconciliationError("Successful-apply baseline requires an artifact hash")
    if source_type == "adopted_discovery":
        evidence_hash = str(baseline.get("evidence_hash", ""))
        if not SHA256_HEX.fullmatch(evidence_hash):
            raise ReconciliationError("Adopted baseline requires discovery evidence")


def build_multicast_reconciliation(
    baseline: Optional[Mapping[str, Any]], current_manifest: Mapping[str, Any]
) -> Dict[str, Any]:
    validate_owned_state(current_manifest)
    if baseline is None:
        return {
            "status": "baseline_missing",
            "baseline_hash": None,
            "stale_resource_count": 0,
            "devices": {},
        }
    validate_baseline(baseline, str(current_manifest["fabric_id"]))
    previous = baseline["manifest"]
    previous_resources: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    current_resources: Dict[Tuple[str, str], Mapping[str, Any]] = {}
    for device_id, device in previous.get("devices", {}).items():
        for item in device.get("resources", []):
            previous_resources[(str(device_id), str(item["key"]))] = item
    for device_id, device in current_manifest.get("devices", {}).items():
        for item in device.get("resources", []):
            current_resources[(str(device_id), str(item["key"]))] = item

    stale = [
        (device_key, item)
        for device_key, item in previous_resources.items()
        if device_key not in current_resources
        or str(current_resources[device_key]["state_hash"]) != str(item["state_hash"])
    ]
    devices: Dict[str, Any] = {}
    for (device_id, key), item in sorted(
        stale,
        key=lambda entry: (
            str(entry[0][0]),
            -int(entry[1].get("remove_order", 0)),
            str(entry[0][1]),
        ),
    ):
        previous_device = previous["devices"][device_id]
        device = devices.setdefault(
            device_id,
            {
                "device": dict(previous_device["device"]),
                "blocks": [],
                "gates": [],
            },
        )
        block_id = "reconcile_{}".format(sha256_json([device_id, key])[:16])
        device["blocks"].append(
            {
                "block_id": block_id,
                "owned_resource_key": key,
                "commands": list(item["remove_commands"]),
                "command_hash": str(item["remove_command_hash"]),
                "secret_refs": [],
            }
        )
        device["gates"].append(
            {
                "gate_id": "reconcile.absent.{}.{}".format(
                    device_id, sha256_json(key)[:12]
                ),
                "phase_id": "multicast_reconciliation",
                "device_id": device_id,
                "command": str(item["gate_command"]),
                "evaluator": "config_lines_absent",
                "expected": {"lines": list(item["forbidden_lines"])},
                "blocking": True,
                "owned_resource_key": key,
            }
        )
    body = {
        "status": "ready",
        "baseline_hash": str(baseline["baseline_hash"]),
        "previous_manifest_hash": str(previous["manifest_hash"]),
        "current_manifest_hash": str(current_manifest["manifest_hash"]),
        "stale_resource_count": len(stale),
        "devices": devices,
    }
    body["reconciliation_hash"] = sha256_json(body)
    return body
