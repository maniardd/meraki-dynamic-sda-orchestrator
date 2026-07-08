"""Intent-derived operational gate specifications and evaluators."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from .parsers import (
    GateResult,
    verify_bgp_neighbors,
    verify_isis_neighbors,
    verify_ios_xe_version,
    verify_lisp_identity,
    verify_lisp_publishers,
    verify_lisp_sessions,
    verify_nve_peers,
    verify_route_prefix,
)


def build_gate_plan(intent: Mapping[str, Any]) -> List[Dict[str, Any]]:
    gates: List[Dict[str, Any]] = []
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
    if evaluator == "nve_peers":
        return verify_nve_peers(output, int(expected["minimum_up"]))
    if evaluator == "bgp_neighbors":
        return verify_bgp_neighbors(output, list(expected["neighbors"]))
    if evaluator == "route_prefix":
        return verify_route_prefix(output, str(expected["prefix"]))
    return GateResult(False, "Unknown evaluator {}".format(evaluator), {"evaluator": evaluator})
