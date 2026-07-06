"""Intent-derived operational gate specifications and evaluators."""

from __future__ import annotations

from typing import Any, Dict, List, Mapping

from .parsers import (
    GateResult,
    verify_bgp_neighbors,
    verify_ios_xe_version,
    verify_isis_neighbors,
    verify_lisp_sessions,
    verify_nve_peers,
)


def build_gate_plan(intent: Mapping[str, Any]) -> List[Dict[str, Any]]:
    gates: List[Dict[str, Any]] = []
    incident_links: Dict[str, int] = {str(device["id"]): 0 for device in intent["devices"]}
    for link in intent.get("links", []):
        for endpoint in link["endpoints"]:
            incident_links[str(endpoint["device_id"])] += 1

    map_server_count = len(intent["lisp"]["map_servers"])
    handoff = intent.get("border_handoff") or {}
    peers_by_device: Dict[str, List[str]] = {}
    for peer in handoff.get("peers", []):
        peers_by_device.setdefault(str(peer["device_id"]), []).append(str(peer["neighbor_ip"]))

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
    if evaluator == "nve_peers":
        return verify_nve_peers(output, int(expected["minimum_up"]))
    if evaluator == "bgp_neighbors":
        return verify_bgp_neighbors(output, list(expected["neighbors"]))
    return GateResult(False, "Unknown evaluator {}".format(evaluator), {"evaluator": evaluator})
