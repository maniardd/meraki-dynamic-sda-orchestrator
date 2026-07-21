"""Deterministic, read-only deployment planning for validated fabric intent."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping

from .intent import ValidationResult, validate_intent


class PlanValidationError(ValueError):
    def __init__(self, result: ValidationResult):
        super().__init__("Fabric intent did not pass validation")
        self.result = result


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _targets_by_role(devices: List[Mapping[str, Any]], role: str) -> List[str]:
    return sorted(
        str(device["id"])
        for device in devices
        if role in device.get("roles", [])
    )


def create_plan(intent: Mapping[str, Any]) -> Dict[str, Any]:
    """Create a deterministic, non-executable deployment plan.

    Execution is intentionally absent in this foundation milestone. The plan
    proves how validated intent will be separated from later device workers.
    """
    validation = validate_intent(intent)
    if not validation.is_valid:
        raise PlanValidationError(validation)

    devices = list(intent["devices"])
    all_devices = sorted(str(device["id"]) for device in devices)
    fusion_nodes = list(intent.get("fusion_nodes", []))
    fusion = sorted(str(device["id"]) for device in fusion_nodes)
    all_targets = sorted(set(all_devices + fusion))
    control_plane = _targets_by_role(devices, "control_plane")
    borders = _targets_by_role(devices, "border")
    edges = _targets_by_role(devices, "fabric_edge")

    phases: List[Dict[str, Any]] = [
        {
            "id": "precheck",
            "name": "Read-only discovery and prechecks",
            "depends_on": [],
            "targets": all_targets,
            "gate": "inventory_topology_addressing_services_and_checkpoint_ready",
        },
        {
            "id": "checkpoint",
            "name": "Create and verify device checkpoints",
            "depends_on": ["precheck"],
            "targets": all_targets,
            "gate": "checkpoint_exists_and_is_restorable",
        },
        {
            "id": "underlay",
            "name": "Deploy and verify IS-IS underlay",
            "depends_on": ["checkpoint"],
            "targets": all_devices,
            "gate": "expected_isis_bfd_routes_and_mtu_pass",
        },
        {
            "id": "lisp_control_plane",
            "name": "Deploy LISP control-plane publisher/map-server roles",
            "depends_on": ["underlay"],
            "targets": control_plane,
            "gate": "map_server_and_resolver_operational",
        },
        {
            "id": "lisp_edges",
            "name": "Deploy LISP ITR/ETR fabric-edge roles",
            "depends_on": ["lisp_control_plane"],
            "targets": edges,
            "gate": "lisp_sessions_established_and_registrations_present",
        },
        {
            "id": "overlay",
            "name": "Deploy VRFs, L2/L3 instances, gateways, and endpoint pools",
            "depends_on": ["lisp_edges"],
            "targets": sorted(set(edges + borders)),
            "gate": "vxlan_peers_vnis_remote_eids_and_gateways_operational",
            "objects": {
                "virtual_networks": len(intent.get("virtual_networks", [])),
                "endpoint_pools": len(intent.get("endpoint_pools", [])),
            },
        },
        {
            "id": "border_handoff",
            "name": "Deploy and verify border/BGP handoff",
            "depends_on": ["overlay"],
            "targets": sorted(set(borders + fusion)),
            "gate": "expected_bgp_neighbors_and_routes_established",
        },
    ]

    assurance_dependency = "border_handoff"
    if intent.get("shared_services"):
        phases.append(
            {
                "id": "shared_services",
                "name": "Deploy and verify deny-by-default shared-service route leaking",
                "depends_on": ["border_handoff"],
                "targets": fusion,
                "gate": "only_approved_service_and_consumer_prefixes_are_reachable",
                "objects": {
                    "services": len(intent["shared_services"].get("services", [])),
                    "route_leaks": len(intent["shared_services"].get("route_leaks", [])),
                },
            }
        )
        assurance_dependency = "shared_services"

    multicast = intent.get("multicast") or {}
    if multicast.get("enabled"):
        multicast_vrfs = {
            str(policy["vrf"])
            for policy in multicast.get("overlay_policies", [])
        }
        fusion_multicast_targets = {
            str(peer["fusion_node_id"])
            for peer in (intent.get("border_handoff") or {}).get("peers", [])
            if peer.get("fusion_node_id")
            and str(peer.get("vrf")) in multicast_vrfs
        }
        multicast_targets = sorted(
            {
                str(loopback["device_id"])
                for policy in multicast.get("overlay_policies", [])
                for loopback in policy.get("segment_loopbacks", [])
            }
            | fusion_multicast_targets
        )
        phases.append(
            {
                "id": "multicast",
                "name": "Deploy and verify fabric multicast and rendezvous points",
                "depends_on": [assurance_dependency],
                "targets": multicast_targets,
                "gate": "pim_interfaces_rp_routes_and_multicast_policy_pass",
                "objects": {
                    "asm_virtual_networks": len(multicast.get("asm_virtual_networks", [])),
                    "ssm_virtual_networks": len(multicast.get("ssm_virtual_networks", [])),
                },
            }
        )
        assurance_dependency = "multicast"

    policy_plane = intent.get("policy_plane") or {}
    if policy_plane.get("mode") not in {None, "none"}:
        phases.append(
            {
                "id": "policy_plane",
                "name": "Publish and verify ISE/SGT/SXP policy-plane intent",
                "depends_on": [assurance_dependency],
                "targets": all_targets,
                "gate": "ise_sgt_contracts_and_sxp_sessions_match_approved_intent",
                "objects": {
                    "security_groups": len(policy_plane.get("security_groups", [])),
                    "contracts": len(policy_plane.get("contracts", [])),
                    "sxp_connections": len(
                        (policy_plane.get("sxp") or {}).get("connections", [])
                    ),
                },
            }
        )
        assurance_dependency = "policy_plane"

    phases.append(
        {
            "id": "endpoint_assurance",
            "name": "Run DHCP, reachability, mobility, multicast, and policy assurance",
            "depends_on": [assurance_dependency],
            "targets": all_devices,
            "gate": "synthetic_endpoint_transactions_pass",
        }
    )

    intent_hash = _sha256(intent)
    plan_body = {
        "schema_version": "1.0",
        "intent_hash": intent_hash,
        "fabric_id": intent["fabric"]["id"],
        "environment": intent["metadata"]["environment"],
        "targets": all_targets,
        "phases": phases,
        "safety": {
            "executable": False,
            "requires_approval": True,
            "requires_maintenance_window": True,
            "requires_fabric_lock": True,
            "requires_verified_rollback": True,
        },
    }
    plan_hash = _sha256(plan_body)

    return {
        **plan_body,
        "plan_id": f"plan_{plan_hash[:16]}",
        "plan_hash": plan_hash,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "validation": validation.as_dict(),
    }
