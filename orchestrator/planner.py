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
    control_plane = _targets_by_role(devices, "control_plane")
    borders = _targets_by_role(devices, "border")
    edges = _targets_by_role(devices, "fabric_edge")

    phases: List[Dict[str, Any]] = [
        {
            "id": "precheck",
            "name": "Read-only discovery and prechecks",
            "depends_on": [],
            "targets": all_devices,
            "gate": "inventory_topology_addressing_services_and_checkpoint_ready",
        },
        {
            "id": "checkpoint",
            "name": "Create and verify device checkpoints",
            "depends_on": ["precheck"],
            "targets": all_devices,
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
            "name": "Deploy LISP map-server and map-resolver roles",
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
            "targets": borders,
            "gate": "expected_bgp_neighbors_and_routes_established",
        },
        {
            "id": "endpoint_assurance",
            "name": "Run DHCP, reachability, mobility, and policy assurance",
            "depends_on": ["border_handoff"],
            "targets": all_devices,
            "gate": "synthetic_endpoint_transactions_pass",
        },
    ]

    intent_hash = _sha256(intent)
    plan_body = {
        "schema_version": "1.0",
        "intent_hash": intent_hash,
        "fabric_id": intent["fabric"]["id"],
        "environment": intent["metadata"]["environment"],
        "targets": all_devices,
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
