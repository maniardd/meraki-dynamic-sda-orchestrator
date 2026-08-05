"""Fail-closed review contract for the isolated SJC23 hardware POC.

This module deliberately creates a *review* object, not an Apply capability.
It makes the derived POC impact understandable in Meraki without returning raw
IOS XE configuration, secret references, or a mechanism to bypass the global
production execution controls.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Sequence


class PocExecutionError(ValueError):
    """The candidate is outside the narrowly approved SJC23 POC scope."""


_POLICY_VERSION = "1.0-sjc23-poc"
_CHANGE_REFERENCE = "SJC23-POC-001"
_FABRIC_ID = "sjc23-poc-fabric"
_REQUIRED_BLOCKER = "poc.local_dhcp_and_attachment_hardware_acceptance_pending"
_DEVICE_SCOPE = {
    "border-cp-01": {
        "platform": "C9500-48Y4C",
        "roles": ["border", "control_plane"],
    },
    "edge-01": {
        "platform": "C9300-24P",
        "roles": ["fabric_edge"],
    },
}
_EXPECTED_PHASES = {
    "border-cp-01": ["underlay", "lisp_control_plane", "overlay", "border_handoff"],
    "edge-01": ["underlay", "lisp_edges", "overlay"],
}


def authorize_sjc23_poc_execution(
    intent: Mapping[str, Any],
    plan: Mapping[str, Any],
    artifact: Mapping[str, Any],
    policy: Mapping[str, Any],
    authorization: Mapping[str, Any],
) -> Dict[str, Any]:
    """Validate the sole narrowly-scoped exception usable by the POC worker.

    This function never removes a blocker from the artifact and never opens a
    device connection.  It only proves that a worker may treat the *single*
    local-DHCP/attachment acceptance blocker as authorized for one immutable
    SJC23 plan.  Any other blocker, policy, topology, plan, or artifact drift
    stays fail-closed.
    """

    _require(isinstance(authorization, Mapping), "POC execution authorization must be an object")
    _require(
        set(authorization) == {"change_reference", "plan_hash", "artifact_hash"},
        "POC execution authorization has unsupported fields",
    )
    _require(
        str(authorization.get("change_reference", "")) == _CHANGE_REFERENCE,
        "SJC23 POC execution change reference is required",
    )
    _require(
        str(authorization.get("plan_hash", "")) == str(plan.get("plan_hash", "")),
        "POC execution authorization does not match the plan hash",
    )
    _require(
        str(authorization.get("artifact_hash", "")) == str(artifact.get("artifact_hash", "")),
        "POC execution authorization does not match the artifact hash",
    )

    preview = build_sjc23_poc_deployment_preview(intent, plan, artifact, policy)
    blockers = list(preview["blocking_requirements"])
    _require(
        blockers == [_REQUIRED_BLOCKER],
        "SJC23 POC execution permits only the local-DHCP/attachment blocker",
    )
    return {
        "scope": str(preview["scope"]),
        "change_reference": _CHANGE_REFERENCE,
        "plan_hash": str(plan["plan_hash"]),
        "artifact_hash": str(artifact["artifact_hash"]),
        "allowed_blocker_codes": [_REQUIRED_BLOCKER],
        "deployment_authorized": False,
    }


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PocExecutionError(message)


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    _require(isinstance(value, Mapping), "{} must be an object".format(label))
    return value


def _list(value: Any, label: str) -> Sequence[Any]:
    _require(isinstance(value, list), "{} must be a list".format(label))
    return value


def _index(items: Sequence[Any], key: str, label: str) -> Dict[str, Mapping[str, Any]]:
    indexed: Dict[str, Mapping[str, Any]] = {}
    for item in items:
        mapping = _mapping(item, label)
        item_id = str(mapping.get(key, ""))
        _require(bool(item_id), "{} item is missing {}".format(label, key))
        _require(item_id not in indexed, "{} contains duplicate {} {}".format(label, key, item_id))
        indexed[item_id] = mapping
    return indexed


def _command_summary(artifact_device: Mapping[str, Any], device_id: str) -> Dict[str, Any]:
    phases = _list(artifact_device.get("phases"), "artifact device phases")
    phase_ids = [str(_mapping(phase, "artifact phase").get("phase_id", "")) for phase in phases]
    _require(
        phase_ids == _EXPECTED_PHASES[device_id],
        "artifact phase sequence is outside the SJC23 POC scope for {}".format(device_id),
    )
    phase_summaries = []
    for phase in phases:
        phase_mapping = _mapping(phase, "artifact phase")
        blocks = _list(phase_mapping.get("blocks"), "artifact blocks")
        block_hashes = []
        command_count = 0
        for block in blocks:
            block_mapping = _mapping(block, "artifact block")
            block_hash = str(block_mapping.get("command_hash", ""))
            _require(len(block_hash) == 64, "artifact block command hash is invalid")
            commands = _list(block_mapping.get("commands"), "artifact block commands")
            command_count += len(commands)
            block_hashes.append(block_hash)
        phase_summaries.append(
            {
                "phase_id": str(phase_mapping["phase_id"]),
                "command_block_count": len(blocks),
                "command_count": command_count,
                "command_block_hashes": block_hashes,
            }
        )
    return {"device_id": device_id, "phases": phase_summaries}


def build_sjc23_poc_deployment_preview(
    intent: Mapping[str, Any],
    plan: Mapping[str, Any],
    artifact: Mapping[str, Any],
    policy: Mapping[str, Any],
) -> Dict[str, Any]:
    """Return a secret-free, review-only summary of the derived POC artifact.

    A caller cannot use this helper to create a production deployment preview:
    every material fact is pinned to the approved two-device SJC23 scope.  The
    current hardware-acceptance blocker is required, so the preview itself
    cannot be mistaken for authorization to Apply.
    """

    _require(str(policy.get("policy_version", "")) == _POLICY_VERSION, "SJC23 POC policy version is required")
    metadata = _mapping(intent.get("metadata"), "intent metadata")
    _require(
        str(metadata.get("change_reference", "")) == _CHANGE_REFERENCE,
        "SJC23 POC change reference is required",
    )
    fabric = _mapping(intent.get("fabric"), "intent fabric")
    _require(str(fabric.get("id", "")) == _FABRIC_ID, "SJC23 POC fabric id is required")
    _require(str(fabric.get("underlay_protocol", "")) == "isis", "SJC23 POC requires IS-IS")
    _require(int(fabric.get("mtu", 0)) == 9100, "SJC23 POC requires MTU 9100")

    devices = _index(_list(intent.get("devices"), "intent devices"), "id", "intent devices")
    _require(set(devices) == set(_DEVICE_SCOPE), "device inventory is outside the SJC23 POC scope")
    for device_id, expected in _DEVICE_SCOPE.items():
        device = devices[device_id]
        _require(str(device.get("platform", "")) == expected["platform"], "device platform is outside the SJC23 POC scope")
        _require(list(device.get("roles", [])) == expected["roles"], "device roles are outside the SJC23 POC scope")

    links = _list(intent.get("links"), "intent links")
    _require(len(links) == 1, "SJC23 POC requires exactly one underlay link")
    link = _mapping(links[0], "underlay link")
    _require(str(link.get("subnet", "")) == "10.255.0.0/31", "SJC23 POC underlay subnet is invalid")
    endpoints = _list(link.get("endpoints"), "underlay endpoints")
    endpoint_summary = [
        {
            "device_id": str(_mapping(endpoint, "underlay endpoint").get("device_id", "")),
            "interface": str(_mapping(endpoint, "underlay endpoint").get("interface", "")),
            "ip": str(_mapping(endpoint, "underlay endpoint").get("ip", "")),
        }
        for endpoint in endpoints
    ]
    _require(
        endpoint_summary
        == [
            {"device_id": "border-cp-01", "interface": "TwentyFiveGigE1/0/2", "ip": "10.255.0.0"},
            {"device_id": "edge-01", "interface": "GigabitEthernet1/0/2", "ip": "10.255.0.1"},
        ],
        "underlay endpoints are outside the SJC23 POC scope",
    )

    lisp = _mapping(intent.get("lisp"), "intent lisp")
    _require(str(lisp.get("site_name", "")) == "site_sjc23", "SJC23 POC LISP site is invalid")
    _require(list(lisp.get("map_servers", [])) == ["border-cp-01"], "SJC23 POC map server is invalid")
    auth_key_ref = str(lisp.get("auth_key_ref", ""))
    _require(
        auth_key_ref.startswith("secret://"),
        "POC LISP authentication must remain a protected reference",
    )

    handoff = _mapping(intent.get("border_handoff"), "border handoff")
    _require(handoff == {"enabled": False, "mode": "isolated"}, "SJC23 POC must remain isolated")

    pools = _index(_list(intent.get("endpoint_pools"), "endpoint pools"), "id", "endpoint pools")
    expected_pools = {
        "sjc23-corporate": ("Corporate", "10.30.100.0/24", 100, "10.30.100.1"),
        "sjc23-guest": ("Guest", "10.30.200.0/24", 200, "10.30.200.1"),
    }
    _require(set(pools) == set(expected_pools), "endpoint pools are outside the SJC23 POC scope")
    pool_summary = []
    for pool_id, (virtual_network, prefix, vlan_id, gateway) in expected_pools.items():
        pool = pools[pool_id]
        _require(str(pool.get("virtual_network", "")) == virtual_network, "endpoint pool virtual network is invalid")
        _require(str(pool.get("prefix", "")) == prefix, "endpoint pool prefix is invalid")
        _require(int(pool.get("vlan_id", 0)) == vlan_id, "endpoint pool VLAN is invalid")
        _require(str(pool.get("gateway", "")) == gateway, "endpoint pool gateway is invalid")
        dhcp = _mapping(pool.get("dhcp"), "endpoint pool dhcp")
        _require(str(dhcp.get("mode", "")) == "local_border", "SJC23 POC requires local-border DHCP")
        _require(str(dhcp.get("server_device_id", "")) == "border-cp-01", "SJC23 POC DHCP server is invalid")
        pool_summary.append(
            {
                "virtual_network": virtual_network,
                "vrf": "CORP_VN" if virtual_network == "Corporate" else "GUEST_VN",
                "vlan_id": vlan_id,
                "endpoint_prefix": prefix,
                "gateway": gateway,
                "dhcp_mode": "local_border",
                "dhcp_server_device_id": "border-cp-01",
                "dhcp_lease_minutes": int(dhcp["lease_minutes"]),
                "dns_servers": sorted(str(server) for server in dhcp.get("dns_servers", [])),
            }
        )

    attachments = _index(_list(intent.get("endpoint_attachments"), "endpoint attachments"), "id", "endpoint attachments")
    expected_attachments = {
        "corp-laptop": ("GigabitEthernet1/0/10", "Corporate", 100),
        "guest-laptop": ("GigabitEthernet1/0/11", "Guest", 200),
    }
    _require(set(attachments) == set(expected_attachments), "endpoint attachments are outside the SJC23 POC scope")
    attachment_summary = []
    for attachment_id, (interface, virtual_network, vlan_id) in expected_attachments.items():
        attachment = attachments[attachment_id]
        _require(str(attachment.get("device_id", "")) == "edge-01", "attachment device is invalid")
        _require(str(attachment.get("interface", "")) == interface, "attachment interface is invalid")
        _require(str(attachment.get("virtual_network", "")) == virtual_network, "attachment virtual network is invalid")
        _require(int(attachment.get("vlan_id", 0)) == vlan_id, "attachment VLAN is invalid")
        attachment_summary.append(
            {
                "attachment_id": attachment_id,
                "device_id": "edge-01",
                "interface": interface,
                "virtual_network": virtual_network,
                "vlan_id": vlan_id,
            }
        )

    safety = _mapping(plan.get("safety"), "plan safety")
    _require(safety.get("executable") is False, "SJC23 POC preview must remain non-executable")
    _require(artifact.get("executable") is False, "SJC23 POC artifact must remain non-executable")
    _require(artifact.get("contains_secret_values") is False, "SJC23 POC artifact may not contain secret values")
    blockers = _list(artifact.get("blocking_requirements"), "artifact blockers")
    blocker_codes = [str(_mapping(blocker, "artifact blocker").get("code", "")) for blocker in blockers]
    _require(_REQUIRED_BLOCKER in blocker_codes, "SJC23 POC hardware-acceptance blocker is required")

    artifact_devices = _mapping(artifact.get("devices"), "artifact devices")
    _require(set(artifact_devices) == set(_DEVICE_SCOPE), "artifact devices are outside the SJC23 POC scope")
    device_summary = []
    for device_id in sorted(_DEVICE_SCOPE):
        device = devices[device_id]
        command_summary = _command_summary(_mapping(artifact_devices[device_id], "artifact device"), device_id)
        device_summary.append(
            {
                "device_id": device_id,
                "hostname": str(device.get("hostname", "")),
                "platform": _DEVICE_SCOPE[device_id]["platform"],
                "roles": list(_DEVICE_SCOPE[device_id]["roles"]),
                **command_summary,
            }
        )

    return {
        "status": "poc_deployment_preview_ready",
        "scope": "sjc23_isolated_two_node",
        "change_reference": _CHANGE_REFERENCE,
        "deployment_authorized": False,
        "artifact_hash": str(artifact.get("artifact_hash", "")),
        "plan_hash": str(plan.get("plan_hash", "")),
        "underlay": {
            "protocol": "isis",
            "mtu": 9100,
            "subnet": "10.255.0.0/31",
            "endpoints": endpoint_summary,
            "bfd": dict(_mapping(link.get("bfd"), "underlay BFD")),
        },
        "lisp": {"site_name": "site_sjc23", "map_servers": ["border-cp-01"]},
        "virtual_networks": pool_summary,
        "endpoint_attachments": attachment_summary,
        "devices": device_summary,
        "blocking_requirements": blocker_codes,
        "contains_secret_values": False,
        "contains_raw_configuration": False,
    }
