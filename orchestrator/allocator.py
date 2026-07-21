"""Deterministic requirements-to-intent allocation.

This module has no database or device side effects.  It receives high-level
requirements, versioned guardrails, and the currently active allocation
ledger, then returns a complete fabric intent plus the resources that must be
reserved atomically by the store.
"""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from jsonschema import Draft202012Validator, FormatChecker


class AllocationError(ValueError):
    """Raised when requirements cannot be satisfied by the guardrails."""


REQUIREMENTS_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "fabric-requirements.schema.json"
MAX_HIERARCHY_DEPTH = 16


def validate_requirements_shape(requirements: Mapping[str, Any]) -> None:
    schema = json.loads(REQUIREMENTS_SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(requirements), key=lambda item: list(item.absolute_path))
    if not errors:
        return
    error = errors[0]
    path = "$"
    for item in error.absolute_path:
        path += "[{}]".format(item) if isinstance(item, int) else ".{}".format(item)
    raise AllocationError("Requirements schema error at {}: {}".format(path, error.message))


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _version_tuple(value: str) -> Tuple[int, ...]:
    numbers = re.findall(r"\d+", str(value))
    if not numbers:
        raise AllocationError("Software version {!r} is not comparable".format(value))
    return tuple(int(item) for item in numbers[:4])


def _network(value: str) -> ipaddress.IPv4Network:
    try:
        parsed = ipaddress.ip_network(str(value), strict=True)
    except ValueError as exc:
        raise AllocationError("Invalid IPv4 prefix {!r}".format(value)) from exc
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise AllocationError("Only IPv4 allocation pools are supported")
    return parsed


def _active_networks(
    ledger: Iterable[Mapping[str, Any]], domain: str, pool_id: str
) -> List[ipaddress.IPv4Network]:
    active = []
    for item in ledger:
        if str(item.get("allocation_domain")) != domain:
            continue
        if str(item.get("resource_pool_id")) != pool_id:
            continue
        if str(item.get("state", "reserved")) not in {
            "reserved",
            "committed",
            "quarantined",
        }:
            continue
        active.append(_network(str(item["prefix"])))
    return active


def _active_scalars(
    ledger: Iterable[Mapping[str, Any]], domain: str, resource_type: str
) -> set:
    return {
        str(item["value"])
        for item in ledger
        if str(item.get("allocation_domain")) == domain
        and str(item.get("resource_type")) == resource_type
        and str(item.get("state", "reserved"))
        in {"reserved", "committed", "quarantined"}
    }


def _policy_reserved_networks(pool_id: str, pool: Mapping[str, Any]) -> List[ipaddress.IPv4Network]:
    """Return policy-reserved space after proving it belongs to the pool."""
    supernet = _network(str(pool["cidr"]))
    reserved = []
    for raw_prefix in pool.get("reserved", []):
        prefix = _network(str(raw_prefix))
        if not prefix.subnet_of(supernet):
            raise AllocationError(
                "Reserved prefix {} is outside guardrail pool {} ({})".format(
                    prefix, pool_id, supernet
                )
            )
        reserved.append(prefix)
    return reserved


def _policy_reserved_scalars(
    resource_type: str, range_policy: Mapping[str, Any]
) -> set:
    """Expand explicitly reserved scalar values and inclusive ranges."""
    minimum = int(range_policy.get("min", range_policy.get("base", 0)))
    maximum = int(range_policy.get("max", minimum))
    reserved = {int(value) for value in range_policy.get("reserved", [])}
    for bounds in range_policy.get("reserved_ranges", []):
        if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
            raise AllocationError(
                "Reserved range for {} must contain [start, end]".format(resource_type)
            )
        start, end = int(bounds[0]), int(bounds[1])
        if end < start:
            raise AllocationError(
                "Reserved range for {} has end before start".format(resource_type)
            )
        reserved.update(range(start, end + 1))
    outside = sorted(value for value in reserved if value < minimum or value > maximum)
    if outside:
        raise AllocationError(
            "Reserved {} value {} is outside {}-{}".format(
                resource_type, outside[0], minimum, maximum
            )
        )
    return {str(value) for value in reserved}


def _first_prefix(
    supernet: ipaddress.IPv4Network,
    prefix_len: int,
    excluded: Sequence[ipaddress.IPv4Network],
) -> ipaddress.IPv4Network:
    if prefix_len < supernet.prefixlen or prefix_len > 32:
        raise AllocationError(
            "Prefix length /{} cannot be carved from {}".format(prefix_len, supernet)
        )
    for candidate in supernet.subnets(new_prefix=prefix_len):
        if not any(candidate.overlaps(item) for item in excluded):
            return candidate
    raise AllocationError("Address pool {} is exhausted for /{}".format(supernet, prefix_len))


def _first_scalar(minimum: int, maximum: int, excluded: set, label: str) -> int:
    for candidate in range(int(minimum), int(maximum) + 1):
        if str(candidate) not in excluded:
            return candidate
    raise AllocationError("Scalar pool {} is exhausted".format(label))


def _host_prefix(users: int, headroom_percent: int, supernet_prefix: int) -> int:
    if users < 1:
        raise AllocationError("users must be at least 1")
    if headroom_percent < 0 or headroom_percent > 500:
        raise AllocationError("headroom_percent must be between 0 and 500")
    required = int(math.ceil(users * (1.0 + headroom_percent / 100.0)))
    host_bits = 2
    while (2 ** host_bits) - 2 < required:
        host_bits += 1
    prefix = 32 - host_bits
    if prefix < supernet_prefix:
        raise AllocationError(
            "Overlay requirement of {} usable hosts exceeds its supernet".format(required)
        )
    return prefix


def _platform_guardrail(device: Mapping[str, Any], policy: Mapping[str, Any]) -> None:
    model = str(device["platform"])
    roles = set(str(role) for role in device["roles"])
    entries = [
        entry
        for entry in policy.get("platform_matrix", [])
        if str(entry.get("model")) == model
    ]
    if not entries:
        raise AllocationError("Platform {} is not approved by guardrails".format(model))
    entry = entries[0]
    allowed = set(str(role) for role in entry.get("roles", []))
    if not roles.issubset(allowed):
        raise AllocationError(
            "Platform {} does not support requested roles {}".format(
                model, sorted(roles - allowed)
            )
        )
    if _version_tuple(str(device["software_version"])) < _version_tuple(
        str(entry["min_ios_xe"])
    ):
        raise AllocationError(
            "Platform {} requires IOS XE {} or later".format(model, entry["min_ios_xe"])
        )


def _require_keys(document: Mapping[str, Any], keys: Sequence[str], path: str) -> None:
    missing = [key for key in keys if key not in document]
    if missing:
        raise AllocationError("{} is missing {}".format(path, ", ".join(missing)))


def _derive_site_context(
    requirements: Mapping[str, Any], policy: Mapping[str, Any]
) -> Dict[str, Any]:
    """Validate and canonicalize the CVD-aligned hierarchy and site model."""

    schema_version = str(requirements.get("schema_version", ""))
    context_keys = ("deployment_model", "site_hierarchy", "fabric_sites", "fabric_zones")
    has_context = any(key in requirements for key in context_keys)
    if schema_version == "1.0" and not has_context:
        return {}
    if schema_version not in {"1.1", "1.2"}:
        raise AllocationError("CVD site context requires requirements schema_version 1.1 or 1.2")

    deployment_model = str(requirements.get("deployment_model", ""))
    allowed_models = set(policy.get("deployment_models", []))
    if deployment_model not in allowed_models:
        raise AllocationError(
            "Deployment model {} is not approved by guardrails".format(deployment_model)
        )

    nodes: List[Dict[str, Any]] = []
    node_by_id: Dict[str, Dict[str, Any]] = {}
    for raw in sorted(
        (copy.deepcopy(item) for item in requirements.get("site_hierarchy", [])),
        key=lambda item: str(item.get("id", "")),
    ):
        node_id = str(raw.get("id", ""))
        if node_id in node_by_id:
            raise AllocationError("Duplicate hierarchy node id {}".format(node_id))
        node_by_id[node_id] = raw
        nodes.append(raw)

    global_nodes = [item for item in nodes if str(item.get("type")) == "global"]
    if len(global_nodes) != 1:
        raise AllocationError("Site hierarchy requires exactly one global node")
    allowed_children = {
        "global": {"area", "building"},
        "area": {"area", "building"},
        "building": {"floor"},
        "floor": set(),
    }
    parents: Dict[str, str] = {}
    for node in nodes:
        node_id = str(node["id"])
        node_type = str(node["type"])
        parent_id = node.get("parent_id")
        if node_type == "global":
            if parent_id is not None:
                raise AllocationError("Global hierarchy node cannot have a parent")
            continue
        if not parent_id or str(parent_id) not in node_by_id:
            raise AllocationError("Hierarchy node {} references an unknown parent".format(node_id))
        parent_id = str(parent_id)
        parent_type = str(node_by_id[parent_id]["type"])
        if node_type not in allowed_children.get(parent_type, set()):
            raise AllocationError(
                "Hierarchy type {} cannot be a child of {}".format(node_type, parent_type)
            )
        parents[node_id] = parent_id

    max_depth = int(policy.get("hierarchy", {}).get("max_depth", MAX_HIERARCHY_DEPTH))
    if max_depth < 1 or max_depth > MAX_HIERARCHY_DEPTH:
        raise AllocationError(
            "Guardrail hierarchy.max_depth must be between 1 and {}".format(
                MAX_HIERARCHY_DEPTH
            )
        )
    depths: Dict[str, int] = {str(global_nodes[0]["id"]): 0}
    for start in sorted(node_by_id):
        trail: List[str] = []
        visiting = set()
        cursor = start
        while cursor not in depths:
            if cursor in visiting:
                raise AllocationError("Site hierarchy contains a parent cycle")
            visiting.add(cursor)
            trail.append(cursor)
            if cursor not in parents:
                depths[cursor] = 0
                break
            cursor = parents[cursor]
        depth = depths[cursor]
        for node_id in reversed(trail):
            if node_id in depths:
                depth = depths[node_id]
                continue
            depth += 1
            if depth > max_depth:
                raise AllocationError(
                    "Site hierarchy exceeds maximum depth {}".format(max_depth)
                )
            depths[node_id] = depth

    nodes.sort(key=lambda item: (depths[str(item["id"])], str(item["id"])))

    raw_profiles = policy.get("site_profiles", [])
    profile_order: List[str] = []
    profile_limits: Dict[str, Mapping[str, Any]] = {}
    for entry in raw_profiles:
        if not isinstance(entry, Mapping) or not entry.get("id"):
            raise AllocationError("Guardrail site profile is invalid")
        profile_id = str(entry["id"])
        if profile_id in profile_limits:
            raise AllocationError("Duplicate guardrail site profile {}".format(profile_id))
        profile_order.append(profile_id)
        profile_limits[profile_id] = entry
    if not profile_order:
        raise AllocationError("Guardrail site profiles are missing")

    sites: List[Dict[str, Any]] = []
    site_by_id: Dict[str, Dict[str, Any]] = {}
    site_nodes = set()
    for raw in sorted(
        (copy.deepcopy(item) for item in requirements.get("fabric_sites", [])),
        key=lambda item: str(item.get("id", "")),
    ):
        site_id = str(raw.get("id", ""))
        if site_id in site_by_id:
            raise AllocationError("Duplicate fabric site id {}".format(site_id))
        hierarchy_node_id = str(raw.get("hierarchy_node_id", ""))
        if hierarchy_node_id not in node_by_id:
            raise AllocationError(
                "Fabric site {} references an unknown hierarchy node".format(site_id)
            )
        if str(node_by_id[hierarchy_node_id]["type"]) == "global":
            raise AllocationError("A fabric site cannot be attached to the global node")
        if hierarchy_node_id in site_nodes:
            raise AllocationError(
                "Hierarchy node {} is already assigned to a fabric site".format(
                    hierarchy_node_id
                )
            )
        site_nodes.add(hierarchy_node_id)
        endpoints = int(raw["endpoint_count"])
        aps = int(raw["ap_count"])
        recommended = next(
            (
                profile_id
                for profile_id in profile_order
                if endpoints <= int(profile_limits[profile_id]["max_endpoints"])
                and aps <= int(profile_limits[profile_id]["max_aps"])
            ),
            None,
        )
        if recommended is None:
            raise AllocationError(
                "Fabric site {} exceeds the largest approved site profile".format(site_id)
            )
        selected = str(raw.get("profile") or recommended)
        if selected not in profile_limits:
            raise AllocationError("Unknown site profile {}".format(selected))
        if endpoints > int(profile_limits[selected]["max_endpoints"]) or aps > int(
            profile_limits[selected]["max_aps"]
        ):
            raise AllocationError(
                "Fabric site {} exceeds selected profile {}".format(site_id, selected)
            )
        raw["profile"] = selected
        site_by_id[site_id] = raw
        sites.append(raw)

    if deployment_model == "single_site" and len(sites) != 1:
        raise AllocationError("single_site deployment requires exactly one fabric site")
    if deployment_model == "distributed_campus" and len(sites) < 2:
        raise AllocationError("distributed_campus requires at least two fabric sites")

    site_ids = set(site_by_id)
    for device in requirements.get("devices", []):
        if str(device.get("site", "")) not in site_ids:
            raise AllocationError(
                "Device {} references an unknown fabric site".format(device.get("id", ""))
            )
    vn_names = {str(item.get("name", "")) for item in requirements.get("virtual_networks", [])}
    for virtual_network in requirements.get("virtual_networks", []):
        for site in virtual_network.get("sites", []):
            if str(site.get("site", "")) not in site_ids:
                raise AllocationError(
                    "Virtual network {} references an unknown fabric site".format(
                        virtual_network.get("name", "")
                    )
                )

    def is_descendant(node_id: str, ancestor_id: str) -> bool:
        cursor = node_id
        visited = set()
        while True:
            if cursor == ancestor_id:
                return True
            if cursor in visited or cursor not in parents:
                return False
            visited.add(cursor)
            cursor = parents[cursor]

    zones: List[Dict[str, Any]] = []
    zone_ids = set()
    for raw in sorted(
        (copy.deepcopy(item) for item in requirements.get("fabric_zones", [])),
        key=lambda item: str(item.get("id", "")),
    ):
        zone_id = str(raw.get("id", ""))
        if zone_id in zone_ids:
            raise AllocationError("Duplicate fabric zone id {}".format(zone_id))
        zone_ids.add(zone_id)
        site_id = str(raw.get("fabric_site_id", ""))
        node_id = str(raw.get("hierarchy_node_id", ""))
        if site_id not in site_by_id:
            raise AllocationError("Fabric zone {} references an unknown site".format(zone_id))
        if node_id not in node_by_id:
            raise AllocationError(
                "Fabric zone {} references an unknown hierarchy node".format(zone_id)
            )
        if not is_descendant(node_id, str(site_by_id[site_id]["hierarchy_node_id"])):
            raise AllocationError(
                "Fabric zone {} is outside its fabric site hierarchy".format(zone_id)
            )
        unknown_vns = sorted(set(str(item) for item in raw["virtual_networks"]) - vn_names)
        if unknown_vns:
            raise AllocationError(
                "Fabric zone {} references unknown virtual network {}".format(
                    zone_id, unknown_vns[0]
                )
            )
        raw["virtual_networks"] = sorted(str(item) for item in raw["virtual_networks"])
        zones.append(raw)

    return {
        "deployment_model": deployment_model,
        "site_hierarchy": nodes,
        "fabric_sites": sites,
        "fabric_zones": zones,
    }


def derive_fabric_intent(
    requirements: Mapping[str, Any],
    policy: Mapping[str, Any],
    network_ledger: Iterable[Mapping[str, Any]] = (),
    scalar_ledger: Iterable[Mapping[str, Any]] = (),
) -> Dict[str, Any]:
    """Derive a complete static intent and a reservation set.

    The caller must atomically persist every returned reservation.  Passing
    active ledger entries makes this function brownfield- and concurrency-safe
    when used inside the store's serialized allocation transaction.
    """

    validate_requirements_shape(requirements)
    if (
        str(requirements.get("schema_version")) != "1.2"
        and "multicast" in requirements
    ):
        raise AllocationError(
            "Top-level multicast requirements require schema_version 1.2"
        )
    _require_keys(
        requirements,
        ["schema_version", "metadata", "allocation_domain", "fabric", "devices", "links", "virtual_networks"],
        "$",
    )
    domain = str(requirements["allocation_domain"])
    if not domain:
        raise AllocationError("allocation_domain is required")
    fabric = requirements["fabric"]
    _require_keys(fabric, ["id", "name", "mtu", "control_plane_mode"], "$.fabric")
    mode = str(fabric["control_plane_mode"])
    allowed_modes = set(policy.get("fabric_control_plane", {}).get("allowed_modes", []))
    if mode not in allowed_modes:
        raise AllocationError("Control-plane mode {} is not approved".format(mode))
    identity_override_requested = fabric.get("lisp_domain_id") is not None or any(
        site.get("lisp_multihoming_id") is not None
        for site in requirements.get("fabric_sites", [])
    )
    if identity_override_requested and (
        str(requirements["schema_version"]) != "1.2" or mode != "lisp_pubsub"
    ):
        raise AllocationError(
            "LISP identity overrides require schema 1.2 lisp_pubsub mode"
        )
    site_context = _derive_site_context(requirements, policy)

    pools = policy.get("supernets", {})
    for pool_id in ("underlay_p2p", "loopbacks", "overlay_hosts"):
        if pool_id not in pools:
            raise AllocationError("Guardrail pool {} is missing".format(pool_id))

    network_taken: Dict[str, List[ipaddress.IPv4Network]] = {
        pool_id: _active_networks(network_ledger, domain, pool_id)
        + _policy_reserved_networks(pool_id, pool)
        for pool_id, pool in pools.items()
    }
    ranges = policy.get("ranges", {})
    scalar_range_names = {
        "vlan_id": "vlan_id",
        "l2_instance_id": "l2_instance_id",
        "l3_instance_id": "l3_instance_id",
        "asn": "bgp_asn_local",
        "sgt": "sgt",
        "lisp_domain_id": "lisp_domain_id",
        "lisp_multihoming_id": "lisp_multihoming_id",
    }
    scalar_taken: Dict[str, set] = {
        kind: _active_scalars(scalar_ledger, domain, kind)
        | _policy_reserved_scalars(kind, ranges[range_name])
        if isinstance(ranges.get(range_name), Mapping)
        else _active_scalars(scalar_ledger, domain, kind)
        for kind, range_name in scalar_range_names.items()
    }
    net_reservations: List[Dict[str, Any]] = []
    scalar_reservations: List[Dict[str, Any]] = []

    def reserve_prefix(pool_id: str, prefix_len: int) -> ipaddress.IPv4Network:
        supernet = _network(str(pools[pool_id]["cidr"]))
        candidate = _first_prefix(supernet, prefix_len, network_taken[pool_id])
        network_taken[pool_id].append(candidate)
        net_reservations.append(
            {
                "allocation_domain": domain,
                "resource_pool_id": pool_id,
                "prefix": str(candidate),
                "state": "reserved",
            }
        )
        return candidate

    def reserve_scalar(kind: str, minimum: int, maximum: int) -> int:
        candidate = _first_scalar(minimum, maximum, scalar_taken[kind], kind)
        scalar_taken[kind].add(str(candidate))
        scalar_reservations.append(
            {
                "allocation_domain": domain,
                "resource_type": kind,
                "value": str(candidate),
                "state": "reserved",
            }
        )
        return candidate

    def reserve_requested_scalar(kind: str, value: int, minimum: int, maximum: int) -> int:
        candidate = int(value)
        if candidate < int(minimum) or candidate > int(maximum):
            raise AllocationError(
                "Requested {} value {} is outside {}-{}".format(
                    kind, candidate, minimum, maximum
                )
            )
        if str(candidate) in scalar_taken[kind]:
            raise AllocationError("Requested {} value {} is unavailable".format(kind, candidate))
        scalar_taken[kind].add(str(candidate))
        scalar_reservations.append(
            {
                "allocation_domain": domain,
                "resource_type": kind,
                "value": str(candidate),
                "state": "reserved",
            }
        )
        return candidate

    raw_devices = sorted(
        (copy.deepcopy(item) for item in requirements["devices"]),
        key=lambda item: str(item["id"]),
    )
    if len(raw_devices) < 2:
        raise AllocationError("At least two devices are required")
    device_ids = set()
    devices = []
    for raw in raw_devices:
        _require_keys(
            raw,
            ["id", "site", "platform", "software_version", "management_ip", "roles", "credential_ref"],
            "$.devices[]",
        )
        device_id = str(raw["id"])
        if device_id in device_ids:
            raise AllocationError("Duplicate device id {}".format(device_id))
        device_ids.add(device_id)
        _platform_guardrail(raw, policy)
        loopback = reserve_prefix("loopbacks", int(pools["loopbacks"]["prefix_len"]))
        device = {
            "id": device_id,
            "hostname": str(raw.get("hostname") or device_id).upper(),
            "site": str(raw["site"]),
            "platform": str(raw["platform"]),
            "software_version": str(raw["software_version"]),
            "management_ip": str(raw["management_ip"]),
            "loopback0_ip": str(loopback.network_address),
            "roles": sorted(str(role) for role in raw["roles"]),
            "credential_ref": str(raw["credential_ref"]),
        }
        if raw.get("dashboard_management_ip"):
            device["dashboard_management_ip"] = str(raw["dashboard_management_ip"])
        devices.append(device)

    fusion_nodes: List[Dict[str, Any]] = []
    fusion_ids = set()
    for raw in sorted(
        (copy.deepcopy(item) for item in requirements.get("fusion_nodes", [])),
        key=lambda item: str(item.get("id", "")),
    ):
        _require_keys(
            raw,
            [
                "id",
                "hostname",
                "platform",
                "software_version",
                "management_ip",
                "credential_ref",
                "bgp_asn",
            ],
            "$.fusion_nodes[]",
        )
        fusion_id = str(raw["id"])
        if fusion_id in fusion_ids or fusion_id in device_ids:
            raise AllocationError("Duplicate fusion or device id {}".format(fusion_id))
        fusion_ids.add(fusion_id)
        platform_candidate = dict(raw)
        platform_candidate["roles"] = ["fusion"]
        _platform_guardrail(platform_candidate, policy)
        fusion_node = {
            "id": fusion_id,
            "hostname": str(raw["hostname"]).upper(),
            "platform": str(raw["platform"]),
            "software_version": str(raw["software_version"]),
            "management_ip": str(raw["management_ip"]),
            "credential_ref": str(raw["credential_ref"]),
            "bgp_asn": int(raw["bgp_asn"]),
        }
        if raw.get("dashboard_management_ip"):
            fusion_node["dashboard_management_ip"] = str(raw["dashboard_management_ip"])
        fusion_nodes.append(fusion_node)

    links = []
    p2p_prefix = int(pools["underlay_p2p"]["prefix_len"])
    for raw in sorted(requirements["links"], key=lambda item: str(item["id"])):
        _require_keys(raw, ["id", "endpoints"], "$.links[]")
        endpoints = sorted(
            (copy.deepcopy(item) for item in raw["endpoints"]),
            key=lambda item: (str(item["device_id"]), str(item["interface"])),
        )
        if len(endpoints) != 2:
            raise AllocationError("Link {} must have exactly two endpoints".format(raw["id"]))
        if any(str(item["device_id"]) not in device_ids for item in endpoints):
            raise AllocationError("Link {} references an unknown device".format(raw["id"]))
        subnet = reserve_prefix("underlay_p2p", p2p_prefix)
        hosts = list(subnet)
        link = {
            "id": str(raw["id"]),
            "subnet": str(subnet),
            "endpoints": [
                {
                    "device_id": str(endpoint["device_id"]),
                    "interface": str(endpoint["interface"]),
                    "ip": str(hosts[index]),
                }
                for index, endpoint in enumerate(endpoints)
            ],
        }
        if "pim_sparse_mode" in raw:
            link["pim_sparse_mode"] = bool(raw["pim_sparse_mode"])
        if "bfd" in raw:
            link["bfd"] = copy.deepcopy(raw["bfd"])
        links.append(link)

    raw_handoff = requirements.get("border_handoff") or {
        "enabled": False,
        "mode": "isolated",
    }
    bgp_enabled = bool(raw_handoff.get("enabled")) and str(
        raw_handoff.get("mode")
    ) == "bgp"
    if bgp_enabled or mode == "lisp_bgp_transit":
        asn_range = ranges["bgp_asn_local"]
        local_as = reserve_scalar("asn", int(asn_range["min"]), int(asn_range["max"]))
    else:
        local_as = int(ranges.get("rd_asn", 65000))
    l3_range = ranges["l3_instance_id"]
    vlan_range = ranges["vlan_id"]
    l2_base = int(ranges["l2_instance_id"]["base"])
    l2_max = int(ranges["l2_instance_id"].get("max", 16777215))
    virtual_networks = []
    endpoint_pools = []
    for raw_vn in sorted(requirements["virtual_networks"], key=lambda item: str(item["name"])):
        _require_keys(raw_vn, ["name", "vrf", "sites"], "$.virtual_networks[]")
        l3_id = reserve_scalar(
            "l3_instance_id", int(l3_range["min"]), int(l3_range["max"])
        )
        virtual_networks.append(
            {
                "name": str(raw_vn["name"]),
                "vrf": str(raw_vn["vrf"]),
                "l3_instance_id": l3_id,
                "rd": "{}:{}".format(local_as, l3_id),
                "route_targets": ["{}:{}".format(local_as, l3_id)],
            }
        )
        for site in sorted(raw_vn["sites"], key=lambda item: str(item["site"])):
            _require_keys(site, ["site", "users", "dhcp_helpers"], "$.virtual_networks[].sites[]")
            vlan = reserve_scalar(
                "vlan_id", int(vlan_range["min"]), int(vlan_range["max"])
            )
            l2_id = l2_base + vlan
            if l2_id > l2_max or str(l2_id) in scalar_taken["l2_instance_id"]:
                raise AllocationError("Derived L2 instance {} is unavailable".format(l2_id))
            scalar_taken["l2_instance_id"].add(str(l2_id))
            scalar_reservations.append(
                {
                    "allocation_domain": domain,
                    "resource_type": "l2_instance_id",
                    "value": str(l2_id),
                    "state": "reserved",
                }
            )
            overlay_supernet = _network(str(pools["overlay_hosts"]["cidr"]))
            prefix_len = _host_prefix(
                int(site["users"]), int(site.get("headroom_percent", 25)), overlay_supernet.prefixlen
            )
            prefix = reserve_prefix("overlay_hosts", prefix_len)
            first_host = next(prefix.hosts())
            endpoint_pools.append(
                {
                    "id": "{}-{}".format(str(site["site"]).lower(), str(raw_vn["name"]).lower()),
                    "site": str(site["site"]),
                    "virtual_network": str(raw_vn["name"]),
                    "vlan_id": vlan,
                    "l2_instance_id": l2_id,
                    "prefix": str(prefix),
                    "gateway": str(first_host),
                    "dhcp_helpers": sorted(str(item) for item in site["dhcp_helpers"]),
                }
            )

    environment = str(requirements["metadata"]["environment"])
    vn_by_name = {item["name"]: item for item in virtual_networks}
    vrf_names = {item["vrf"] for item in virtual_networks}

    shared_services = None
    raw_shared_services = requirements.get("shared_services")
    if raw_shared_services is not None:
        service_vrf = str(raw_shared_services["vrf"])
        if service_vrf not in vrf_names:
            raise AllocationError("Shared-services VRF {} is unknown".format(service_vrf))
        if str(raw_shared_services.get("default_action")) != "deny":
            raise AllocationError("Shared-services default action must be deny")
        if "shared_service_handoff" not in pools:
            raise AllocationError("Guardrail pool shared_service_handoff is missing")
        shared_vlan_range = ranges.get("shared_service_vlan_id")
        if not isinstance(shared_vlan_range, Mapping):
            raise AllocationError("Guardrail range shared_service_vlan_id is missing")
        attachments = []
        attachment_ids = set()
        attached_fusions = set()
        for raw_attachment in sorted(
            (copy.deepcopy(item) for item in raw_shared_services.get("attachments", [])),
            key=lambda item: str(item.get("id", "")),
        ):
            attachment_id = str(raw_attachment["id"])
            fusion_id = str(raw_attachment["fusion_node_id"])
            if attachment_id in attachment_ids:
                raise AllocationError(
                    "Duplicate shared-service attachment {}".format(attachment_id)
                )
            attachment_ids.add(attachment_id)
            if fusion_id not in fusion_ids:
                raise AllocationError(
                    "Shared-service attachment {} references unknown fusion node {}".format(
                        attachment_id, fusion_id
                    )
                )
            if fusion_id in attached_fusions:
                raise AllocationError(
                    "Fusion node {} has multiple shared-service attachments".format(fusion_id)
                )
            attached_fusions.add(fusion_id)
            vlan = reserve_scalar(
                "vlan_id",
                int(shared_vlan_range["min"]),
                int(shared_vlan_range["max"]),
            )
            prefix = reserve_prefix(
                "shared_service_handoff",
                int(pools["shared_service_handoff"]["prefix_len"]),
            )
            addresses = list(prefix.hosts())
            if len(addresses) < 2:
                raise AllocationError(
                    "Shared-service handoff {} must provide two usable addresses".format(
                        prefix
                    )
                )
            attachments.append(
                {
                    "id": attachment_id,
                    "fusion_node_id": fusion_id,
                    "interface": str(raw_attachment["interface"]),
                    "vlan_id": vlan,
                    "prefix": str(prefix),
                    "local_ip": str(addresses[0]),
                    "next_hop": str(addresses[1]),
                }
            )
        if environment == "production":
            missing_fusions = sorted(fusion_ids - attached_fusions)
            if missing_fusions:
                raise AllocationError(
                    "Production shared services are missing attachment for fusion node {}".format(
                        missing_fusions[0]
                    )
                )
        services = []
        import_prefixes_by_consumer: Dict[str, set] = {}
        service_ids = set()
        for raw_service in sorted(
            (copy.deepcopy(item) for item in raw_shared_services.get("services", [])),
            key=lambda item: str(item.get("id", "")),
        ):
            service_id = str(raw_service["id"])
            if service_id in service_ids:
                raise AllocationError("Duplicate shared service id {}".format(service_id))
            service_ids.add(service_id)
            prefixes = sorted(str(_network(item)) for item in raw_service["prefixes"])
            parsed_prefixes = [_network(item) for item in prefixes]
            for service_prefix in parsed_prefixes:
                for endpoint_pool in endpoint_pools:
                    endpoint_prefix = _network(str(endpoint_pool["prefix"]))
                    if service_prefix.overlaps(endpoint_prefix):
                        raise AllocationError(
                            "Shared service {} prefix {} overlaps fabric endpoint pool {}".format(
                                service_id, service_prefix, endpoint_prefix
                            )
                        )
            addresses = sorted(str(ipaddress.ip_address(item)) for item in raw_service["addresses"])
            for address in addresses:
                if not any(ipaddress.ip_address(address) in prefix for prefix in parsed_prefixes):
                    raise AllocationError(
                        "Shared service {} address {} is outside its advertised prefixes".format(
                            service_id, address
                        )
                    )
            consumers = sorted(str(item) for item in raw_service["consumer_virtual_networks"])
            unknown_consumers = sorted(set(consumers) - set(vn_by_name))
            if unknown_consumers:
                raise AllocationError(
                    "Shared service {} references unknown virtual network {}".format(
                        service_id, unknown_consumers[0]
                    )
                )
            for consumer in consumers:
                import_prefixes_by_consumer.setdefault(consumer, set()).update(prefixes)
            services.append(
                {
                    "id": service_id,
                    "type": str(raw_service["type"]),
                    "addresses": addresses,
                    "prefixes": prefixes,
                    "consumer_virtual_networks": consumers,
                }
            )
        route_leaks = []
        for consumer in sorted(import_prefixes_by_consumer):
            export_prefixes = sorted(
                item["prefix"]
                for item in endpoint_pools
                if item["virtual_network"] == consumer
            )
            if not export_prefixes:
                raise AllocationError(
                    "Shared-services consumer {} has no endpoint pool".format(consumer)
                )
            route_leaks.append(
                {
                    "consumer_vrf": str(vn_by_name[consumer]["vrf"]),
                    "service_vrf": service_vrf,
                    "import_prefixes": sorted(import_prefixes_by_consumer[consumer]),
                    "export_prefixes": export_prefixes,
                }
            )
        shared_services = {
            "vrf": service_vrf,
            "default_action": "deny",
            "attachments": attachments,
            "services": services,
            "route_leaks": route_leaks,
        }

    multicast = None
    raw_multicast = requirements.get("multicast")
    if raw_multicast is not None:
        enabled = bool(raw_multicast["enabled"])
        transport = str(raw_multicast["transport"])
        rp_mode = str(raw_multicast["rp_mode"])
        border_ids = {
            item["id"] for item in devices if "border" in set(item.get("roles", []))
        }
        rp_device_ids = sorted(str(item) for item in raw_multicast.get("rp_device_ids", []))
        unknown_rps = sorted(set(rp_device_ids) - border_ids)
        if unknown_rps:
            raise AllocationError(
                "Multicast RP device {} is not a border".format(unknown_rps[0])
            )
        asm_vns = sorted(str(item) for item in raw_multicast["asm_virtual_networks"])
        ssm_vns = sorted(str(item) for item in raw_multicast["ssm_virtual_networks"])
        unknown_multicast_vns = sorted((set(asm_vns) | set(ssm_vns)) - set(vn_by_name))
        if unknown_multicast_vns:
            raise AllocationError(
                "Multicast references unknown virtual network {}".format(
                    unknown_multicast_vns[0]
                )
            )
        overlap_vns = sorted(set(asm_vns) & set(ssm_vns))
        if overlap_vns:
            raise AllocationError(
                "Virtual network {} cannot use both ASM and SSM".format(overlap_vns[0])
            )
        if enabled and transport == "native" and any(
            not bool(item.get("pim_sparse_mode")) for item in links
        ):
            raise AllocationError("Native multicast requires PIM sparse mode on every fabric link")
        underlay_rp_address = None
        if enabled and rp_mode in {"anycast", "static"}:
            if "multicast_rp" not in pools:
                raise AllocationError("Guardrail pool multicast_rp is missing")
            if not rp_device_ids:
                raise AllocationError("Enabled ASM multicast requires RP devices")
            if rp_mode == "anycast" and environment == "production" and len(rp_device_ids) < 2:
                raise AllocationError("Production Anycast-RP requires at least two RP devices")
            rp_prefix = reserve_prefix(
                "multicast_rp", int(pools["multicast_rp"].get("prefix_len", 32))
            )
            underlay_rp_address = str(rp_prefix.network_address)
        ssm_range = _network(str(raw_multicast.get("ssm_range", "232.0.0.0/8")))
        if not ssm_range.subnet_of(_network("232.0.0.0/8")):
            raise AllocationError("Multicast ssm_range must be inside 232.0.0.0/8")
        raw_overlay_policies = raw_multicast.get("overlay_policies", [])
        if enabled and (asm_vns or ssm_vns) and not raw_overlay_policies:
            raise AllocationError(
                "Enabled overlay multicast requires explicit per-VN overlay_policies"
            )
        if not enabled and raw_overlay_policies:
            raise AllocationError(
                "Disabled multicast cannot declare overlay_policies"
            )
        multicast_devices = sorted(
            (
                item
                for item in devices
                if set(item.get("roles", [])) & {"border", "fabric_edge"}
            ),
            key=lambda item: str(item["id"]),
        )
        if enabled and raw_overlay_policies and not multicast_devices:
            raise AllocationError(
                "Overlay multicast requires at least one border or fabric-edge device"
            )
        if raw_overlay_policies and "multicast_overlay_loopbacks" not in pools:
            raise AllocationError(
                "Guardrail pool multicast_overlay_loopbacks is missing"
            )
        core_group_pool = None
        core_group_count = None
        if enabled and transport == "native" and raw_overlay_policies:
            if "multicast_core_groups" not in pools:
                raise AllocationError("Guardrail pool multicast_core_groups is missing")
            core_group_pool = pools["multicast_core_groups"]
            core_supernet = _network(str(core_group_pool["cidr"]))
            if not core_supernet.subnet_of(_network("232.0.0.0/8")):
                raise AllocationError(
                    "Guardrail pool multicast_core_groups must be inside 232.0.0.0/8"
                )
            core_prefix_len = int(core_group_pool["prefix_len"])
            if core_prefix_len < core_supernet.prefixlen or core_prefix_len > 32:
                raise AllocationError(
                    "Guardrail multicast_core_groups prefix_len is invalid"
                )
            core_group_count = int(core_group_pool.get("usable_count", 1000))
            if core_group_count < 1 or core_group_count > (2 ** (32 - core_prefix_len)) - 1:
                raise AllocationError(
                    "Guardrail multicast_core_groups usable_count does not fit its prefix"
                )

        overlay_policies = []
        overlay_policy_names = set()
        for raw_policy in sorted(
            raw_overlay_policies,
            key=lambda item: str(item.get("virtual_network", "")),
        ):
            virtual_network = str(raw_policy["virtual_network"])
            if virtual_network in overlay_policy_names:
                raise AllocationError(
                    "Duplicate multicast overlay policy for virtual network {}".format(
                        virtual_network
                    )
                )
            overlay_policy_names.add(virtual_network)
            if virtual_network not in vn_by_name:
                raise AllocationError(
                    "Multicast overlay policy references unknown virtual network {}".format(
                        virtual_network
                    )
                )
            overlay_mode = str(raw_policy["mode"])
            expected_mode = "asm" if virtual_network in set(asm_vns) else "ssm"
            if virtual_network not in set(asm_vns) | set(ssm_vns):
                raise AllocationError(
                    "Multicast overlay policy {} is absent from ASM/SSM selections".format(
                        virtual_network
                    )
                )
            if overlay_mode != expected_mode:
                raise AllocationError(
                    "Multicast overlay policy {} mode does not match ASM/SSM selection".format(
                        virtual_network
                    )
                )
            group_range = _network(str(raw_policy["group_range"]))
            if not group_range.subnet_of(_network("224.0.0.0/4")):
                raise AllocationError(
                    "Multicast overlay policy {} group_range is not multicast".format(
                        virtual_network
                    )
                )
            if overlay_mode == "ssm" and not group_range.subnet_of(ssm_range):
                raise AllocationError(
                    "SSM policy {} group_range must be inside {}".format(
                        virtual_network, ssm_range
                    )
                )
            if overlay_mode == "asm" and group_range.overlaps(
                _network("232.0.0.0/8")
            ):
                raise AllocationError(
                    "ASM policy {} group_range cannot overlap SSM space".format(
                        virtual_network
                    )
                )

            vn = vn_by_name[virtual_network]
            derived_policy = {
                "virtual_network": virtual_network,
                "vrf": str(vn["vrf"]),
                "l3_instance_id": int(vn["l3_instance_id"]),
                "mode": overlay_mode,
                "group_range": str(group_range),
                "access_list": "SDA-MCAST-{}".format(
                    sha256_json(
                        {
                            "vrf": str(vn["vrf"]),
                            "mode": overlay_mode,
                            "group_range": str(group_range),
                        }
                    )[:12].upper()
                ),
                "segment_loopbacks": [],
            }
            if overlay_mode == "asm":
                overlay_rp_address = ipaddress.ip_address(
                    str(raw_policy["rp_address"])
                )
                rp_prefix = _network(str(raw_policy["rp_prefix"]))
                if overlay_rp_address.is_multicast or overlay_rp_address not in rp_prefix:
                    raise AllocationError(
                        "ASM policy {} RP address must be unicast and inside rp_prefix".format(
                            virtual_network
                        )
                    )
                derived_policy["rp_address"] = str(overlay_rp_address)
                derived_policy["rp_prefix"] = str(rp_prefix)
            for device in multicast_devices:
                segment_prefix = reserve_prefix(
                    "multicast_overlay_loopbacks",
                    int(pools["multicast_overlay_loopbacks"].get("prefix_len", 32)),
                )
                if segment_prefix.prefixlen != 32:
                    raise AllocationError(
                        "Guardrail multicast_overlay_loopbacks must allocate /32 addresses"
                    )
                derived_policy["segment_loopbacks"].append(
                    {
                        "device_id": str(device["id"]),
                        "address": str(segment_prefix.network_address),
                    }
                )
            if core_group_pool is not None:
                core_prefix = reserve_prefix(
                    "multicast_core_groups", int(core_group_pool["prefix_len"])
                )
                derived_policy["core_group"] = {
                    "prefix": str(core_prefix),
                    "start": str(core_prefix.network_address + 1),
                    "count": int(core_group_count),
                }
            overlay_policies.append(derived_policy)

        expected_policy_names = set(asm_vns) | set(ssm_vns)
        if overlay_policy_names != expected_policy_names:
            missing = sorted(expected_policy_names - overlay_policy_names)
            raise AllocationError(
                "Missing multicast overlay policy for virtual network {}".format(
                    missing[0]
                )
            )
        l2_bum_groups = []
        if enabled and transport == "native":
            if "multicast_bum_groups" not in pools:
                raise AllocationError("Guardrail pool multicast_bum_groups is missing")
            bum_pool = pools["multicast_bum_groups"]
            bum_supernet = _network(str(bum_pool["cidr"]))
            if (
                not bum_supernet.subnet_of(_network("224.0.0.0/4"))
                or bum_supernet.overlaps(_network("232.0.0.0/8"))
            ):
                raise AllocationError(
                    "Guardrail pool multicast_bum_groups must be ASM multicast space"
                )
            if int(bum_pool.get("prefix_len", 32)) != 32:
                raise AllocationError(
                    "Guardrail multicast_bum_groups must allocate /32 groups"
                )
            for endpoint_pool in sorted(
                endpoint_pools, key=lambda item: int(item["l2_instance_id"])
            ):
                bum_prefix = reserve_prefix("multicast_bum_groups", 32)
                l2_bum_groups.append(
                    {
                        "endpoint_pool_id": str(endpoint_pool["id"]),
                        "l2_instance_id": int(endpoint_pool["l2_instance_id"]),
                        "vlan_id": int(endpoint_pool["vlan_id"]),
                        "group": str(bum_prefix.network_address),
                    }
                )
        multicast = {
            "enabled": enabled,
            "transport": transport,
            "rp_mode": rp_mode,
            "rp_device_ids": rp_device_ids,
            "asm_virtual_networks": asm_vns,
            "ssm_virtual_networks": ssm_vns,
            "ssm_range": str(ssm_range),
            "overlay_policies": overlay_policies,
            "l2_bum_groups": l2_bum_groups,
        }
        if underlay_rp_address:
            multicast["rp_address"] = underlay_rp_address

    policy_plane = None
    raw_policy_plane = requirements.get("policy_plane")
    if raw_policy_plane is not None:
        policy_mode = str(raw_policy_plane["mode"])
        if policy_mode in {"ise", "hybrid"} and not raw_policy_plane.get("ise"):
            raise AllocationError("Policy-plane mode {} requires ISE settings".format(policy_mode))
        if policy_mode in {"sxp", "hybrid"} and not raw_policy_plane.get("sxp"):
            raise AllocationError("Policy-plane mode {} requires SXP settings".format(policy_mode))
        sgt_range = ranges.get("sgt")
        if not isinstance(sgt_range, Mapping):
            raise AllocationError("Guardrail range sgt is missing")
        security_groups = []
        security_group_names = set()
        for raw_group in sorted(
            (copy.deepcopy(item) for item in raw_policy_plane.get("security_groups", [])),
            key=lambda item: str(item.get("name", "")),
        ):
            name = str(raw_group["name"])
            if name in security_group_names:
                raise AllocationError("Duplicate security group {}".format(name))
            security_group_names.add(name)
            if raw_group.get("tag") is None:
                tag = reserve_scalar("sgt", int(sgt_range["min"]), int(sgt_range["max"]))
            else:
                tag = reserve_requested_scalar(
                    "sgt", int(raw_group["tag"]), int(sgt_range["min"]), int(sgt_range["max"])
                )
            security_groups.append({"name": name, "tag": tag})
        contracts = []
        contract_keys = set()
        for raw_contract in sorted(
            (copy.deepcopy(item) for item in raw_policy_plane.get("contracts", [])),
            key=lambda item: (
                str(item.get("source", "")),
                str(item.get("destination", "")),
                str(item.get("protocol", "")),
                str(item.get("action", "")),
            ),
        ):
            source = str(raw_contract["source"])
            destination = str(raw_contract["destination"])
            unknown_groups = sorted({source, destination} - security_group_names)
            if unknown_groups:
                raise AllocationError(
                    "Policy contract references unknown security group {}".format(
                        unknown_groups[0]
                    )
                )
            key = (source, destination, str(raw_contract["protocol"]))
            if key in contract_keys:
                raise AllocationError(
                    "Duplicate policy contract {} to {} for {}".format(*key)
                )
            contract_keys.add(key)
            contracts.append(
                {
                    "source": source,
                    "destination": destination,
                    "action": str(raw_contract["action"]),
                    "protocol": str(raw_contract["protocol"]),
                }
            )
        policy_plane = {
            "mode": policy_mode,
            "security_groups": security_groups,
            "contracts": contracts,
        }
        ise_addresses = set()
        if raw_policy_plane.get("ise"):
            raw_ise = raw_policy_plane["ise"]
            ise_addresses = {str(item["address"]) for item in raw_ise["nodes"]}
            policy_plane["ise"] = {
                "credential_ref": str(raw_ise["credential_ref"]),
                "nodes": sorted(
                    (
                        {
                            "id": str(item["id"]),
                            "address": str(item["address"]),
                            "roles": sorted(str(role) for role in item["roles"]),
                        }
                        for item in raw_ise["nodes"]
                    ),
                    key=lambda item: item["id"],
                ),
            }
        if raw_policy_plane.get("sxp"):
            raw_sxp = raw_policy_plane["sxp"]
            known_speakers = device_ids | fusion_ids
            connections = []
            connection_ids = set()
            for item in sorted(raw_sxp["connections"], key=lambda entry: str(entry["id"])):
                connection_id = str(item["id"])
                if connection_id in connection_ids:
                    raise AllocationError("Duplicate SXP connection {}".format(connection_id))
                connection_ids.add(connection_id)
                if str(item["speaker_id"]) not in known_speakers:
                    raise AllocationError(
                        "SXP connection {} references unknown speaker {}".format(
                            connection_id, item["speaker_id"]
                        )
                    )
                if policy_mode in {"ise", "hybrid"} and str(item["listener_ip"]) not in ise_addresses:
                    raise AllocationError(
                        "SXP connection {} listener {} is not an approved ISE node".format(
                            connection_id, item["listener_ip"]
                        )
                    )
                connections.append(
                    {
                        "id": connection_id,
                        "speaker_id": str(item["speaker_id"]),
                        "listener_ip": str(item["listener_ip"]),
                        "password_ref": str(item["password_ref"]),
                    }
                )
            policy_plane["sxp"] = {"connections": connections}

    control_planes = [item["id"] for item in devices if "control_plane" in item["roles"]]
    if not control_planes:
        raise AllocationError("At least one control-plane device is required")
    redundancy = policy.get("redundancy", {})
    if environment == "production":
        border_count = sum("border" in item["roles"] for item in devices)
        if border_count < int(redundancy.get("min_borders_production", 2)):
            raise AllocationError("Production guardrails require redundant borders")
        if len(control_planes) < int(redundancy.get("min_control_planes_production", 2)):
            raise AllocationError("Production guardrails require redundant control planes")
        if str(requirements["schema_version"]) == "1.2" and len(fusion_nodes) < int(
            redundancy.get("min_fusion_nodes_production", 2)
        ):
            raise AllocationError("Production guardrails require redundant fusion nodes")

    lisp_domain_id = None
    multihoming_groups: List[Dict[str, Any]] = []
    if str(requirements["schema_version"]) == "1.2" and mode == "lisp_pubsub":
        domain_range = ranges.get("lisp_domain_id")
        multihoming_range = ranges.get("lisp_multihoming_id")
        if not isinstance(domain_range, Mapping):
            raise AllocationError("Guardrail range lisp_domain_id is missing")
        if not isinstance(multihoming_range, Mapping):
            raise AllocationError("Guardrail range lisp_multihoming_id is missing")
        if fabric.get("lisp_domain_id") is None:
            lisp_domain_id = reserve_scalar(
                "lisp_domain_id",
                int(domain_range["min"]),
                int(domain_range["max"]),
            )
        else:
            lisp_domain_id = reserve_requested_scalar(
                "lisp_domain_id",
                int(fabric["lisp_domain_id"]),
                int(domain_range["min"]),
                int(domain_range["max"]),
            )

        sites_by_id = {
            str(item["id"]): item for item in requirements.get("fabric_sites", [])
        }
        borders_by_site: Dict[str, List[str]] = {}
        for device in devices:
            if "border" in device["roles"]:
                borders_by_site.setdefault(str(device["site"]), []).append(
                    str(device["id"])
                )
        for site_id, site in sorted(sites_by_id.items()):
            if site.get("lisp_multihoming_id") is not None and len(
                borders_by_site.get(site_id, [])
            ) < 2:
                raise AllocationError(
                    "Requested lisp_multihoming_id for site {} requires at least two borders".format(
                        site_id
                    )
                )
        for site_id, border_ids in sorted(borders_by_site.items()):
            if len(border_ids) < 2:
                continue
            site = sites_by_id.get(site_id, {})
            if site.get("lisp_multihoming_id") is None:
                multihoming_id = reserve_scalar(
                    "lisp_multihoming_id",
                    int(multihoming_range["min"]),
                    int(multihoming_range["max"]),
                )
            else:
                multihoming_id = reserve_requested_scalar(
                    "lisp_multihoming_id",
                    int(site["lisp_multihoming_id"]),
                    int(multihoming_range["min"]),
                    int(multihoming_range["max"]),
                )
            multihoming_groups.append(
                {
                    "site_id": site_id,
                    "multihoming_id": multihoming_id,
                    "border_device_ids": sorted(border_ids),
                }
            )

    intent = {
        "schema_version": str(requirements["schema_version"]),
        "metadata": copy.deepcopy(requirements["metadata"]),
        "fabric": {
            "id": str(fabric["id"]),
            "name": str(fabric["name"]),
            "underlay_protocol": "isis",
            "mtu": int(fabric["mtu"]),
            "isis_process": str(fabric.get("isis_process", "SDA-ISIS")),
            "isis_area": str(fabric.get("isis_area", "49.0001")),
        },
        "devices": devices,
        "links": links,
        "lisp": {
            "site_name": str(fabric.get("lisp_site_name", str(fabric["id"]).replace("-", "_"))),
            "auth_key_ref": str(fabric["lisp_auth_key_ref"]),
            "locator_set": str(fabric.get("locator_set", "rloc_fabric")),
            "map_servers": sorted(control_planes),
        },
        "virtual_networks": virtual_networks,
        "endpoint_pools": endpoint_pools,
    }
    intent.update(site_context)
    if str(requirements["schema_version"]) == "1.2":
        intent["fabric"]["control_plane_mode"] = mode
        intent["lisp"]["control_plane_mode"] = mode
        if mode == "lisp_pubsub":
            intent["lisp"]["publishers"] = sorted(control_planes)
            intent["lisp"]["subscribers"] = sorted(
                item["id"] for item in devices if "border" in item["roles"]
            )
            intent["lisp"]["domain_id"] = lisp_domain_id
            intent["lisp"]["multihoming_groups"] = multihoming_groups
        intent["fusion_nodes"] = fusion_nodes
        intent["shared_services"] = shared_services
        intent["multicast"] = multicast
        intent["policy_plane"] = policy_plane
        if multicast is not None:
            intent["fabric"]["multicast"] = {
                "enabled": bool(multicast["enabled"]),
                "transport": str(multicast["transport"]),
                "ssm_default": bool(multicast["ssm_virtual_networks"]),
            }
            if multicast["rp_device_ids"]:
                intent["fabric"]["multicast"]["rp_device_ids"] = list(
                    multicast["rp_device_ids"]
                )
            if multicast.get("rp_address"):
                intent["fabric"]["multicast"]["rp_address"] = str(
                    multicast["rp_address"]
                )
                intent["fabric"]["multicast"]["rp_loopback_id"] = 60000
    if bgp_enabled:
        if "border_handoff" not in pools:
            raise AllocationError("Guardrail pool border_handoff is missing")
        handoff_vlan = ranges.get("handoff_vlan_id")
        if not isinstance(handoff_vlan, Mapping):
            raise AllocationError("Guardrail range handoff_vlan_id is missing")
        vrfs = {item["vrf"] for item in virtual_networks}
        vn_to_vrf = {item["name"]: item["vrf"] for item in virtual_networks}
        border_ids = {item["id"] for item in devices if "border" in item["roles"]}
        peers = []
        raw_adjacencies = raw_handoff.get("adjacencies") or []
        if str(requirements["schema_version"]) == "1.2":
            if not raw_adjacencies:
                raise AllocationError("Schema 1.2 BGP handoff requires fusion adjacencies")
            fusion_by_id = {item["id"]: item for item in fusion_nodes}
            adjacency_pairs = set()
            fusion_vns_by_border: Dict[Tuple[str, str], set] = {}
            expanded_peers = []
            for adjacency in sorted(
                raw_adjacencies,
                key=lambda item: (
                    str(item.get("border_device_id", "")),
                    str(item.get("fusion_node_id", "")),
                ),
            ):
                border_id = str(adjacency.get("border_device_id", ""))
                fusion_id = str(adjacency.get("fusion_node_id", ""))
                if border_id not in border_ids:
                    raise AllocationError(
                        "Fusion adjacency must target an approved border"
                    )
                if fusion_id not in fusion_by_id:
                    raise AllocationError(
                        "Fusion adjacency references unknown fusion node {}".format(fusion_id)
                    )
                pair = (border_id, fusion_id)
                if pair in adjacency_pairs:
                    raise AllocationError(
                        "Duplicate border/fusion adjacency {} to {}".format(*pair)
                    )
                adjacency_pairs.add(pair)
                selected_vns = sorted(
                    str(item)
                    for item in adjacency.get("virtual_networks", sorted(vn_to_vrf))
                )
                unknown_vns = sorted(set(selected_vns) - set(vn_to_vrf))
                if unknown_vns:
                    raise AllocationError(
                        "Fusion adjacency references unknown virtual network {}".format(
                            unknown_vns[0]
                        )
                    )
                for vn_name in selected_vns:
                    fusion_vns_by_border.setdefault((border_id, vn_name), set()).add(
                        fusion_id
                    )
                    expanded_peers.append(
                        {
                            "device_id": border_id,
                            "fusion_node_id": fusion_id,
                            "vrf": str(vn_to_vrf[vn_name]),
                            "border_interface": str(adjacency["border_interface"]),
                            "fusion_interface": str(adjacency["fusion_interface"]),
                            "remote_as": int(fusion_by_id[fusion_id]["bgp_asn"]),
                        }
                    )
            fusion_policy = policy.get("fusion", {})
            if environment == "production" and bool(
                fusion_policy.get("require_full_mesh_production", True)
            ):
                expected_pairs = {
                    (border_id, fusion_id)
                    for border_id in border_ids
                    for fusion_id in fusion_ids
                }
                missing_pairs = sorted(expected_pairs - adjacency_pairs)
                if missing_pairs:
                    raise AllocationError(
                        "Production fusion full mesh is missing adjacency {} to {}".format(
                            *missing_pairs[0]
                        )
                    )
                minimum_fusions = int(
                    fusion_policy.get("min_fusion_nodes_per_border_vrf_production", 2)
                )
                if minimum_fusions < 1 or minimum_fusions > len(fusion_ids):
                    raise AllocationError(
                        "Fusion per-VRF redundancy guardrail must be between 1 and {}".format(
                            len(fusion_ids)
                        )
                    )
                for border_id in sorted(border_ids):
                    for vn_name in sorted(vn_to_vrf):
                        fusion_count = len(
                            fusion_vns_by_border.get((border_id, vn_name), set())
                        )
                        if fusion_count < minimum_fusions:
                            raise AllocationError(
                                "Production fusion redundancy requires {} nodes for border {} virtual network {}; found {}".format(
                                    minimum_fusions, border_id, vn_name, fusion_count
                                )
                            )
            raw_peers = expanded_peers
        else:
            remote_as = int(raw_handoff.get("remote_as", 0))
            if remote_as < 1 or remote_as > 4294967295:
                raise AllocationError("A valid border_handoff.remote_as is required")
            raw_peers = raw_handoff.get("peers") or [
                {"device_id": device_id, "vrf": vrf, "remote_as": remote_as}
                for device_id in sorted(border_ids)
                for vrf in sorted(vrfs)
            ]
        for peer in sorted(
            raw_peers,
            key=lambda item: (
                str(item.get("device_id", "")),
                str(item.get("fusion_node_id", "")),
                str(item.get("vrf", "")),
            ),
        ):
            device_id = str(peer.get("device_id", ""))
            vrf = str(peer.get("vrf", ""))
            if device_id not in border_ids:
                raise AllocationError("BGP handoff peer must target an approved border")
            if vrf not in vrfs:
                raise AllocationError("BGP handoff peer references unknown VRF {}".format(vrf))
            vlan = reserve_scalar(
                "vlan_id", int(handoff_vlan["min"]), int(handoff_vlan["max"])
            )
            prefix = reserve_prefix(
                "border_handoff", int(pools["border_handoff"]["prefix_len"])
            )
            addresses = list(prefix.hosts())
            rendered_peer = {
                "device_id": device_id,
                "vrf": vrf,
                "vlan_id": vlan,
                "interface": str(peer.get("interface") or "Vlan{}".format(vlan)),
                "prefix": str(prefix),
                "local_ip": str(addresses[0]),
                "neighbor_ip": str(addresses[1]),
                "remote_as": int(peer.get("remote_as")),
            }
            if peer.get("fusion_node_id"):
                rendered_peer.update(
                    {
                        "fusion_node_id": str(peer["fusion_node_id"]),
                        "border_interface": str(peer["border_interface"]),
                        "fusion_interface": str(peer["fusion_interface"]),
                    }
                )
            peers.append(rendered_peer)
        intent["border_handoff"] = {
            "enabled": True,
            "mode": "bgp",
            "local_as": local_as,
            "peers": peers,
        }
    else:
        intent["border_handoff"] = {"enabled": False, "mode": "isolated"}

    reservation_body = {
        "allocation_domain": domain,
        "fabric_id": str(fabric["id"]),
        "network": net_reservations,
        "scalar": scalar_reservations,
    }
    return {
        "intent": intent,
        "intent_hash": sha256_json(intent),
        "requirements_hash": sha256_json(requirements),
        "policy_hash": sha256_json(policy),
        "reservations": reservation_body,
        "reservation_hash": sha256_json(reservation_body),
    }
