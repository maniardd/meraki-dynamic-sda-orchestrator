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
    if schema_version != "1.1":
        raise AllocationError("CVD site context requires requirements schema_version 1.1")

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

    control_planes = [item["id"] for item in devices if "control_plane" in item["roles"]]
    if not control_planes:
        raise AllocationError("At least one control-plane device is required")
    environment = str(requirements["metadata"]["environment"])
    redundancy = policy.get("redundancy", {})
    if environment == "production":
        border_count = sum("border" in item["roles"] for item in devices)
        if border_count < int(redundancy.get("min_borders_production", 2)):
            raise AllocationError("Production guardrails require redundant borders")
        if len(control_planes) < int(redundancy.get("min_control_planes_production", 2)):
            raise AllocationError("Production guardrails require redundant control planes")

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
    if bgp_enabled:
        if "border_handoff" not in pools:
            raise AllocationError("Guardrail pool border_handoff is missing")
        handoff_vlan = ranges.get("handoff_vlan_id")
        if not isinstance(handoff_vlan, Mapping):
            raise AllocationError("Guardrail range handoff_vlan_id is missing")
        remote_as = int(raw_handoff.get("remote_as", 0))
        if remote_as < 1 or remote_as > 4294967295:
            raise AllocationError("A valid border_handoff.remote_as is required")
        vrfs = {item["vrf"] for item in virtual_networks}
        border_ids = {item["id"] for item in devices if "border" in item["roles"]}
        peers = []
        raw_peers = raw_handoff.get("peers") or [
            {"device_id": device_id, "vrf": vrf}
            for device_id in sorted(border_ids)
            for vrf in sorted(vrfs)
        ]
        for peer in sorted(
            raw_peers,
            key=lambda item: (str(item.get("device_id", "")), str(item.get("vrf", ""))),
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
            # hosts() returns both addresses for /31 and excludes the network
            # and broadcast addresses for /30, so either supported handoff
            # size produces IOS XE-usable peer addresses.
            addresses = list(prefix.hosts())
            peers.append(
                {
                    "device_id": device_id,
                    "vrf": vrf,
                    "vlan_id": vlan,
                    "interface": str(peer.get("interface") or "Vlan{}".format(vlan)),
                    "prefix": str(prefix),
                    "local_ip": str(addresses[0]),
                    "neighbor_ip": str(addresses[1]),
                    "remote_as": remote_as,
                }
            )
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
