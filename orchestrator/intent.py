"""Typed validation boundary for production fabric intent.

This module deliberately has no device-side effects. It validates a proposed
fabric document before planning, configuration rendering, or deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableSequence, Optional, Tuple, Union

import yaml
from jsonschema import Draft202012Validator, FormatChecker


ALLOWED_ENVIRONMENTS = {"lab", "staging", "production"}
ALLOWED_UNDERLAY_PROTOCOLS = {"isis"}
MAX_HIERARCHY_DEPTH = 16
ALLOWED_ROLES = {
    "border",
    "control_plane",
    "fabric_edge",
    "fusion",
    "underlay",
}
SENSITIVE_FIELD_NAMES = {
    "api_key",
    "auth_key",
    "password",
    "radius_key",
    "secret",
    "shared_secret",
    "token",
}

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "fabric-intent.schema.json"


def _schema_validator() -> Draft202012Validator:
    import json

    with SCHEMA_PATH.open("r", encoding="utf-8") as handle:
        schema = json.load(handle)
    return Draft202012Validator(schema, format_checker=FormatChecker())


SCHEMA_VALIDATOR = _schema_validator()


@dataclass(frozen=True)
class ValidationIssue:
    code: str
    path: str
    message: str
    severity: str = "error"

    def as_dict(self) -> Dict[str, str]:
        return {
            "code": self.code,
            "path": self.path,
            "message": self.message,
            "severity": self.severity,
        }


@dataclass
class ValidationResult:
    issues: List[ValidationIssue]

    @property
    def errors(self) -> List[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "error"]

    @property
    def warnings(self) -> List[ValidationIssue]:
        return [issue for issue in self.issues if issue.severity == "warning"]

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def as_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.is_valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [issue.as_dict() for issue in self.issues],
        }


def load_intent(path: Union[str, Path]) -> Dict[str, Any]:
    """Load a YAML or JSON-compatible intent document."""
    source = Path(path)
    with source.open("r", encoding="utf-8-sig") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        raise ValueError("Fabric intent root must be a mapping")
    return document


def _add(
    issues: MutableSequence[ValidationIssue],
    code: str,
    path: str,
    message: str,
    severity: str = "error",
) -> None:
    issues.append(ValidationIssue(code, path, message, severity))


def _mapping(
    value: Any,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _add(issues, "type.mapping", path, "Expected an object/mapping")
        return {}
    return value


def _list(
    value: Any,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> List[Any]:
    if not isinstance(value, list):
        _add(issues, "type.list", path, "Expected a list")
        return []
    return value


def _required_string(
    obj: Mapping[str, Any],
    key: str,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> Optional[str]:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        _add(issues, "required.string", f"{path}.{key}", "A non-empty string is required")
        return None
    if "\r" in value or "\n" in value:
        _add(issues, "security.control_character", f"{path}.{key}", "Line breaks are forbidden")
        return None
    return value.strip()


def _integer(
    obj: Mapping[str, Any],
    key: str,
    path: str,
    issues: MutableSequence[ValidationIssue],
    minimum: int,
    maximum: int,
) -> Optional[int]:
    value = obj.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        _add(issues, "required.integer", f"{path}.{key}", "An integer is required")
        return None
    if not minimum <= value <= maximum:
        _add(
            issues,
            "range.integer",
            f"{path}.{key}",
            f"Value must be between {minimum} and {maximum}",
        )
        return None
    return value


def _ipv4_address(
    value: Any,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> Optional[IPv4Address]:
    try:
        parsed = ip_address(value)
    except (TypeError, ValueError):
        _add(issues, "format.ipv4", path, "A valid IPv4 address is required")
        return None
    if not isinstance(parsed, IPv4Address):
        _add(issues, "format.ipv4", path, "IPv6 is not supported in schema version 1.0")
        return None
    return parsed


def _ipv4_network(
    value: Any,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> Optional[IPv4Network]:
    try:
        parsed = ip_network(value, strict=True)
    except (TypeError, ValueError):
        _add(issues, "format.prefix", path, "A canonical IPv4 prefix is required")
        return None
    if not isinstance(parsed, IPv4Network):
        _add(issues, "format.prefix", path, "IPv6 is not supported in schema version 1.0")
        return None
    return parsed


def _walk_sensitive_fields(
    value: Any,
    path: str,
    issues: MutableSequence[ValidationIssue],
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            child_path = f"{path}.{key}"
            normalized = str(key).lower().replace("-", "_")
            if normalized in SENSITIVE_FIELD_NAMES and not normalized.endswith("_ref"):
                _add(
                    issues,
                    "security.inline_secret",
                    child_path,
                    "Inline secrets are forbidden; use a *_ref secret reference",
                )
            _walk_sensitive_fields(child, child_path, issues)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_sensitive_fields(child, f"{path}[{index}]", issues)


def _check_duplicate(
    seen: Dict[Any, str],
    value: Any,
    path: str,
    label: str,
    issues: MutableSequence[ValidationIssue],
) -> None:
    if value is None:
        return
    if value in seen:
        _add(
            issues,
            "unique.duplicate",
            path,
            f"Duplicate {label}; first declared at {seen[value]}",
        )
    else:
        seen[value] = path


def _check_network_overlaps(
    networks: Iterable[Tuple[str, IPv4Network, str]],
    issues: MutableSequence[ValidationIssue],
) -> None:
    items = list(networks)
    for index, (path_a, network_a, kind_a) in enumerate(items):
        for path_b, network_b, kind_b in items[index + 1 :]:
            if network_a.overlaps(network_b):
                _add(
                    issues,
                    "address.overlap",
                    path_b,
                    f"{kind_b} {network_b} overlaps {kind_a} {network_a} at {path_a}",
                )


def validate_intent(document: Mapping[str, Any]) -> ValidationResult:
    """Validate shape, references, addressing, identifiers, roles, and HA rules."""
    issues: List[ValidationIssue] = []
    root = _mapping(document, "$", issues)
    for error in sorted(
        SCHEMA_VALIDATOR.iter_errors(root),
        key=lambda item: tuple(str(part) for part in item.absolute_path),
    ):
        path = "$"
        for part in error.absolute_path:
            path += "[{}]".format(part) if isinstance(part, int) else ".{}".format(part)
        _add(
            issues,
            "schema.{}".format(error.validator),
            path,
            error.message,
        )
    _walk_sensitive_fields(root, "$", issues)

    schema_version = root.get("schema_version")
    if schema_version not in {"1.0", "1.1"}:
        _add(
            issues,
            "schema.unsupported",
            "$.schema_version",
            "Supported schema_version values are '1.0' and '1.1'",
        )

    metadata = _mapping(root.get("metadata"), "$.metadata", issues)
    _required_string(metadata, "name", "$.metadata", issues)
    environment = _required_string(metadata, "environment", "$.metadata", issues)
    _required_string(metadata, "organization", "$.metadata", issues)
    _required_string(metadata, "region", "$.metadata", issues)
    if environment and environment not in ALLOWED_ENVIRONMENTS:
        _add(
            issues,
            "enum.environment",
            "$.metadata.environment",
            f"Expected one of {sorted(ALLOWED_ENVIRONMENTS)}",
        )

    hierarchy_node_ids: Dict[str, str] = {}
    hierarchy_parents: Dict[str, str] = {}
    hierarchy_parent_paths: Dict[str, str] = {}
    hierarchy_types: Dict[str, str] = {}
    fabric_site_ids: Dict[str, str] = {}
    fabric_site_nodes: Dict[str, str] = {}
    fabric_site_node_ids: Dict[str, str] = {}
    if schema_version == "1.1":
        deployment_model = _required_string(root, "deployment_model", "$", issues)
        if deployment_model and deployment_model not in {"single_site", "distributed_campus"}:
            _add(
                issues,
                "enum.deployment_model",
                "$.deployment_model",
                "deployment_model must be single_site or distributed_campus",
            )
        hierarchy = _list(root.get("site_hierarchy"), "$.site_hierarchy", issues)
        global_count = 0
        for index, raw_node in enumerate(hierarchy):
            path = f"$.site_hierarchy[{index}]"
            node = _mapping(raw_node, path, issues)
            node_id = _required_string(node, "id", path, issues)
            _required_string(node, "name", path, issues)
            node_type = _required_string(node, "type", path, issues)
            if node_id:
                _check_duplicate(hierarchy_node_ids, node_id, f"{path}.id", "hierarchy node id", issues)
                if node_type:
                    hierarchy_types[node_id] = node_type
            if node_type == "global":
                global_count += 1
                if "parent_id" in node:
                    _add(issues, "hierarchy.global_parent", f"{path}.parent_id", "Global node cannot have a parent")
            else:
                parent_id = _required_string(node, "parent_id", path, issues)
                if node_id and parent_id:
                    hierarchy_parents[node_id] = parent_id
                    hierarchy_parent_paths[node_id] = f"{path}.parent_id"
        if global_count != 1:
            _add(issues, "hierarchy.global_count", "$.site_hierarchy", "Exactly one global node is required")
        allowed_hierarchy_children = {
            "global": {"area", "building"},
            "area": {"area", "building"},
            "building": {"floor"},
            "floor": set(),
        }
        for node_id, parent_id in hierarchy_parents.items():
            if parent_id not in hierarchy_node_ids:
                _add(
                    issues,
                    "reference.hierarchy_parent",
                    hierarchy_parent_paths.get(node_id, "$.site_hierarchy"),
                    f"Unknown hierarchy parent {parent_id!r}",
                )
            elif hierarchy_types.get(node_id) not in allowed_hierarchy_children.get(
                hierarchy_types.get(parent_id, ""), set()
            ):
                _add(
                    issues,
                    "hierarchy.parent_type",
                    hierarchy_parent_paths.get(node_id, "$.site_hierarchy"),
                    "Invalid hierarchy parent/child type relationship",
                )
        depths: Dict[str, int] = {
            node_id: 0
            for node_id, node_type in hierarchy_types.items()
            if node_type == "global"
        }
        cycle_reported = False
        for start in sorted(hierarchy_node_ids):
            trail: List[str] = []
            visiting = set()
            cursor = start
            invalid_path = False
            while cursor not in depths:
                if cursor in visiting:
                    if not cycle_reported:
                        _add(
                            issues,
                            "hierarchy.cycle",
                            hierarchy_parent_paths.get(cursor, "$.site_hierarchy"),
                            "Site hierarchy contains a parent cycle",
                        )
                        cycle_reported = True
                    invalid_path = True
                    break
                if cursor not in hierarchy_node_ids:
                    invalid_path = True
                    break
                visiting.add(cursor)
                trail.append(cursor)
                if cursor not in hierarchy_parents:
                    depths[cursor] = 0
                    break
                cursor = hierarchy_parents[cursor]
            if invalid_path:
                continue
            depth = depths[cursor]
            for node_id in reversed(trail):
                if node_id in depths:
                    depth = depths[node_id]
                    continue
                depth += 1
                depths[node_id] = depth
                if depth > MAX_HIERARCHY_DEPTH:
                    _add(
                        issues,
                        "hierarchy.too_deep",
                        hierarchy_parent_paths.get(node_id, "$.site_hierarchy"),
                        f"Site hierarchy exceeds maximum depth {MAX_HIERARCHY_DEPTH}",
                    )

        fabric_sites = _list(root.get("fabric_sites"), "$.fabric_sites", issues)
        for index, raw_site in enumerate(fabric_sites):
            path = f"$.fabric_sites[{index}]"
            site = _mapping(raw_site, path, issues)
            site_id = _required_string(site, "id", path, issues)
            _required_string(site, "name", path, issues)
            node_id = _required_string(site, "hierarchy_node_id", path, issues)
            _integer(site, "endpoint_count", path, issues, 1, 1_000_000)
            _integer(site, "ap_count", path, issues, 0, 100_000)
            _required_string(site, "profile", path, issues)
            if site_id:
                _check_duplicate(fabric_site_ids, site_id, f"{path}.id", "fabric site id", issues)
                if node_id:
                    fabric_site_nodes[site_id] = node_id
            if node_id and node_id not in hierarchy_node_ids:
                _add(
                    issues,
                    "reference.hierarchy_node",
                    f"{path}.hierarchy_node_id",
                    f"Unknown hierarchy node {node_id!r}",
                )
            elif node_id:
                _check_duplicate(
                    fabric_site_node_ids,
                    node_id,
                    f"{path}.hierarchy_node_id",
                    "fabric-site hierarchy node",
                    issues,
                )
                if hierarchy_types.get(node_id) == "global":
                    _add(
                        issues,
                        "site.global_node",
                        f"{path}.hierarchy_node_id",
                        "A fabric site cannot be attached to the global node",
                    )
        if deployment_model == "single_site" and len(fabric_sites) != 1:
            _add(issues, "site.count", "$.fabric_sites", "single_site requires exactly one fabric site")
        if deployment_model == "distributed_campus" and len(fabric_sites) < 2:
            _add(issues, "site.count", "$.fabric_sites", "distributed_campus requires at least two fabric sites")

    fabric = _mapping(root.get("fabric"), "$.fabric", issues)
    _required_string(fabric, "id", "$.fabric", issues)
    _required_string(fabric, "name", "$.fabric", issues)
    underlay_protocol = _required_string(fabric, "underlay_protocol", "$.fabric", issues)
    if underlay_protocol and underlay_protocol not in ALLOWED_UNDERLAY_PROTOCOLS:
        _add(
            issues,
            "enum.underlay_protocol",
            "$.fabric.underlay_protocol",
            f"Schema 1.0 supports {sorted(ALLOWED_UNDERLAY_PROTOCOLS)}",
        )
    mtu = _integer(fabric, "mtu", "$.fabric", issues, 1550, 9216)
    if mtu is not None and mtu < 9100:
        _add(
            issues,
            "fabric.mtu.recommended",
            "$.fabric.mtu",
            "An MTU of at least 9100 is recommended for the validated VXLAN design",
            "warning",
        )
    multicast_raw = fabric.get("multicast")
    if multicast_raw is not None:
        multicast = _mapping(multicast_raw, "$.fabric.multicast", issues)
        multicast_enabled = multicast.get("enabled")
        if not isinstance(multicast_enabled, bool):
            _add(
                issues,
                "type.boolean",
                "$.fabric.multicast.enabled",
                "enabled must be boolean",
            )
        if multicast_enabled:
            _ipv4_address(
                multicast.get("rp_address"),
                "$.fabric.multicast.rp_address",
                issues,
            )
            _integer(
                multicast,
                "rp_loopback_id",
                "$.fabric.multicast",
                issues,
                1,
                2_147_483_647,
            )
        if "ssm_default" in multicast and not isinstance(multicast.get("ssm_default"), bool):
            _add(
                issues,
                "type.boolean",
                "$.fabric.multicast.ssm_default",
                "ssm_default must be boolean",
            )

    devices = _list(root.get("devices"), "$.devices", issues)
    device_ids: Dict[str, str] = {}
    hostnames: Dict[str, str] = {}
    management_ips: Dict[IPv4Address, str] = {}
    dashboard_management_ips: Dict[IPv4Address, str] = {}
    loopbacks: Dict[IPv4Address, str] = {}
    role_counts = {role: 0 for role in ALLOWED_ROLES}
    device_roles: Dict[str, set] = {}
    address_networks: List[Tuple[str, IPv4Network, str]] = []

    for index, raw_device in enumerate(devices):
        path = f"$.devices[{index}]"
        device = _mapping(raw_device, path, issues)
        device_id = _required_string(device, "id", path, issues)
        hostname = _required_string(device, "hostname", path, issues)
        site = _required_string(device, "site", path, issues)
        if schema_version == "1.1" and site and site not in fabric_site_ids:
            _add(
                issues,
                "reference.fabric_site",
                f"{path}.site",
                f"Unknown fabric site {site!r}",
            )
        _required_string(device, "platform", path, issues)
        _required_string(device, "software_version", path, issues)
        if device_id:
            _check_duplicate(device_ids, device_id, f"{path}.id", "device id", issues)
        if hostname:
            _check_duplicate(hostnames, hostname.lower(), f"{path}.hostname", "hostname", issues)

        management_ip = _ipv4_address(device.get("management_ip"), f"{path}.management_ip", issues)
        dashboard_management_ip = None
        if "dashboard_management_ip" in device:
            dashboard_management_ip = _ipv4_address(
                device.get("dashboard_management_ip"),
                f"{path}.dashboard_management_ip",
                issues,
            )
        loopback = _ipv4_address(device.get("loopback0_ip"), f"{path}.loopback0_ip", issues)
        _check_duplicate(management_ips, management_ip, f"{path}.management_ip", "management IP", issues)
        _check_duplicate(
            dashboard_management_ips,
            dashboard_management_ip,
            f"{path}.dashboard_management_ip",
            "Dashboard management IP",
            issues,
        )
        _check_duplicate(loopbacks, loopback, f"{path}.loopback0_ip", "loopback IP", issues)
        if loopback:
            address_networks.append((f"{path}.loopback0_ip", ip_network(f"{loopback}/32"), "loopback"))

        roles = _list(device.get("roles"), f"{path}.roles", issues)
        if device_id:
            device_roles[device_id] = set(roles)
        if not roles:
            _add(issues, "device.roles.empty", f"{path}.roles", "At least one role is required")
        for role in roles:
            if role not in ALLOWED_ROLES:
                _add(
                    issues,
                    "enum.device_role",
                    f"{path}.roles",
                    f"Unsupported role {role!r}; expected one of {sorted(ALLOWED_ROLES)}",
                )
            else:
                role_counts[role] += 1

        credential_ref = device.get("credential_ref")
        if not isinstance(credential_ref, str) or not credential_ref.startswith("secret://"):
            _add(
                issues,
                "security.credential_ref",
                f"{path}.credential_ref",
                "credential_ref must use the secret:// reference scheme",
            )

    if role_counts["fabric_edge"] == 0:
        _add(issues, "roles.fabric_edge.required", "$.devices", "At least one fabric_edge is required")
    if role_counts["control_plane"] == 0:
        _add(issues, "roles.control_plane.required", "$.devices", "At least one control_plane is required")
    if role_counts["border"] == 0:
        _add(issues, "roles.border.required", "$.devices", "At least one border is required")

    if environment == "production":
        if role_counts["control_plane"] < 2:
            _add(
                issues,
                "ha.control_plane",
                "$.devices",
                "Production requires at least two control_plane nodes",
            )
        if role_counts["border"] < 2:
            _add(issues, "ha.border", "$.devices", "Production requires at least two border nodes")
    else:
        if role_counts["control_plane"] == 1:
            _add(
                issues,
                "ha.control_plane.single",
                "$.devices",
                "Single control-plane node is acceptable only for lab/staging",
                "warning",
            )
        if role_counts["border"] == 1:
            _add(
                issues,
                "ha.border.single",
                "$.devices",
                "Single border node is acceptable only for lab/staging",
                "warning",
            )

    links = _list(root.get("links"), "$.links", issues)
    link_ids: Dict[str, str] = {}
    for index, raw_link in enumerate(links):
        path = f"$.links[{index}]"
        link = _mapping(raw_link, path, issues)
        link_id = _required_string(link, "id", path, issues)
        if link_id:
            _check_duplicate(link_ids, link_id, f"{path}.id", "link id", issues)
        subnet = _ipv4_network(link.get("subnet"), f"{path}.subnet", issues)
        if subnet:
            address_networks.append((f"{path}.subnet", subnet, "underlay link"))
            if subnet.prefixlen not in (30, 31):
                _add(
                    issues,
                    "link.prefix_length",
                    f"{path}.subnet",
                    "Point-to-point links must use /31 or /30",
                )
        if "pim_sparse_mode" in link and not isinstance(link.get("pim_sparse_mode"), bool):
            _add(
                issues,
                "type.boolean",
                f"{path}.pim_sparse_mode",
                "pim_sparse_mode must be boolean",
            )
        bfd_raw = link.get("bfd")
        if bfd_raw is not None:
            bfd = _mapping(bfd_raw, f"{path}.bfd", issues)
            if not isinstance(bfd.get("enabled"), bool):
                _add(
                    issues,
                    "type.boolean",
                    f"{path}.bfd.enabled",
                    "enabled must be boolean",
                )
            if bfd.get("enabled"):
                _integer(bfd, "interval_ms", f"{path}.bfd", issues, 50, 1000)
                _integer(bfd, "min_rx_ms", f"{path}.bfd", issues, 50, 1000)
                _integer(bfd, "multiplier", f"{path}.bfd", issues, 3, 50)
        endpoints = _list(link.get("endpoints"), f"{path}.endpoints", issues)
        if len(endpoints) != 2:
            _add(issues, "link.endpoints.count", f"{path}.endpoints", "Exactly two endpoints are required")
        endpoint_devices: List[str] = []
        endpoint_ips: Dict[IPv4Address, str] = {}
        for endpoint_index, raw_endpoint in enumerate(endpoints):
            endpoint_path = f"{path}.endpoints[{endpoint_index}]"
            endpoint = _mapping(raw_endpoint, endpoint_path, issues)
            endpoint_device = _required_string(endpoint, "device_id", endpoint_path, issues)
            _required_string(endpoint, "interface", endpoint_path, issues)
            if endpoint_device:
                endpoint_devices.append(endpoint_device)
                if endpoint_device not in device_ids:
                    _add(
                        issues,
                        "reference.device",
                        f"{endpoint_path}.device_id",
                        f"Unknown device_id {endpoint_device!r}",
                    )
            endpoint_ip = _ipv4_address(endpoint.get("ip"), f"{endpoint_path}.ip", issues)
            _check_duplicate(endpoint_ips, endpoint_ip, f"{endpoint_path}.ip", "link endpoint IP", issues)
            if subnet and endpoint_ip and endpoint_ip not in subnet:
                _add(
                    issues,
                    "link.endpoint.outside_subnet",
                    f"{endpoint_path}.ip",
                    f"Address {endpoint_ip} is not in {subnet}",
                )
        if len(endpoint_devices) == 2 and endpoint_devices[0] == endpoint_devices[1]:
            _add(issues, "link.self", f"{path}.endpoints", "A fabric link cannot connect a device to itself")

    virtual_networks = _list(root.get("virtual_networks"), "$.virtual_networks", issues)
    vn_names: Dict[str, str] = {}
    vrf_names: Dict[str, str] = {}
    l3_instances: Dict[int, str] = {}
    route_distinguishers: Dict[str, str] = {}
    for index, raw_vn in enumerate(virtual_networks):
        path = f"$.virtual_networks[{index}]"
        vn = _mapping(raw_vn, path, issues)
        name = _required_string(vn, "name", path, issues)
        vrf = _required_string(vn, "vrf", path, issues)
        l3_instance = _integer(vn, "l3_instance_id", path, issues, 1, 16_777_215)
        route_distinguisher = _required_string(vn, "rd", path, issues)
        route_targets = _list(vn.get("route_targets"), f"{path}.route_targets", issues)
        if not route_targets:
            _add(issues, "vn.route_targets.empty", f"{path}.route_targets", "At least one route target is required")
        if name:
            _check_duplicate(vn_names, name, f"{path}.name", "virtual-network name", issues)
        if vrf:
            _check_duplicate(vrf_names, vrf, f"{path}.vrf", "VRF name", issues)
        if l3_instance is not None:
            _check_duplicate(
                l3_instances,
                l3_instance,
                f"{path}.l3_instance_id",
                "L3 instance id",
                issues,
            )
        if route_distinguisher:
            _check_duplicate(
                route_distinguishers,
                route_distinguisher,
                f"{path}.rd",
                "route distinguisher",
                issues,
            )

    if schema_version == "1.1":
        zone_ids: Dict[str, str] = {}
        zones = _list(root.get("fabric_zones", []), "$.fabric_zones", issues)

        def hierarchy_descends_from(node_id: str, ancestor_id: str) -> bool:
            cursor = node_id
            visited = set()
            while cursor not in visited:
                if cursor == ancestor_id:
                    return True
                visited.add(cursor)
                if cursor not in hierarchy_parents:
                    return False
                cursor = hierarchy_parents[cursor]
            return False

        for index, raw_zone in enumerate(zones):
            path = f"$.fabric_zones[{index}]"
            zone = _mapping(raw_zone, path, issues)
            zone_id = _required_string(zone, "id", path, issues)
            site_id = _required_string(zone, "fabric_site_id", path, issues)
            node_id = _required_string(zone, "hierarchy_node_id", path, issues)
            if zone_id:
                _check_duplicate(zone_ids, zone_id, f"{path}.id", "fabric zone id", issues)
            if site_id and site_id not in fabric_site_ids:
                _add(
                    issues,
                    "reference.fabric_site",
                    f"{path}.fabric_site_id",
                    f"Unknown fabric site {site_id!r}",
                )
            if node_id and node_id not in hierarchy_node_ids:
                _add(
                    issues,
                    "reference.hierarchy_node",
                    f"{path}.hierarchy_node_id",
                    f"Unknown hierarchy node {node_id!r}",
                )
            if (
                site_id in fabric_site_nodes
                and node_id in hierarchy_node_ids
                and not hierarchy_descends_from(node_id, fabric_site_nodes[site_id])
            ):
                _add(
                    issues,
                    "zone.outside_site",
                    f"{path}.hierarchy_node_id",
                    "Fabric zone hierarchy node is outside its fabric site",
                )
            zone_vns = _list(zone.get("virtual_networks"), f"{path}.virtual_networks", issues)
            for vn_index, vn_name in enumerate(zone_vns):
                if vn_name not in vn_names:
                    _add(
                        issues,
                        "reference.virtual_network",
                        f"{path}.virtual_networks[{vn_index}]",
                        f"Unknown virtual network {vn_name!r}",
                    )

    endpoint_pools = _list(root.get("endpoint_pools"), "$.endpoint_pools", issues)
    pool_ids: Dict[str, str] = {}
    l2_instances: Dict[int, str] = {}
    site_vlans: Dict[Tuple[str, int], str] = {}
    for index, raw_pool in enumerate(endpoint_pools):
        path = f"$.endpoint_pools[{index}]"
        pool = _mapping(raw_pool, path, issues)
        pool_id = _required_string(pool, "id", path, issues)
        site = _required_string(pool, "site", path, issues)
        vn_name = _required_string(pool, "virtual_network", path, issues)
        if schema_version == "1.1" and site and site not in fabric_site_ids:
            _add(
                issues,
                "reference.fabric_site",
                f"{path}.site",
                f"Unknown fabric site {site!r}",
            )
        if pool_id:
            _check_duplicate(pool_ids, pool_id, f"{path}.id", "endpoint-pool id", issues)
        if vn_name and vn_name not in vn_names:
            _add(
                issues,
                "reference.virtual_network",
                f"{path}.virtual_network",
                f"Unknown virtual network {vn_name!r}",
            )
        vlan = _integer(pool, "vlan_id", path, issues, 1, 4094)
        if vlan in {1002, 1003, 1004, 1005}:
            _add(issues, "vlan.reserved", f"{path}.vlan_id", "Legacy reserved VLAN ID is not allowed")
        if site and vlan is not None:
            _check_duplicate(
                site_vlans,
                (site, vlan),
                f"{path}.vlan_id",
                f"VLAN {vlan} in site {site}",
                issues,
            )
        l2_instance = _integer(pool, "l2_instance_id", path, issues, 1, 16_777_215)
        if l2_instance is not None:
            _check_duplicate(
                l2_instances,
                l2_instance,
                f"{path}.l2_instance_id",
                "L2 instance id",
                issues,
            )
        prefix = _ipv4_network(pool.get("prefix"), f"{path}.prefix", issues)
        gateway = _ipv4_address(pool.get("gateway"), f"{path}.gateway", issues)
        if prefix:
            address_networks.append((f"{path}.prefix", prefix, "endpoint pool"))
        if prefix and gateway and gateway not in prefix:
            _add(
                issues,
                "pool.gateway.outside_prefix",
                f"{path}.gateway",
                f"Gateway {gateway} is not in {prefix}",
            )
        helpers = _list(pool.get("dhcp_helpers"), f"{path}.dhcp_helpers", issues)
        if not helpers:
            _add(
                issues,
                "pool.dhcp_helpers.empty",
                f"{path}.dhcp_helpers",
                "At least one external DHCP helper is required",
            )
        for helper_index, helper in enumerate(helpers):
            _ipv4_address(helper, f"{path}.dhcp_helpers[{helper_index}]", issues)

    handoff_raw = root.get("border_handoff")
    handoff = _mapping(handoff_raw, "$.border_handoff", issues) if handoff_raw is not None else {}
    handoff_enabled = handoff.get("enabled", False)
    handoff_mode = handoff.get("mode")
    if not isinstance(handoff_enabled, bool):
        _add(issues, "type.boolean", "$.border_handoff.enabled", "enabled must be boolean")
        handoff_enabled = False
    if handoff_mode is not None and handoff_mode not in {"bgp", "isolated"}:
        _add(
            issues,
            "enum.border_handoff_mode",
            "$.border_handoff.mode",
            "mode must be 'bgp' or 'isolated'",
        )
    if handoff_mode == "isolated" and handoff_enabled:
        _add(
            issues,
            "bgp.handoff.mode_conflict",
            "$.border_handoff",
            "Isolated mode requires enabled=false",
        )
    if handoff_mode == "bgp" and not handoff_enabled:
        _add(
            issues,
            "bgp.handoff.mode_conflict",
            "$.border_handoff",
            "BGP mode requires enabled=true",
        )
    if handoff_mode == "isolated":
        _add(
            issues,
            "bgp.handoff.isolated",
            "$.border_handoff",
            "Fabric is intentionally isolated and has no external Layer-3 handoff",
            "warning",
        )
    if environment == "production" and (not handoff_enabled or handoff_mode == "isolated"):
        _add(
            issues,
            "bgp.handoff.required",
            "$.border_handoff",
            "Production requires an enabled BGP/fusion border handoff",
        )
    if handoff_enabled:
        _integer(handoff, "local_as", "$.border_handoff", issues, 1, 4_294_967_295)
        peers = _list(handoff.get("peers"), "$.border_handoff.peers", issues)
        if not peers:
            _add(issues, "bgp.peers.empty", "$.border_handoff.peers", "At least one BGP peer is required")
        peer_keys: Dict[Tuple[str, str, str], str] = {}
        device_vlans: Dict[Tuple[str, int], str] = {}
        border_devices_with_peers = set()
        for index, raw_peer in enumerate(peers):
            path = f"$.border_handoff.peers[{index}]"
            peer = _mapping(raw_peer, path, issues)
            device_id = _required_string(peer, "device_id", path, issues)
            vrf = _required_string(peer, "vrf", path, issues)
            _required_string(peer, "interface", path, issues)
            vlan = _integer(peer, "vlan_id", path, issues, 1, 4094)
            _integer(peer, "remote_as", path, issues, 1, 4_294_967_295)
            prefix = _ipv4_network(peer.get("prefix"), f"{path}.prefix", issues)
            local_ip = _ipv4_address(peer.get("local_ip"), f"{path}.local_ip", issues)
            neighbor_ip = _ipv4_address(peer.get("neighbor_ip"), f"{path}.neighbor_ip", issues)
            if device_id:
                if device_id not in device_ids:
                    _add(issues, "reference.device", f"{path}.device_id", f"Unknown device_id {device_id!r}")
                elif "border" not in device_roles.get(device_id, set()):
                    _add(issues, "bgp.peer.not_border", f"{path}.device_id", "BGP handoff peer must target a border device")
                else:
                    border_devices_with_peers.add(device_id)
            if vrf and vrf not in vrf_names:
                _add(issues, "reference.vrf", f"{path}.vrf", f"Unknown VRF {vrf!r}")
            if prefix:
                address_networks.append((f"{path}.prefix", prefix, "BGP handoff"))
                if prefix.prefixlen not in (30, 31):
                    _add(issues, "bgp.prefix_length", f"{path}.prefix", "BGP handoffs must use /31 or /30")
            if prefix and local_ip and local_ip not in prefix:
                _add(issues, "bgp.local_ip.outside_prefix", f"{path}.local_ip", f"Address {local_ip} is not in {prefix}")
            if prefix and neighbor_ip and neighbor_ip not in prefix:
                _add(issues, "bgp.neighbor_ip.outside_prefix", f"{path}.neighbor_ip", f"Address {neighbor_ip} is not in {prefix}")
            if (
                prefix
                and prefix.prefixlen <= 30
                and local_ip in {prefix.network_address, prefix.broadcast_address}
            ):
                _add(
                    issues,
                    "bgp.local_ip.not_usable",
                    f"{path}.local_ip",
                    f"Address {local_ip} is not a usable host in {prefix}",
                )
            if (
                prefix
                and prefix.prefixlen <= 30
                and neighbor_ip in {prefix.network_address, prefix.broadcast_address}
            ):
                _add(
                    issues,
                    "bgp.neighbor_ip.not_usable",
                    f"{path}.neighbor_ip",
                    f"Address {neighbor_ip} is not a usable host in {prefix}",
                )
            if local_ip and neighbor_ip and local_ip == neighbor_ip:
                _add(issues, "bgp.peer.same_address", path, "Local and neighbor addresses must differ")
            if device_id and vrf and neighbor_ip:
                _check_duplicate(peer_keys, (device_id, vrf, str(neighbor_ip)), path, "BGP peer", issues)
            if device_id and vlan is not None:
                _check_duplicate(device_vlans, (device_id, vlan), f"{path}.vlan_id", "handoff VLAN on device", issues)
        for border_id, roles in device_roles.items():
            if "border" in roles and border_id not in border_devices_with_peers:
                _add(
                    issues,
                    "bgp.border_without_peer",
                    "$.border_handoff.peers",
                    f"Border device {border_id!r} has no BGP handoff peer",
                )

    _check_network_overlaps(address_networks, issues)

    lisp = _mapping(root.get("lisp"), "$.lisp", issues)
    _required_string(lisp, "site_name", "$.lisp", issues)
    auth_key_ref = lisp.get("auth_key_ref")
    if not isinstance(auth_key_ref, str) or not auth_key_ref.startswith("secret://"):
        _add(
            issues,
            "security.auth_key_ref",
            "$.lisp.auth_key_ref",
            "auth_key_ref must use the secret:// reference scheme",
        )
    map_servers = _list(lisp.get("map_servers"), "$.lisp.map_servers", issues)
    if not map_servers:
        _add(issues, "lisp.map_servers.empty", "$.lisp.map_servers", "At least one map server is required")
    for index, map_server in enumerate(map_servers):
        path = f"$.lisp.map_servers[{index}]"
        if map_server not in device_ids:
            _add(
                issues,
                "reference.map_server",
                path,
                f"Unknown map-server device_id {map_server!r}",
            )

    if not endpoint_pools:
        _add(
            issues,
            "endpoint_pools.empty",
            "$.endpoint_pools",
            "A deployable fabric intent requires at least one endpoint pool",
        )

    return ValidationResult(issues)
