"""Fail-closed Cisco ISE ERS transaction boundary.

The planner and renderer emit only a secret reference and a declarative
manifest.  This module is imported by the isolated worker process, resolves
credentials at runtime, proves ownership before mutation, verifies every
write, and retains an in-memory journal for verified reverse rollback.
"""

from __future__ import annotations

import copy
import re
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence
from urllib.parse import quote, urlparse

import requests

from .store import sha256_json


class IseErsError(RuntimeError):
    pass


class IseManifestError(IseErsError):
    pass


class IsePreflightError(IseErsError):
    pass


class IseCollisionError(IsePreflightError):
    pass


class IseVerificationError(IseErsError):
    pass


class IseRollbackError(IseErsError):
    pass


_RESOURCE_SPECS = {
    "sgt": {
        "path": "sgt",
        "root": "Sgt",
        "strategy": "upsert_owned_by_name",
        "mutable": (
            "id",
            "name",
            "description",
            "value",
            "propogateToApic",
            "defaultSGACLs",
        ),
        "compare": ("name", "description", "value", "propogateToApic"),
    },
    "sgacl": {
        "path": "sgacl",
        "root": "Sgacl",
        "strategy": "upsert_owned_by_name",
        "mutable": (
            "id",
            "name",
            "description",
            "aclcontent",
            "ipVersion",
            "modelledContent",
        ),
        "compare": ("name", "description", "aclcontent", "ipVersion"),
    },
    "egressmatrixcell": {
        "path": "egressmatrixcell",
        "root": "EgressMatrixCell",
        "strategy": "upsert_owned_by_sgt_pair",
        "mutable": (
            "id",
            "name",
            "description",
            "sourceSgtId",
            "destinationSgtId",
            "matrixCellStatus",
            "defaultRule",
            "sgacls",
        ),
        "compare": (
            "description",
            "sourceSgtId",
            "destinationSgtId",
            "matrixCellStatus",
            "defaultRule",
            "sgacls",
        ),
    },
}

_SAFE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_DEFAULT_POLICY_NAMES = {"ANY-ANY", "ANY_ANY", "ANY ANY"}
_WRITE_METHODS = {"POST", "PUT", "DELETE"}


def _nonempty_text(value: Any, label: str) -> str:
    rendered = str(value or "")
    if not rendered or "\r" in rendered or "\x00" in rendered:
        raise IseManifestError("{} is empty or invalid".format(label))
    return rendered


def _mapping_records(value: Any) -> Iterable[Mapping[str, Any]]:
    if isinstance(value, Mapping):
        yield value
        for nested in value.values():
            yield from _mapping_records(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _mapping_records(nested)


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for nested in value.values():
            yield from _strings(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _strings(nested)


class IseErsAdapter:
    """A narrow ERS client for SGT, SGACL, and egress-matrix ownership."""

    def __init__(
        self,
        manifest: Mapping[str, Any],
        credential_resolver: Callable[[str], Mapping[str, str]],
        value_resolver: Callable[[str], str],
        session_factory: Callable[[], Any] = requests.Session,
        timeout: Sequence[int] = (10, 30),
    ):
        self.manifest = copy.deepcopy(dict(manifest))
        self.credential_resolver = credential_resolver
        self.value_resolver = value_resolver
        self.session_factory = session_factory
        self.timeout = tuple(int(item) for item in timeout)
        if len(self.timeout) != 2 or min(self.timeout) < 1:
            raise IseManifestError("ISE timeout must contain positive connect/read values")
        self.session: Optional[Any] = None
        self.verify: Any = True
        self.csrf_token: Optional[str] = None
        self._prepared: Optional[Dict[str, Any]] = None
        self._journal: List[Dict[str, Any]] = []
        self._validate_manifest()

    def _validate_manifest(self) -> None:
        if self.manifest.get("type") != "cisco_ise_ers":
            raise IseManifestError("Unsupported external-system type")
        if self.manifest.get("executor_contract_version") != "1.0":
            raise IseManifestError("Unsupported ISE executor contract version")
        if self.manifest.get("contains_secret_values") is not False:
            raise IseManifestError("ISE manifest must assert that it contains no secret values")
        if self.manifest.get("tls_verify") is not True:
            raise IseManifestError("ISE TLS verification cannot be disabled")
        parsed = urlparse(str(self.manifest.get("api_base_url", "")))
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise IseManifestError("ISE API base URL must be an origin-only HTTPS URL")
        try:
            port = parsed.port
        except ValueError as exc:
            raise IseManifestError("ISE API base URL port is invalid") from exc
        if port is not None and not 1 <= port <= 65535:
            raise IseManifestError("ISE API base URL port is invalid")
        self.base_url = str(self.manifest["api_base_url"]).rstrip("/")
        self.base_origin = "{}://{}".format(parsed.scheme, parsed.netloc)
        self.api_hostname = str(parsed.hostname).lower()
        credential_ref = str(self.manifest.get("credential_ref", ""))
        if not credential_ref.startswith("secret://"):
            raise IseManifestError("ISE credentials must use a secret:// reference")
        write_node_id = _nonempty_text(
            self.manifest.get("write_node_id"), "ISE write-node ID"
        )
        if "\n" in write_node_id or not _SAFE_NAME.fullmatch(write_node_id):
            raise IseManifestError("ISE write-node ID is invalid")
        try:
            if ip_address(str(self.manifest.get("write_node_address", ""))).version != 4:
                raise ValueError
        except ValueError as exc:
            raise IseManifestError("ISE write-node address must be IPv4") from exc
        ownership = self.manifest.get("ownership") or {}
        marker = _nonempty_text(
            ownership.get("marker"), "ownership marker"
        )
        if "\n" in marker:
            raise IseManifestError("Ownership marker cannot contain line breaks")
        if ownership.get("unmanaged_collision") != "fail":
            raise IseManifestError("ISE unmanaged collisions must fail")
        if (
            ownership.get("delete_policy")
            != "new_owned_resources_only_during_verified_rollback"
        ):
            raise IseManifestError("ISE deletion policy is unsupported")
        if (
            self.manifest.get("rollback")
            != "restore_prechange_snapshots_and_delete_only_new_owned_resources"
        ):
            raise IseManifestError("ISE rollback contract is unsupported")
        self.ownership_marker = marker
        expected_preconditions = {
            "ers_read_write_enabled",
            "write_node_is_primary_pan",
            "trusted_tls_chain",
            "default_egress_matrix_is_deny",
        }
        preconditions = self.manifest.get("preconditions") or []
        if len(preconditions) != 4 or set(preconditions) != expected_preconditions:
            raise IseManifestError("ISE precondition contract is incomplete")
        if self.manifest.get("csrf_mode") != "auto":
            raise IseManifestError("ISE CSRF mode must be auto")

        operations = self.manifest.get("operations")
        if not isinstance(operations, list) or not 1 <= len(operations) <= 10000:
            raise IseManifestError("ISE manifest requires operations")
        operation_ids = set()
        names = {"sgt": set(), "sgacl": set()}
        for operation in operations:
            if not isinstance(operation, Mapping):
                raise IseManifestError("ISE operation must be an object")
            operation_id = _nonempty_text(operation.get("operation_id"), "operation ID")
            if not _SAFE_NAME.fullmatch(operation_id) or operation_id in operation_ids:
                raise IseManifestError("ISE operation IDs must be unique")
            operation_ids.add(operation_id)
            resource = str(operation.get("resource", ""))
            spec = _RESOURCE_SPECS.get(resource)
            if spec is None:
                raise IseManifestError("Unsupported ISE resource")
            if operation.get("strategy") != spec["strategy"]:
                raise IseManifestError("ISE operation strategy does not match its resource")
            if operation.get("collision_policy") != "fail_if_unmanaged":
                raise IseManifestError("ISE collision policy must fail closed")
            desired = operation.get("desired")
            lookup = operation.get("lookup")
            if not isinstance(desired, Mapping) or not isinstance(lookup, Mapping):
                raise IseManifestError("ISE operation requires lookup and desired objects")
            description = _nonempty_text(
                desired.get("description"), "ISE resource description"
            )
            if "\n" in description or self.ownership_marker not in description:
                raise IseManifestError("Every desired ISE object must carry the ownership marker")
            if any("secret://" in value or "<secret:" in value for value in _strings(desired)):
                raise IseManifestError("ISE desired state cannot contain secret references")
            if resource in names:
                name = _nonempty_text(lookup.get("name"), "ISE resource name")
                if (
                    not _SAFE_NAME.fullmatch(name)
                    or name != str(desired.get("name", ""))
                    or name in names[resource]
                ):
                    raise IseManifestError("ISE resource names must be unique and lookup-bound")
                names[resource].add(name)
                if resource == "sgt":
                    value = desired.get("value")
                    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
                        raise IseManifestError("ISE SGT value must be an integer in 1..65535")
                    if not isinstance(desired.get("propogateToApic"), bool):
                        raise IseManifestError("ISE SGT APIC propagation flag must be boolean")
                elif (
                    desired.get("ipVersion") != "IPV4"
                    or not isinstance(desired.get("aclcontent"), str)
                    or not desired["aclcontent"]
                    or "\r" in desired["aclcontent"]
                    or "\x00" in desired["aclcontent"]
                ):
                    raise IseManifestError("ISE SGACL desired state is invalid")
            else:
                source_name = _nonempty_text(
                    lookup.get("source_sgt_name"), "source SGT name"
                )
                destination_name = _nonempty_text(
                    lookup.get("destination_sgt_name"), "destination SGT name"
                )
                if (
                    not _SAFE_NAME.fullmatch(source_name)
                    or not _SAFE_NAME.fullmatch(destination_name)
                    or source_name == destination_name
                ):
                    raise IseManifestError("Egress matrix SGT pair is invalid")
                refs = desired.get("sgacl_name_refs")
                if not isinstance(refs, list) or not refs or len(refs) != len(set(refs)):
                    raise IseManifestError("Egress matrix cell requires unique SGACL name references")
                if not all(_SAFE_NAME.fullmatch(str(item)) for item in refs):
                    raise IseManifestError("Egress matrix cell SGACL reference is invalid")
                if (
                    desired.get("matrixCellStatus") != "ENABLED"
                    or desired.get("defaultRule") != "NONE"
                ):
                    raise IseManifestError("Egress matrix cell must be enabled with explicit SGACLs")
        for operation in operations:
            if operation["resource"] != "egressmatrixcell":
                continue
            lookup = operation["lookup"]
            if lookup["source_sgt_name"] not in names["sgt"]:
                raise IseManifestError("Egress cell source does not reference a planned SGT")
            if lookup["destination_sgt_name"] not in names["sgt"]:
                raise IseManifestError("Egress cell destination does not reference a planned SGT")
            if not set(operation["desired"]["sgacl_name_refs"]).issubset(names["sgacl"]):
                raise IseManifestError("Egress cell references an unplanned SGACL")

    def connect(self) -> None:
        if self.session is not None:
            return
        credentials = self.credential_resolver(str(self.manifest["credential_ref"]))
        username = _nonempty_text(credentials.get("username"), "ISE username")
        password = _nonempty_text(credentials.get("password"), "ISE password")
        if "\n" in username or "\n" in password:
            raise IseManifestError("ISE credentials contain invalid line breaks")
        if self.manifest.get("ca_bundle_ref"):
            candidate = Path(
                self.value_resolver(str(self.manifest["ca_bundle_ref"]))
            ).expanduser().resolve()
            if not candidate.is_file():
                raise IseManifestError("ISE CA bundle reference must resolve to a regular file")
            self.verify = str(candidate)
        self.session = self.session_factory()
        self.session.auth = (username, password)
        self.session.headers.update(
            {"Accept": "application/json", "Content-Type": "application/json"}
        )
        self.session.trust_env = False
        response = self._request(
            "GET",
            "/ers/config/sgt/versioninfo",
            expected=(200,),
            headers={"X-CSRF-Token": "fetch"},
        )
        token = response.headers.get("X-CSRF-Token")
        if token:
            self.csrf_token = _nonempty_text(token, "ISE CSRF token")
            if "\n" in self.csrf_token:
                raise IseErsError("ISE CSRF token contains invalid line breaks")

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None
        self.csrf_token = None

    def _request(
        self,
        method: str,
        path: str,
        expected: Sequence[int],
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        if self.session is None:
            raise IseErsError("ISE session is not connected")
        if not path.startswith("/") or "//" in path or ".." in path:
            raise IseManifestError("Unsafe ISE API path")
        request_headers = dict(headers or {})
        verb = str(method).upper()
        if verb in _WRITE_METHODS and self.csrf_token:
            request_headers["X-CSRF-Token"] = self.csrf_token
        try:
            response = self.session.request(
                verb,
                self.base_url + path,
                params=dict(params or {}),
                json=dict(body) if body is not None else None,
                headers=request_headers,
                timeout=self.timeout,
                verify=self.verify,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            raise IseErsError("ISE request transport failed") from exc
        if response.status_code not in set(expected):
            raise IseErsError(
                "ISE {} {} returned HTTP {}".format(verb, path, response.status_code)
            )
        return response

    @staticmethod
    def _json(response: Any) -> Mapping[str, Any]:
        try:
            body = response.json()
        except (TypeError, ValueError) as exc:
            raise IseErsError("ISE returned malformed JSON") from exc
        if not isinstance(body, Mapping):
            raise IseErsError("ISE returned a non-object JSON response")
        return body

    def _root(self, resource: str, response: Any) -> Dict[str, Any]:
        root_name = _RESOURCE_SPECS[resource]["root"]
        root = self._json(response).get(root_name)
        if not isinstance(root, Mapping):
            raise IseErsError("ISE response is missing {}".format(root_name))
        resource_id = str(root.get("id", ""))
        if not _SAFE_ID.fullmatch(resource_id):
            raise IseErsError("ISE resource returned an unsafe identifier")
        return copy.deepcopy(dict(root))

    def _search(
        self, resource: str, filters: Sequence[str]
    ) -> List[Mapping[str, Any]]:
        response = self._request(
            "GET",
            "/ers/config/{}".format(_RESOURCE_SPECS[resource]["path"]),
            expected=(200,),
            params={"page": 1, "size": 100, "filter": list(filters)},
        )
        search = self._json(response).get("SearchResult")
        if not isinstance(search, Mapping):
            raise IseErsError("ISE search response is missing SearchResult")
        resources = search.get("resources") or []
        if not isinstance(resources, list):
            raise IseErsError("ISE search resources are malformed")
        total = int(search.get("total", len(resources)))
        if total > 100:
            raise IsePreflightError("ISE filtered lookup exceeded the bounded result limit")
        return [item for item in resources if isinstance(item, Mapping)]

    def _get_by_id(self, resource: str, resource_id: str) -> Optional[Dict[str, Any]]:
        if not _SAFE_ID.fullmatch(str(resource_id)):
            raise IseManifestError("Unsafe ISE resource identifier")
        response = self._request(
            "GET",
            "/ers/config/{}/{}".format(
                _RESOURCE_SPECS[resource]["path"], quote(str(resource_id), safe="")
            ),
            expected=(200, 404),
        )
        if response.status_code == 404:
            return None
        return self._root(resource, response)

    def _find_by_name(self, resource: str, name: str) -> Optional[Dict[str, Any]]:
        exact = []
        for summary in self._search(resource, ["name.EQ.{}".format(name)]):
            resource_id = str(summary.get("id", ""))
            candidate = self._get_by_id(resource, resource_id)
            if candidate is not None and str(candidate.get("name")) == name:
                exact.append(candidate)
        if len(exact) > 1:
            raise IseCollisionError("ISE lookup returned duplicate exact names")
        return exact[0] if exact else None

    def _find_sgt_by_value(self, value: int) -> Optional[Dict[str, Any]]:
        exact = []
        for summary in self._search("sgt", ["value.EQ.{}".format(int(value))]):
            candidate = self._get_by_id("sgt", str(summary.get("id", "")))
            if candidate is not None and int(candidate.get("value", -1)) == int(value):
                exact.append(candidate)
        if len(exact) > 1:
            raise IseCollisionError("ISE lookup returned duplicate exact SGT values")
        return exact[0] if exact else None

    def _find_cell(self, source_id: str, destination_id: str) -> Optional[Dict[str, Any]]:
        exact = []
        for summary in self._search(
            "egressmatrixcell",
            [
                "sourceSgtId.EQ.{}".format(source_id),
                "destinationSgtId.EQ.{}".format(destination_id),
            ],
        ):
            candidate = self._get_by_id(
                "egressmatrixcell", str(summary.get("id", ""))
            )
            if (
                candidate is not None
                and str(candidate.get("sourceSgtId")) == source_id
                and str(candidate.get("destinationSgtId")) == destination_id
            ):
                exact.append(candidate)
        if len(exact) > 1:
            raise IseCollisionError("ISE lookup returned duplicate SGT-pair cells")
        return exact[0] if exact else None

    def _mutable(self, resource: str, value: Mapping[str, Any]) -> Dict[str, Any]:
        return {
            key: copy.deepcopy(value[key])
            for key in _RESOURCE_SPECS[resource]["mutable"]
            if key in value
        }

    def _comparable(self, resource: str, value: Mapping[str, Any]) -> Dict[str, Any]:
        result = {
            key: copy.deepcopy(value.get(key))
            for key in _RESOURCE_SPECS[resource]["compare"]
        }
        if resource == "sgt" and result.get("value") is not None:
            result["value"] = int(result["value"])
        return result

    def _state_hash(self, resource: str, value: Mapping[str, Any]) -> str:
        return sha256_json(self._comparable(resource, value))

    def _owned(self, value: Mapping[str, Any]) -> bool:
        return self.ownership_marker in str(value.get("description", ""))

    def _classify(
        self,
        operation: Mapping[str, Any],
        desired: Mapping[str, Any],
        existing: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        resource = str(operation["resource"])
        action = {
            "operation_id": str(operation["operation_id"]),
            "resource": resource,
            "desired": copy.deepcopy(dict(desired)),
        }
        if existing is None:
            action["action"] = "create"
            return action
        if not self._owned(existing):
            raise IseCollisionError(
                "ISE {} collision is not owned by this orchestrator".format(resource)
            )
        snapshot = self._mutable(resource, existing)
        action.update(
            {
                "resource_id": str(existing["id"]),
                "snapshot": snapshot,
                "pre_hash": self._state_hash(resource, existing),
                "action": "noop"
                if self._comparable(resource, existing)
                == self._comparable(resource, desired)
                else "update",
            }
        )
        return action

    def _verify_primary_pan(self) -> Dict[str, Any]:
        response = self._request("GET", "/api/v1/deployment/node", expected=(200,))
        body = self._json(response)
        aliases = {
            str(self.manifest.get("write_node_id", "")).lower(),
            str(self.manifest.get("write_node_address", "")).lower(),
            self.api_hostname,
        }
        aliases.discard("")
        matches = []
        for record in _mapping_records(body):
            roles = record.get("roles")
            if not isinstance(roles, list) or "PrimaryAdmin" not in roles:
                continue
            identifiers = {
                str(record.get(key, "")).lower()
                for key in ("hostname", "fqdn", "ipAddress", "ipaddress", "name")
                if record.get(key)
            }
            if aliases.intersection(identifiers):
                matches.append(record)
        if len(matches) != 1:
            raise IsePreflightError("Configured ISE write node is not the unique PrimaryAdmin")
        return {"verified": True, "role": "PrimaryAdmin"}

    def _verify_default_deny(self) -> Dict[str, Any]:
        matches: Dict[str, Dict[str, Any]] = {}
        for name in sorted(_DEFAULT_POLICY_NAMES):
            for summary in self._search("egressmatrixcell", ["name.EQ.{}".format(name)]):
                candidate = self._get_by_id(
                    "egressmatrixcell", str(summary.get("id", ""))
                )
                if candidate is not None and str(candidate.get("name", "")).upper() in _DEFAULT_POLICY_NAMES:
                    matches[str(candidate["id"])] = candidate
        if len(matches) != 1:
            raise IsePreflightError("ISE ANY-ANY default egress policy was not uniquely identified")
        default_cell = next(iter(matches.values()))
        if str(default_cell.get("matrixCellStatus")) != "ENABLED":
            raise IsePreflightError("ISE ANY-ANY default egress policy is not enabled")
        if str(default_cell.get("defaultRule")) not in {"DENY_IP", "DENY_IP_LOG"}:
            raise IsePreflightError("ISE ANY-ANY default egress policy is not deny")
        return {
            "verified": True,
            "resource_hash": self._state_hash("egressmatrixcell", default_cell),
        }

    def prepare(self) -> Dict[str, Any]:
        if self.session is None:
            raise IseErsError("ISE adapter must be connected before preflight")
        if self._journal:
            raise IseErsError("ISE adapter cannot prepare with an active journal")
        primary = self._verify_primary_pan()
        default_policy = self._verify_default_deny()
        operations = list(self.manifest["operations"])
        priority = {"sgt": 0, "sgacl": 1, "egressmatrixcell": 2}
        operations.sort(key=lambda item: (priority[str(item["resource"])], str(item["operation_id"])))
        actions: List[Dict[str, Any]] = []
        known_sgts: Dict[str, str] = {}
        known_sgacls: Dict[str, str] = {}
        for operation in operations:
            resource = str(operation["resource"])
            if resource == "egressmatrixcell":
                continue
            name = str(operation["lookup"]["name"])
            desired = dict(operation["desired"])
            existing = self._find_by_name(resource, name)
            if resource == "sgt":
                by_value = self._find_sgt_by_value(int(desired["value"]))
                if by_value is not None and (
                    existing is None or str(by_value["id"]) != str(existing["id"])
                ):
                    raise IseCollisionError("ISE SGT value is already assigned to another object")
            action = self._classify(operation, desired, existing)
            actions.append(action)
            if existing is not None:
                target = known_sgts if resource == "sgt" else known_sgacls
                target[name] = str(existing["id"])
        for operation in operations:
            if operation["resource"] != "egressmatrixcell":
                continue
            lookup = operation["lookup"]
            source_id = known_sgts.get(str(lookup["source_sgt_name"]))
            destination_id = known_sgts.get(str(lookup["destination_sgt_name"]))
            sgacl_ids = [
                known_sgacls.get(str(name))
                for name in operation["desired"]["sgacl_name_refs"]
            ]
            if source_id and destination_id and all(sgacl_ids):
                desired = dict(operation["desired"])
                desired.pop("sgacl_name_refs", None)
                desired.update(
                    {
                        "sourceSgtId": source_id,
                        "destinationSgtId": destination_id,
                        "sgacls": sgacl_ids,
                    }
                )
                existing = self._find_cell(source_id, destination_id)
                actions.append(self._classify(operation, desired, existing))
            else:
                actions.append(
                    {
                        "operation_id": str(operation["operation_id"]),
                        "resource": "egressmatrixcell",
                        "action": "deferred",
                        "lookup": copy.deepcopy(dict(lookup)),
                        "desired": copy.deepcopy(dict(operation["desired"])),
                    }
                )
        summary = [
            {
                "operation_id": action["operation_id"],
                "resource": action["resource"],
                "action": action["action"],
                "pre_hash": action.get("pre_hash"),
            }
            for action in actions
        ]
        self._prepared = {
            "actions": actions,
            "prepared_hash": sha256_json(summary),
            "primary_pan": primary,
            "default_policy": default_policy,
        }
        return {
            "verified": True,
            "prepared_hash": self._prepared["prepared_hash"],
            "action_counts": {
                name: sum(1 for item in actions if item["action"] == name)
                for name in ("create", "update", "noop", "deferred")
            },
            "primary_pan": primary,
            "default_policy": default_policy,
        }

    def _body(self, resource: str, desired: Mapping[str, Any]) -> Dict[str, Any]:
        return {_RESOURCE_SPECS[resource]["root"]: self._mutable(resource, desired)}

    def _location_id(self, resource: str, response: Any) -> str:
        location = str(response.headers.get("Location", ""))
        parsed = urlparse(location)
        if parsed.scheme or parsed.netloc:
            if "{}://{}".format(parsed.scheme, parsed.netloc) != self.base_origin:
                raise IseVerificationError("ISE create returned a cross-origin Location")
            path = parsed.path
        else:
            path = location
        prefix = "/ers/config/{}/".format(_RESOURCE_SPECS[resource]["path"])
        if not path.startswith(prefix):
            raise IseVerificationError("ISE create returned an unexpected Location")
        resource_id = path[len(prefix) :]
        if not _SAFE_ID.fullmatch(resource_id):
            raise IseVerificationError("ISE create returned an unsafe resource ID")
        return resource_id

    def _lookup_for_action(self, action: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        resource = str(action["resource"])
        desired = action["desired"]
        if resource in {"sgt", "sgacl"}:
            return self._find_by_name(resource, str(desired["name"]))
        return self._find_cell(
            str(desired["sourceSgtId"]), str(desired["destinationSgtId"])
        )

    def _apply_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        resource = str(action["resource"])
        desired = dict(action["desired"])
        kind = str(action["action"])
        if kind == "noop":
            current = self._get_by_id(resource, str(action["resource_id"]))
            if current is None or self._state_hash(resource, current) != action["pre_hash"]:
                raise IseCollisionError("ISE object changed after preflight")
            return {
                "operation_id": action["operation_id"],
                "resource": resource,
                "action": "noop",
                "resource_id": str(action["resource_id"]),
                "verified": True,
                "post_hash": str(action["pre_hash"]),
            }
        if kind == "create":
            if self._lookup_for_action(action) is not None:
                raise IseCollisionError("ISE object appeared after preflight")
            journal = {
                "operation_id": action["operation_id"],
                "resource": resource,
                "action": "create",
                "resource_id": None,
                "desired": copy.deepcopy(desired),
                "post_hash": None,
            }
            self._journal.append(journal)
            response = self._request(
                "POST",
                "/ers/config/{}".format(_RESOURCE_SPECS[resource]["path"]),
                expected=(201,),
                body=self._body(resource, desired),
            )
            try:
                resource_id = self._location_id(resource, response)
            except IseVerificationError:
                # Never follow an untrusted Location. Recover through the
                # bounded same-origin lookup so rollback can still own the
                # successful POST.
                recovered = self._lookup_for_action(action)
                if (
                    recovered is not None
                    and self._owned(recovered)
                    and self._comparable(resource, recovered)
                    == self._comparable(resource, desired)
                ):
                    journal["resource_id"] = str(recovered["id"])
                    journal["post_hash"] = self._state_hash(resource, recovered)
                raise
            journal["resource_id"] = resource_id
            current = self._get_by_id(resource, resource_id)
            if current is None:
                raise IseVerificationError("ISE create verification could not read the object")
            journal["post_hash"] = self._state_hash(resource, current)
            if self._comparable(resource, current) != self._comparable(resource, desired):
                raise IseVerificationError("ISE create verification failed")
            return {
                "operation_id": journal["operation_id"],
                "resource": resource,
                "action": "create",
                "resource_id": resource_id,
                "post_hash": journal["post_hash"],
                "verified": True,
            }
        if kind != "update":
            raise IseManifestError("Unknown prepared ISE action")
        resource_id = str(action["resource_id"])
        current = self._get_by_id(resource, resource_id)
        if current is None or self._state_hash(resource, current) != action["pre_hash"]:
            raise IseCollisionError("ISE object changed after preflight")
        update = dict(desired)
        update["id"] = resource_id
        journal = {
            "operation_id": action["operation_id"],
            "resource": resource,
            "action": "update",
            "resource_id": resource_id,
            "snapshot": copy.deepcopy(action["snapshot"]),
            "pre_hash": str(action["pre_hash"]),
            "post_hash": None,
        }
        self._journal.append(journal)
        self._request(
            "PUT",
            "/ers/config/{}/{}".format(_RESOURCE_SPECS[resource]["path"], quote(resource_id, safe="")),
            expected=(200, 204),
            body=self._body(resource, update),
        )
        current = self._get_by_id(resource, resource_id)
        if current is None:
            raise IseVerificationError("ISE update verification could not read the object")
        journal["post_hash"] = self._state_hash(resource, current)
        if self._comparable(resource, current) != self._comparable(resource, desired):
            raise IseVerificationError("ISE update verification failed")
        return {
            key: value for key, value in journal.items() if key != "snapshot"
        } | {"verified": True}

    def apply(self) -> Dict[str, Any]:
        if self._prepared is None:
            raise IseErsError("ISE preflight prepare must complete before apply")
        if self._journal:
            raise IseErsError("ISE transaction already contains changes")
        results: List[Dict[str, Any]] = []
        ids = {"sgt": {}, "sgacl": {}}
        actions = list(self._prepared["actions"])
        for action in actions:
            if action["resource"] == "egressmatrixcell":
                continue
            result = self._apply_action(action)
            results.append(result)
            ids[str(action["resource"])][str(action["desired"]["name"])] = result["resource_id"]
        for action in actions:
            if action["resource"] != "egressmatrixcell":
                continue
            if action["action"] == "deferred":
                desired = dict(action["desired"])
                refs = desired.pop("sgacl_name_refs")
                source_id = ids["sgt"][str(action["lookup"]["source_sgt_name"])]
                destination_id = ids["sgt"][str(action["lookup"]["destination_sgt_name"])]
                desired.update(
                    {
                        "sourceSgtId": source_id,
                        "destinationSgtId": destination_id,
                        "sgacls": [ids["sgacl"][str(name)] for name in refs],
                    }
                )
                operation = next(
                    item
                    for item in self.manifest["operations"]
                    if item["operation_id"] == action["operation_id"]
                )
                action = self._classify(
                    operation, desired, self._find_cell(source_id, destination_id)
                )
            results.append(self._apply_action(action))
        return {
            "verified": True,
            "prepared_hash": self._prepared["prepared_hash"],
            "changed_count": len(self._journal),
            "noop_count": sum(1 for item in results if item["action"] == "noop"),
            "operations": results,
        }

    def rollback(self) -> Dict[str, Any]:
        failures = []
        rolled_back = []
        for item in reversed(self._journal):
            resource = str(item["resource"])
            try:
                if item["action"] == "create":
                    resource_id = item.get("resource_id")
                    current = (
                        self._get_by_id(resource, str(resource_id))
                        if resource_id
                        else self._lookup_for_action(
                            {"resource": resource, "desired": item["desired"]}
                        )
                    )
                    if current is None:
                        # A failed/ambiguous POST that left no object is already
                        # at the verified pre-change state.
                        rolled_back.append(
                            {
                                "operation_id": item["operation_id"],
                                "resource": resource,
                                "action": "create",
                                "verified": True,
                                "already_absent": True,
                            }
                        )
                        continue
                    resource_id = str(current["id"])
                    post_hash = item.get("post_hash")
                    if post_hash and self._state_hash(resource, current) != post_hash:
                        raise IseRollbackError("ISE object changed after apply; refusing rollback")
                    if not self._owned(current):
                        raise IseRollbackError("ISE created object lost its ownership marker")
                    if self._comparable(resource, current) != self._comparable(
                        resource, item["desired"]
                    ):
                        raise IseRollbackError("ISE created object no longer matches the transaction")
                    self._request(
                        "DELETE",
                        "/ers/config/{}/{}".format(
                            _RESOURCE_SPECS[resource]["path"], quote(resource_id, safe="")
                        ),
                        expected=(200, 204),
                    )
                    if self._get_by_id(resource, resource_id) is not None:
                        raise IseRollbackError("ISE create rollback deletion was not verified")
                else:
                    resource_id = str(item["resource_id"])
                    current = self._get_by_id(resource, resource_id)
                    if current is None:
                        raise IseRollbackError("ISE updated object disappeared before rollback")
                    current_hash = self._state_hash(resource, current)
                    if current_hash == item["pre_hash"]:
                        rolled_back.append(
                            {
                                "operation_id": item["operation_id"],
                                "resource": resource,
                                "action": "update",
                                "verified": True,
                                "already_restored": True,
                            }
                        )
                        continue
                    if not item.get("post_hash") or current_hash != item["post_hash"]:
                        raise IseRollbackError("ISE object changed after apply; refusing rollback")
                    snapshot = copy.deepcopy(item["snapshot"])
                    self._request(
                        "PUT",
                        "/ers/config/{}/{}".format(
                            _RESOURCE_SPECS[resource]["path"], quote(resource_id, safe="")
                        ),
                        expected=(200, 204),
                        body=self._body(resource, snapshot),
                    )
                    restored = self._get_by_id(resource, resource_id)
                    if restored is None or self._state_hash(resource, restored) != item["pre_hash"]:
                        raise IseRollbackError("ISE update rollback was not verified")
                rolled_back.append(
                    {
                        "operation_id": item["operation_id"],
                        "resource": resource,
                        "action": item["action"],
                        "verified": True,
                    }
                )
            except Exception as exc:
                failures.append(
                    {
                        "operation_id": item["operation_id"],
                        "resource": resource,
                        "error_type": type(exc).__name__,
                    }
                )
        if failures:
            raise IseRollbackError("ISE rollback failed for one or more resources")
        self._journal = []
        return {"verified": True, "operations": rolled_back}

    @property
    def has_changes(self) -> bool:
        return bool(self._journal)
