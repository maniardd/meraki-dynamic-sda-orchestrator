"""Secret-safe intake checks for tenant-native Meraki workflow exports.

Meraki owns the concrete workflow and activity identifiers.  The portable
package therefore cannot manufacture an import file safely: it must learn the
installed tenant serialization from genuine exports.  This module inventories
those exports without returning property values and fails closed on unsafe
transport, inline credentials, Python execution, or incomplete package sets.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


_WORKFLOW_PREFIX = "definition_workflow_"
_ACTIVITY_PREFIX = "definition_activity_"
_FORBIDDEN_MARKERS = {
    "transport.ngrok": "ngrok",
    "api.legacy_v2": "/api/v2/",
    "transport.tls_verification_disabled": "verify=false",
}
_SECRET_KEYS = {
    "api_key",
    "apikey",
    "authorization",
    "bearer_token",
    "client_secret",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


@dataclass(frozen=True)
class NativeExportIssue:
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


def load_native_export(path: Path | str) -> Dict[str, Any]:
    document = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Meraki native export must be a JSON object")
    return document


def _canonical_hash(document: Mapping[str, Any]) -> str:
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _walk(value: Any, path: str = "$") -> Iterable[Tuple[str, Any]]:
    yield path, value
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, "{}.{}".format(path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, "{}[{}]".format(path, index))


def _workflow_objects(document: Mapping[str, Any]) -> List[Tuple[str, Mapping[str, Any]]]:
    found: List[Tuple[str, Mapping[str, Any]]] = []
    seen: set[int] = set()
    for path, value in _walk(document):
        if not isinstance(value, Mapping):
            continue
        if value.get("base_type") != "workflow" and value.get("object_type") != "definition_workflow":
            continue
        identity = id(value)
        if identity not in seen:
            seen.add(identity)
            found.append((path, value))
    return found


def _activity_objects(workflow: Mapping[str, Any], workflow_path: str) -> List[Tuple[str, Mapping[str, Any]]]:
    found: List[Tuple[str, Mapping[str, Any]]] = []
    actions = workflow.get("actions")
    if not isinstance(actions, list):
        return found
    for path, value in _walk(actions, workflow_path + ".actions"):
        if not isinstance(value, Mapping):
            continue
        if value.get("base_type") == "activity" or value.get("object_type") == "definition_activity":
            found.append((path, value))
    return found


def _label(value: Mapping[str, Any]) -> str:
    properties = value.get("properties")
    if not isinstance(properties, Mapping):
        properties = {}
    for candidate in (
        properties.get("display_name"),
        value.get("title"),
        value.get("name"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
    return ""


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()


def inventory_native_export(document: Mapping[str, Any]) -> Dict[str, Any]:
    """Return structural fingerprints only; property values are never emitted."""

    workflows: List[Dict[str, Any]] = []
    for workflow_path, workflow in _workflow_objects(document):
        actions: List[Dict[str, Any]] = []
        for action_path, action in _activity_objects(workflow, workflow_path):
            properties = action.get("properties")
            if not isinstance(properties, Mapping):
                properties = {}
            actions.append(
                {
                    "path": action_path,
                    "name": _label(action),
                    "type": str(action.get("type", "")),
                    "base_type": str(action.get("base_type", "")),
                    "object_type": str(action.get("object_type", "")),
                    "property_keys": sorted(str(key) for key in properties),
                }
            )
        workflows.append(
            {
                "path": workflow_path,
                "name": _label(workflow),
                "type": str(workflow.get("type", "")),
                "action_count": len(actions),
                "actions": actions,
            }
        )
    return {
        "export_sha256": _canonical_hash(document),
        "workflow_count": len(workflows),
        "workflows": workflows,
        "contains_property_values": False,
    }


def _secret_reference(value: str) -> bool:
    stripped = value.strip()
    return (
        not stripped
        or stripped.startswith("$") and stripped.endswith("$")
        or stripped.startswith("secret://")
        or stripped.startswith("target://")
    )


def audit_native_export(
    document: Mapping[str, Any],
    *,
    expected_workflow_names: Sequence[str] = (),
    required_activity_names: Sequence[str] = (),
) -> Dict[str, Any]:
    issues: List[NativeExportIssue] = []
    workflows = _workflow_objects(document)
    if not workflows:
        issues.append(
            NativeExportIssue(
                "native.workflow_missing",
                "$",
                "Export contains no tenant-native definition_workflow object",
            )
        )

    workflow_names: List[str] = []
    activity_labels: List[str] = []
    for workflow_path, workflow in workflows:
        workflow_names.append(_label(workflow))
        unique_name = str(workflow.get("unique_name", ""))
        if not unique_name.startswith(_WORKFLOW_PREFIX):
            issues.append(
                NativeExportIssue(
                    "native.workflow_identifier",
                    workflow_path + ".unique_name",
                    "Workflow must retain its tenant-generated definition_workflow identifier",
                )
            )
        if workflow.get("type") != "generic.workflow":
            issues.append(
                NativeExportIssue(
                    "native.workflow_type",
                    workflow_path + ".type",
                    "Expected a tenant-native generic.workflow definition",
                )
            )
        properties = workflow.get("properties")
        if not isinstance(properties, Mapping) or not str(properties.get("description", "")).strip():
            issues.append(
                NativeExportIssue(
                    "documentation.workflow_description",
                    workflow_path + ".properties.description",
                    "Every exported workflow requires a description",
                )
            )
        for action_path, action in _activity_objects(workflow, workflow_path):
            activity_labels.append(_normalized("{} {} {}".format(
                _label(action), action.get("name", ""), action.get("type", "")
            )))
            action_unique_name = str(action.get("unique_name", ""))
            if not action_unique_name.startswith(_ACTIVITY_PREFIX):
                issues.append(
                    NativeExportIssue(
                        "native.activity_identifier",
                        action_path + ".unique_name",
                        "Activity must retain its tenant-generated definition_activity identifier",
                    )
                )
            if action.get("type") == "python3.script":
                issues.append(
                    NativeExportIssue(
                        "native.python_forbidden",
                        action_path,
                        "Production workflow exports must use native activities instead of Python",
                    )
                )

    expected = {str(name).strip() for name in expected_workflow_names if str(name).strip()}
    actual = {name for name in workflow_names if name}
    for missing in sorted(expected - actual):
        issues.append(
            NativeExportIssue(
                "package.workflow_missing",
                "$",
                "Native export set is missing workflow {!r}".format(missing),
            )
        )

    for required_name in required_activity_names:
        marker = _normalized(str(required_name))
        if marker and not any(marker in label for label in activity_labels):
            issues.append(
                NativeExportIssue(
                    "package.activity_missing",
                    "$",
                    "Native export set is missing activity {!r}".format(required_name),
                )
            )

    for path, value in _walk(document):
        if isinstance(value, str):
            lowered = value.lower().replace(" ", "")
            for code, marker in _FORBIDDEN_MARKERS.items():
                if marker in lowered:
                    issues.append(
                        NativeExportIssue(
                            code,
                            path,
                            "Forbidden production marker found in native export",
                        )
                    )
            if re.search(r"\bbearer\s+[a-z0-9._~+/-]{8,}", value, re.IGNORECASE):
                issues.append(
                    NativeExportIssue(
                        "secret.inline_bearer",
                        path,
                        "Inline bearer credentials are forbidden",
                    )
                )
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_name = str(key).lower().replace("-", "_")
                if key_name in _SECRET_KEYS and isinstance(child, str) and not _secret_reference(child):
                    issues.append(
                        NativeExportIssue(
                            "secret.inline_value",
                            "{}.{}".format(path, key),
                            "Credential values must stay in Meraki Account Keys or secret references",
                        )
                    )

    # Duplicate findings at one path/code add noise without adding evidence.
    deduplicated: Dict[Tuple[str, str], NativeExportIssue] = {}
    for issue in issues:
        deduplicated[(issue.code, issue.path)] = issue
    ordered = sorted(deduplicated.values(), key=lambda item: (item.path, item.code))
    errors = [issue for issue in ordered if issue.severity == "error"]
    warnings = [issue for issue in ordered if issue.severity == "warning"]
    return {
        "native_export_valid": not errors,
        "production_package_complete": not errors and expected.issubset(actual),
        "export_sha256": _canonical_hash(document),
        "workflow_names": sorted(actual),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [issue.as_dict() for issue in ordered],
        "inventory": inventory_native_export(document),
    }


def audit_native_export_set(
    documents: Sequence[Mapping[str, Any]],
    *,
    expected_workflow_names: Sequence[str],
    required_activity_names: Sequence[str],
) -> Dict[str, Any]:
    """Audit multiple exports as one package without merging their identifiers."""

    reports = [audit_native_export(document) for document in documents]
    workflow_names = {
        name for report in reports for name in report.get("workflow_names", [])
    }
    activity_labels = {
        _normalized("{} {}".format(action.get("name", ""), action.get("type", "")))
        for report in reports
        for workflow in report["inventory"]["workflows"]
        for action in workflow["actions"]
    }
    issues: List[Dict[str, str]] = [
        issue for report in reports for issue in report.get("issues", [])
    ]
    for missing in sorted(set(expected_workflow_names) - workflow_names):
        issues.append(
            NativeExportIssue(
                "package.workflow_missing", "$", "Missing workflow {!r}".format(missing)
            ).as_dict()
        )
    for required_name in required_activity_names:
        marker = _normalized(required_name)
        if not any(marker in label for label in activity_labels):
            issues.append(
                NativeExportIssue(
                    "package.activity_missing", "$", "Missing activity {!r}".format(required_name)
                ).as_dict()
            )
    issues = sorted(
        {(item["code"], item["path"], item["message"]): item for item in issues}.values(),
        key=lambda item: (item["path"], item["code"], item["message"]),
    )
    error_count = sum(item.get("severity") == "error" for item in issues)
    return {
        "native_export_set_valid": error_count == 0,
        "production_package_complete": error_count == 0,
        "document_count": len(documents),
        "workflow_names": sorted(workflow_names),
        "error_count": error_count,
        "warning_count": sum(item.get("severity") == "warning" for item in issues),
        "issues": issues,
        "inventories": [report["inventory"] for report in reports],
    }
