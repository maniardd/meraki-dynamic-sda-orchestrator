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
_WORKFLOW_VARIABLE_PREFIX = "variable_workflow_"
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
        workflow_properties = workflow.get("properties")
        if not isinstance(workflow_properties, Mapping):
            workflow_properties = {}
        variables: List[Dict[str, Any]] = []
        raw_variables = workflow.get("variables")
        if isinstance(raw_variables, list):
            for variable in raw_variables:
                if not isinstance(variable, Mapping):
                    continue
                variable_properties = variable.get("properties")
                if not isinstance(variable_properties, Mapping):
                    variable_properties = {}
                variables.append(
                    {
                        "object_type": str(variable.get("object_type", "")),
                        "unique_name_prefix": (
                            _WORKFLOW_VARIABLE_PREFIX
                            if str(variable.get("unique_name", "")).startswith(
                                _WORKFLOW_VARIABLE_PREFIX
                            )
                            else ""
                        ),
                        "wrapper_keys": sorted(str(key) for key in variable),
                        "property_keys": sorted(
                            str(key) for key in variable_properties
                        ),
                    }
                )
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
                    "unique_name_prefix": (
                        _ACTIVITY_PREFIX
                        if str(action.get("unique_name", "")).startswith(
                            _ACTIVITY_PREFIX
                        )
                        else ""
                    ),
                    "property_keys": sorted(str(key) for key in properties),
                }
            )
        workflows.append(
            {
                "path": workflow_path,
                "name": _label(workflow),
                "type": str(workflow.get("type", "")),
                "base_type": str(workflow.get("base_type", "")),
                "object_type": str(workflow.get("object_type", "")),
                "unique_name_prefix": (
                    _WORKFLOW_PREFIX
                    if str(workflow.get("unique_name", "")).startswith(
                        _WORKFLOW_PREFIX
                    )
                    else ""
                ),
                "top_level_keys": sorted(str(key) for key in workflow),
                "property_keys": sorted(str(key) for key in workflow_properties),
                "variables": variables,
                "action_count": len(actions),
                "actions": actions,
            }
        )
    return {
        "export_sha256": _canonical_hash(document),
        "top_level_keys": sorted(str(key) for key in document),
        "workflow_count": len(workflows),
        "workflows": workflows,
        "contains_property_values": False,
    }


def verify_capture_fingerprint(
    document: Mapping[str, Any], fingerprint: Mapping[str, Any]
) -> Dict[str, Any]:
    """Compare a raw capture to its committed structural-only fingerprint."""

    issues: List[NativeExportIssue] = []
    inventory = inventory_native_export(document)
    source = fingerprint.get("source")
    if not isinstance(source, Mapping):
        source = {}
    if source.get("export_sha256") != inventory["export_sha256"]:
        issues.append(
            NativeExportIssue(
                "capture.hash",
                "$.source.export_sha256",
                "Capture provenance hash does not match the raw tenant export",
            )
        )
    safety = fingerprint.get("safety")
    if not isinstance(safety, Mapping):
        safety = {}
    for field, expected in (
        ("contains_property_values", False),
        ("contains_credentials", False),
        ("contains_target_bindings", False),
        ("configured_properties_complete", True),
        ("workflow_executed", False),
    ):
        if safety.get(field) is not expected:
            issues.append(
                NativeExportIssue(
                    "capture.safety",
                    "$.safety.{}".format(field),
                    "Capture safety declaration is missing or inconsistent",
                )
            )
    if source.get("raw_export_committed") is not False:
        issues.append(
            NativeExportIssue(
                "capture.raw_export",
                "$.source.raw_export_committed",
                "Raw tenant exports must remain outside the repository",
            )
        )
    if source.get("child_workflows_embedded") is not False:
        issues.append(
            NativeExportIssue(
                "capture.child_workflows",
                "$.source.child_workflows_embedded",
                "The schema capture must exclude child-workflow internals",
            )
        )

    expected_export_keys = fingerprint.get("export_top_level_keys")
    if (
        not isinstance(expected_export_keys, list)
        or inventory["top_level_keys"] != sorted(expected_export_keys)
    ):
        issues.append(
            NativeExportIssue(
                "capture.export_keys",
                "$.export_top_level_keys",
                "Export top-level key inventory does not match the raw capture",
            )
        )

    workflows = inventory["workflows"]
    if len(workflows) != 1:
        issues.append(
            NativeExportIssue(
                "capture.workflow_count",
                "$.workflow",
                "Schema capture must contain exactly one root workflow",
            )
        )
    else:
        observed_workflow = workflows[0]
        expected_workflow = fingerprint.get("workflow")
        if not isinstance(expected_workflow, Mapping):
            expected_workflow = {}
        for observed_field, expected_field, code in (
            ("type", "type", "capture.workflow_type"),
            ("base_type", "base_type", "capture.workflow_base_type"),
            ("object_type", "object_type", "capture.workflow_object_type"),
            (
                "unique_name_prefix",
                "unique_name_prefix",
                "capture.workflow_identifier",
            ),
            ("top_level_keys", "top_level_keys", "capture.workflow_keys"),
            ("property_keys", "property_keys", "capture.workflow_property_keys"),
        ):
            observed = observed_workflow.get(observed_field)
            expected = expected_workflow.get(expected_field)
            if isinstance(observed, list) and isinstance(expected, list):
                matches = observed == sorted(expected)
            else:
                matches = observed == expected
            if not matches:
                issues.append(
                    NativeExportIssue(
                        code,
                        "$.workflow.{}".format(expected_field),
                        "Workflow structural fingerprint does not match the raw capture",
                    )
                )
        if observed_workflow.get("name") != source.get("workflow_name"):
            issues.append(
                NativeExportIssue(
                    "capture.workflow_name",
                    "$.source.workflow_name",
                    "Captured workflow label does not match the raw export",
                )
            )

        expected_variable = expected_workflow.get("variable")
        observed_variables = observed_workflow.get("variables") or []
        variable_match = False
        if isinstance(expected_variable, Mapping):
            for observed_variable in observed_variables:
                variable_match = (
                    observed_variable.get("object_type")
                    == expected_variable.get("object_type")
                    and observed_variable.get("unique_name_prefix")
                    == expected_variable.get("unique_name_prefix")
                    and observed_variable.get("wrapper_keys")
                    == sorted(expected_variable.get("wrapper_keys") or [])
                    and observed_variable.get("property_keys")
                    == sorted(expected_variable.get("property_keys") or [])
                )
                if variable_match:
                    break
        if not variable_match:
            issues.append(
                NativeExportIssue(
                    "capture.workflow_variable",
                    "$.workflow.variable",
                    "Configured workflow-variable schema does not match the raw capture",
                )
            )

        expected_activities = fingerprint.get("activities")
        if not isinstance(expected_activities, Mapping):
            expected_activities = {}
        observed_actions = observed_workflow.get("actions") or []
        for portable_name, expected_activity in expected_activities.items():
            if not isinstance(expected_activity, Mapping):
                candidates: List[Mapping[str, Any]] = []
            else:
                candidates = [
                    action
                    for action in observed_actions
                    if action.get("type") == expected_activity.get("type")
                ]
            matched = any(
                action.get("base_type") == expected_activity.get("base_type")
                and action.get("object_type") == expected_activity.get("object_type")
                and action.get("unique_name_prefix")
                == expected_activity.get("unique_name_prefix")
                and action.get("property_keys")
                == sorted(expected_activity.get("property_keys") or [])
                for action in candidates
            )
            if not matched:
                issues.append(
                    NativeExportIssue(
                        "capture.activity",
                        "$.activities.{}".format(portable_name),
                        "Native activity type or property-key schema does not match the raw capture",
                    )
                )

        expected_types = {
            str(item.get("type", ""))
            for item in expected_activities.values()
            if isinstance(item, Mapping)
        }
        observed_types = {str(item.get("type", "")) for item in observed_actions}
        if observed_types != expected_types:
            issues.append(
                NativeExportIssue(
                    "capture.activity_inventory",
                    "$.activities",
                    "Native activity inventory contains missing or unexpected types",
                )
            )

        raw_workflows = _workflow_objects(document)
        raw_root = raw_workflows[0][1] if len(raw_workflows) == 1 else {}
        raw_actions = raw_root.get("actions") if isinstance(raw_root, Mapping) else []
        reverse_types = {
            str(item.get("type")): str(name)
            for name, item in expected_activities.items()
            if isinstance(item, Mapping)
        }
        root_sequence = [
            reverse_types.get(str(action.get("type")), "")
            for action in raw_actions
            if isinstance(action, Mapping)
        ] if isinstance(raw_actions, list) else []
        topology = fingerprint.get("serialization_topology")
        expected_root_sequence = (
            topology.get("root_action_sequence")
            if isinstance(topology, Mapping)
            else None
        )
        if root_sequence != expected_root_sequence:
            issues.append(
                NativeExportIssue(
                    "capture.root_sequence",
                    "$.serialization_topology.root_action_sequence",
                    "Root native action sequence does not match the raw capture",
                )
            )

        if not isinstance(topology, Mapping):
            topology = {}

        condition_topology = topology.get("condition")
        condition_type = str(
            (expected_activities.get("condition") or {}).get("type", "")
        )
        branch_type = str(
            (expected_activities.get("condition_branch") or {}).get("type", "")
        )
        terminal_type = str(
            (expected_activities.get("completed") or {}).get("type", "")
        )
        raw_condition = next(
            (
                action
                for action in raw_actions
                if isinstance(action, Mapping)
                and action.get("type") == condition_type
            ),
            None,
        ) if isinstance(raw_actions, list) else None
        condition_valid = False
        if isinstance(condition_topology, Mapping) and isinstance(raw_condition, Mapping):
            blocks_key = str(condition_topology.get("children_key", ""))
            branch_actions_key = str(
                condition_topology.get("branch_actions_key", "")
            )
            blocks = raw_condition.get(blocks_key)
            condition_valid = (
                isinstance(blocks, list)
                and bool(blocks)
                and all(
                    isinstance(block, Mapping)
                    and block.get("type") == branch_type
                    for block in blocks
                )
                and any(
                    isinstance(block.get(branch_actions_key), list)
                    and any(
                        isinstance(action, Mapping)
                        and action.get("type") == terminal_type
                        for action in block.get(branch_actions_key, [])
                    )
                    for block in blocks
                    if isinstance(block, Mapping)
                )
            )
        if condition_type and not condition_valid:
            issues.append(
                NativeExportIssue(
                    "capture.condition_topology",
                    "$.serialization_topology.condition",
                    "Condition branch and terminal nesting does not match the raw capture",
                )
            )

        while_topology = topology.get("while_loop")
        while_type = str(
            (expected_activities.get("while_loop") or {}).get("type", "")
        )
        raw_while = next(
            (
                action
                for action in raw_actions
                if isinstance(action, Mapping) and action.get("type") == while_type
            ),
            None,
        ) if isinstance(raw_actions, list) else None
        while_valid = False
        if isinstance(while_topology, Mapping) and isinstance(raw_while, Mapping):
            while_blocks = raw_while.get(str(while_topology.get("children_key", "")))
            while_valid = (
                isinstance(while_blocks, list)
                and bool(while_blocks)
                and all(
                    isinstance(block, Mapping)
                    and block.get("type") == branch_type
                    for block in while_blocks
                )
            )
        if while_type and not while_valid:
            issues.append(
                NativeExportIssue(
                    "capture.while_topology",
                    "$.serialization_topology.while_loop",
                    "While-loop branch nesting does not match the raw capture",
                )
            )

        child_topology = topology.get("child_workflow")
        child_type = str(
            (expected_activities.get("child_workflow") or {}).get("type", "")
        )
        raw_children = [
            action
            for action in raw_actions
            if isinstance(action, Mapping) and action.get("type") == child_type
        ] if isinstance(raw_actions, list) else []
        child_valid = False
        if isinstance(child_topology, Mapping):
            dependency_key = str(child_topology.get("dependency_key", ""))
            dependencies = document.get(dependency_key)
            child_refs = [
                (action.get("properties") or {}).get("workflow_id")
                for action in raw_children
                if isinstance(action.get("properties"), Mapping)
            ]
            child_valid = (
                child_topology.get("embedded_workflows") is False
                and isinstance(dependencies, list)
                and bool(child_refs)
                and all(reference in dependencies for reference in child_refs)
                and len(raw_workflows) == 1
            )
        if child_type and not child_valid:
            issues.append(
                NativeExportIssue(
                    "capture.child_topology",
                    "$.serialization_topology.child_workflow",
                    "Child-workflow dependency reference does not match the raw capture",
                )
            )

    ordered = sorted(issues, key=lambda item: (item.path, item.code))
    return {
        "capture_fingerprint_valid": not ordered,
        "error_count": len(ordered),
        "issues": [issue.as_dict() for issue in ordered],
        "inventory": inventory,
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
