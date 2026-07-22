"""Validation and deterministic build plans for the Meraki workflow package.

The YAML manifest is deliberately vendor-serialization independent.  Meraki
exports contain tenant-generated definition identifiers and installed atomic
action identifiers, so those identifiers must be captured from the target
tenant rather than invented by this project.  This module proves the portable
security and API contract before the native workflows are assembled/exported.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence

import yaml


EXPECTED_ROLES = {"planner", "approver", "operator", "auditor"}
ALLOWED_ACCOUNT_KEY_TYPES = {
    "http_bearer_authentication",
    "http_custom_header_authentication",
    "http_client_certificate_authentication",
}
ALLOWED_ACTIVITIES = {
    "approval_task_rule",
    "bounded_poll",
    "build_json",
    "child_workflow",
    "condition",
    "create_prompt",
    "http_request",
    "json_path_extract",
    "request_approval",
    "result_summary",
}
EXPECTED_NATIVE_ACTIVITY_TYPES = {
    "http_request": "web-service.http_request",
    "create_prompt": "task.prompt_request",
    "condition": "logic.if_else",
    "condition_branch": "logic.condition_block",
    "completed": "logic.completed",
    "request_approval": "task.request_approval",
    "child_workflow": "workflow.sub_workflow",
}
EXPECTED_NATIVE_WORKFLOW_PROPERTY_KEYS = {
    "atomic",
    "delete_workflow_instance",
    "description",
    "display_name",
    "owner",
    "runtime_user",
    "target",
}
EXPECTED_NATIVE_PROPERTY_KEYS = {
    "http_request": {
        "accept",
        "action_timeout",
        "allow_auto_redirect",
        "allow_headers_redirect",
        "body",
        "continue_on_error_status_code",
        "continue_on_failure",
        "description",
        "display_name",
        "method",
        "relative_url",
        "runtime_user",
        "skip_execution",
        "target",
    },
    "create_prompt": {
        "assignee_roles",
        "assignees",
        "continue_on_failure",
        "description",
        "display_name",
        "expiration_date",
        "form_elements",
        "prompt_body",
        "prompt_title",
        "skip_execution",
        "task_owner",
        "task_requestor",
        "wait_for_prompt_response",
    },
    "condition": {
        "conditions",
        "continue_on_failure",
        "description",
        "display_name",
        "skip_execution",
    },
    "condition_branch": {
        "condition",
        "continue_on_failure",
        "display_name",
        "skip_execution",
    },
    "completed": {
        "completion_type",
        "continue_on_failure",
        "description",
        "display_name",
        "skip_execution",
    },
    "request_approval": {
        "approval_choices_holder",
        "approval_title",
        "assignee_roles",
        "body_text",
        "continue_on_failure",
        "description",
        "display_name",
        "due_date",
        "expiration_date",
        "expiration_status",
        "minimum_approvals",
        "priority",
        "skip_execution",
        "task_owner",
        "task_requestor",
        "wait_for_request_approval_response",
    },
    "child_workflow": {
        "atomic",
        "continue_on_failure",
        "description",
        "display_name",
        "input",
        "runtime_user",
        "skip_execution",
        "target",
        "workflow_id",
        "workflow_name",
    },
}
EXPECTED_NATIVE_SERIALIZATION_TOPOLOGY = {
    "root_action_sequence": [
        "http_request",
        "create_prompt",
        "condition",
        "request_approval",
        "child_workflow",
    ],
    "condition": {
        "children_key": "blocks",
        "branch_activity": "condition_branch",
        "branch_actions_key": "actions",
        "terminal_activity": "completed",
    },
    "child_workflow": {
        "dependency_key": "dependent_workflows",
        "embedded_workflows": False,
    },
}


@dataclass(frozen=True)
class PackageIssue:
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


def load_workflow_package(path: Path | str) -> Dict[str, Any]:
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Workflow package must be a YAML object")
    return document


def _canonical_hash(document: Mapping[str, Any]) -> str:
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _issue(
    issues: List[PackageIssue], code: str, path: str, message: str, severity: str = "error"
) -> None:
    issues.append(PackageIssue(code, path, message, severity))


def _workflow_map(document: Mapping[str, Any]) -> Dict[str, Mapping[str, Any]]:
    workflows = document.get("workflows") or []
    if not isinstance(workflows, list):
        return {}
    return {
        str(item.get("id")): item
        for item in workflows
        if isinstance(item, Mapping) and item.get("id")
    }


def validate_workflow_package(document: Mapping[str, Any]) -> Dict[str, Any]:
    issues: List[PackageIssue] = []
    if str(document.get("schema_version", "")) != "1.1":
        _issue(issues, "schema.version", "$.schema_version", "Expected package schema 1.1")

    package = document.get("package") or {}
    safety = document.get("safety") or {}
    runtime = document.get("runtime") or {}
    if not isinstance(package, Mapping):
        package = {}
        _issue(issues, "package.missing", "$.package", "Package metadata is required")
    if not isinstance(safety, Mapping):
        safety = {}
        _issue(issues, "safety.missing", "$.safety", "Safety policy is required")
    if not isinstance(runtime, Mapping):
        runtime = {}
        _issue(issues, "runtime.missing", "$.runtime", "Runtime policy is required")

    if package.get("serialization_state") != "build_spec_complete":
        _issue(
            issues,
            "serialization.state",
            "$.package.serialization_state",
            "Portable build specification must be complete before tenant assembly",
        )
    importable_exports = package.get("importable_exports_present") is True
    native_exports = package.get("native_exports") or []
    production_flag = package.get("production_ready") is True
    exchange_flag = package.get("exchange_publishable") is True
    apply_enabled = safety.get("apply_enabled") is True
    if production_flag and not importable_exports:
        _issue(
            issues,
            "release.importable_exports_missing",
            "$.package.production_ready",
            "Package cannot be production-ready without validated native exports",
        )
    if importable_exports and (not isinstance(native_exports, list) or not native_exports):
        _issue(
            issues,
            "release.native_export_inventory",
            "$.package.native_exports",
            "Importable-export claim requires an inventory of tenant-native exports",
        )
    if production_flag and not apply_enabled:
        _issue(
            issues,
            "release.apply_disabled",
            "$.package.production_ready",
            "Package cannot be production-ready while apply is disabled",
        )
    if exchange_flag and not production_flag:
        _issue(
            issues,
            "release.exchange_before_production",
            "$.package.exchange_publishable",
            "Exchange publication requires production readiness",
        )

    native_serialization = document.get("native_serialization") or {}
    if not isinstance(native_serialization, Mapping):
        native_serialization = {}
        _issue(
            issues,
            "native.serialization_type",
            "$.native_serialization",
            "Native serialization metadata must be an object",
        )
    if native_serialization.get("contains_property_values") is not False:
        _issue(
            issues,
            "native.property_values",
            "$.native_serialization.contains_property_values",
            "The committed native fingerprint must never contain property values",
        )
    if native_serialization.get("configured_properties_complete") is not True:
        _issue(
            issues,
            "native.configured_properties_incomplete",
            "$.native_serialization.configured_properties_complete",
            "Configured native activity, logic, and child-workflow schemas must be pinned",
        )
    capture_hash = native_serialization.get("capture_export_sha256")
    if not isinstance(capture_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", capture_hash):
        _issue(
            issues,
            "native.capture_hash",
            "$.native_serialization.capture_export_sha256",
            "Native capture requires a lowercase SHA-256 provenance hash",
        )
    native_workflow = native_serialization.get("workflow") or {}
    if not isinstance(native_workflow, Mapping):
        native_workflow = {}
        _issue(
            issues,
            "native.workflow_type",
            "$.native_serialization.workflow",
            "Native workflow serialization metadata must be an object",
        )
    elif native_workflow.get("type") != "generic.workflow":
        _issue(
            issues,
            "native.workflow_type",
            "$.native_serialization.workflow.type",
            "Native workflow type must come from a genuine generic.workflow export",
        )
    if native_workflow.get("unique_name_prefix") != "definition_workflow_":
        _issue(
            issues,
            "native.workflow_identifier",
            "$.native_serialization.workflow.unique_name_prefix",
            "Native workflow identifier prefix must be definition_workflow_",
        )
    workflow_property_keys = native_workflow.get("observed_property_keys")
    if (
        not isinstance(workflow_property_keys, list)
        or any(not isinstance(key, str) or not key for key in workflow_property_keys)
        or set(workflow_property_keys) != EXPECTED_NATIVE_WORKFLOW_PROPERTY_KEYS
    ):
        _issue(
            issues,
            "native.workflow_property_keys",
            "$.native_serialization.workflow.observed_property_keys",
            "Configured native workflow property-key inventory does not match the captured schema",
        )
    native_activities = native_serialization.get("activities") or {}
    if not isinstance(native_activities, Mapping):
        native_activities = {}
    if set(native_activities) != set(EXPECTED_NATIVE_ACTIVITY_TYPES):
        _issue(
            issues,
            "native.activity_inventory",
            "$.native_serialization.activities",
            "Configured native activity inventory must match the pinned capture",
        )
    for portable_type, expected_type in EXPECTED_NATIVE_ACTIVITY_TYPES.items():
        path = "$.native_serialization.activities.{}".format(portable_type)
        activity = native_activities.get(portable_type) or {}
        if not isinstance(activity, Mapping) or activity.get("type") != expected_type:
            _issue(
                issues,
                "native.activity_type",
                path + ".type",
                "Expected captured tenant-native type {!r}".format(expected_type),
            )
            continue
        if activity.get("unique_name_prefix") != "definition_activity_":
            _issue(
                issues,
                "native.activity_identifier",
                path + ".unique_name_prefix",
                "Native activity identifier prefix must be definition_activity_",
            )
        observed_keys = activity.get("observed_property_keys")
        if (
            not isinstance(observed_keys, list)
            or any(not isinstance(key, str) or not key for key in observed_keys)
            or set(observed_keys) != EXPECTED_NATIVE_PROPERTY_KEYS[portable_type]
        ):
            _issue(
                issues,
                "native.property_keys",
                path + ".observed_property_keys",
                "Configured native activity property-key inventory does not match the captured schema",
            )

    if native_serialization.get("serialization_topology") != EXPECTED_NATIVE_SERIALIZATION_TOPOLOGY:
        _issue(
            issues,
            "native.serialization_topology",
            "$.native_serialization.serialization_topology",
            "Native condition nesting and child-workflow dependency serialization must match the capture",
        )

    targets = document.get("targets") or []
    role_to_target: Dict[str, Mapping[str, Any]] = {}
    bindings: set[str] = set()
    if not isinstance(targets, list):
        _issue(issues, "targets.type", "$.targets", "Targets must be a list")
        targets = []
    for index, target in enumerate(targets):
        path = "$.targets[{}]".format(index)
        if not isinstance(target, Mapping):
            _issue(issues, "target.type", path, "Target must be an object")
            continue
        role = str(target.get("role", ""))
        binding = str(target.get("binding", ""))
        if role in role_to_target:
            _issue(issues, "target.role_duplicate", path + ".role", "Target role is duplicated")
        role_to_target[role] = target
        if binding in bindings or not binding.startswith("target://"):
            _issue(
                issues,
                "target.binding",
                path + ".binding",
                "Target binding must be a unique target:// alias",
            )
        bindings.add(binding)
        if target.get("type") != "http_endpoint":
            _issue(issues, "target.type", path + ".type", "Only HTTP Endpoint targets are allowed")
        if target.get("account_key_type") not in ALLOWED_ACCOUNT_KEY_TYPES:
            _issue(
                issues,
                "target.account_key_type",
                path + ".account_key_type",
                "Use a supported HTTP account-key authentication type",
            )
        if target.get("trusted_https_required") is not True:
            _issue(
                issues,
                "target.trusted_https",
                path + ".trusted_https_required",
                "Trusted HTTPS must be required",
            )
    if set(role_to_target) != EXPECTED_ROLES:
        _issue(
            issues,
            "target.role_set",
            "$.targets",
            "Exactly planner, approver, operator, and auditor targets are required",
        )

    operations = document.get("api_operations") or {}
    if not isinstance(operations, Mapping):
        _issue(issues, "operations.type", "$.api_operations", "API operations must be an object")
        operations = {}
    for name, operation in operations.items():
        path = "$.api_operations.{}".format(name)
        if not isinstance(operation, Mapping):
            _issue(issues, "operation.type", path, "Operation must be an object")
            continue
        request_path = str(operation.get("path", ""))
        if (
            not request_path.startswith("/v1/workflow-actions/")
            or "://" in request_path
            or "$" in request_path
            or "{" in request_path
        ):
            _issue(
                issues,
                "operation.path",
                path + ".path",
                "HTTP Request must use a fixed relative /v1/workflow-actions/ path",
            )
        if operation.get("method") != "POST":
            _issue(issues, "operation.method", path + ".method", "Operation must use POST")
        if operation.get("role") not in role_to_target:
            _issue(issues, "operation.role", path + ".role", "Operation role has no target")
        statuses = operation.get("success_statuses") or []
        if not isinstance(statuses, list) or not statuses or any(
            not isinstance(status, int) or status < 200 or status > 299 for status in statuses
        ):
            _issue(
                issues,
                "operation.success_statuses",
                path + ".success_statuses",
                "At least one explicit 2xx success status is required",
            )

    workflows = _workflow_map(document)
    required_workflows = {
        "parent",
        "validate_and_plan",
        "request_approval",
        "start_dry_run",
        "start_apply",
        "export_evidence",
    }
    if not required_workflows.issubset(workflows):
        _issue(
            issues,
            "workflow.required",
            "$.workflows",
            "Missing required workflow IDs: {}".format(
                sorted(required_workflows - set(workflows))
            ),
        )

    request_timeout_value = runtime.get("request_timeout_seconds")
    request_timeout_valid = (
        isinstance(request_timeout_value, int)
        and not isinstance(request_timeout_value, bool)
        and request_timeout_value > 0
    )
    if not request_timeout_valid:
        _issue(
            issues,
            "runtime.request_timeout",
            "$.runtime.request_timeout_seconds",
            "Request timeout must be a positive integer",
        )
    request_timeout = request_timeout_value if request_timeout_valid else 0

    max_parent_runtime_value = runtime.get("max_parent_runtime_seconds")
    max_parent_runtime_valid = (
        isinstance(max_parent_runtime_value, int)
        and not isinstance(max_parent_runtime_value, bool)
        and max_parent_runtime_value > 0
    )
    if not max_parent_runtime_valid:
        _issue(
            issues,
            "runtime.parent_budget",
            "$.runtime.max_parent_runtime_seconds",
            "Parent runtime budget must be a positive integer",
        )
    max_parent_runtime = max_parent_runtime_value if max_parent_runtime_valid else 0
    for workflow_id, workflow in workflows.items():
        workflow_path = "$.workflows[{}]".format(workflow_id)
        if not str(workflow.get("description", "")).strip():
            _issue(
                issues,
                "workflow.description",
                workflow_path + ".description",
                "Workflow description is required",
            )
        target_role = workflow.get("target_role")
        if workflow.get("kind") == "child" and target_role not in EXPECTED_ROLES:
            _issue(
                issues,
                "workflow.target_role",
                workflow_path + ".target_role",
                "Child workflow requires one separated target role",
            )
        seen_steps: set[str] = set()
        steps = workflow.get("steps") or []
        if not isinstance(steps, list):
            _issue(issues, "workflow.steps", workflow_path + ".steps", "Steps must be a list")
            continue
        for index, step in enumerate(steps):
            step_path = "{}.steps[{}]".format(workflow_path, index)
            if not isinstance(step, Mapping):
                _issue(issues, "step.type", step_path, "Step must be an object")
                continue
            step_id = str(step.get("id", ""))
            if not step_id or step_id in seen_steps:
                _issue(issues, "step.id", step_path + ".id", "Step ID must be present and unique")
            seen_steps.add(step_id)
            activity = str(step.get("activity", ""))
            if activity not in ALLOWED_ACTIVITIES:
                _issue(issues, "step.activity", step_path + ".activity", "Unsupported activity")
            if activity == "http_request":
                operation_name = str(step.get("operation", ""))
                operation = operations.get(operation_name)
                if not isinstance(operation, Mapping):
                    _issue(
                        issues,
                        "step.operation",
                        step_path + ".operation",
                        "HTTP step references an unknown operation",
                    )
                elif operation.get("role") != target_role:
                    _issue(
                        issues,
                        "step.role_mismatch",
                        step_path + ".operation",
                        "HTTP operation role does not match the child target role",
                    )
                if step.get("continue_on_http_error") is not True:
                    _issue(
                        issues,
                        "step.http_error_handling",
                        step_path + ".continue_on_http_error",
                        "HTTP errors must continue into an explicit status condition",
                    )
                next_step = steps[index + 1] if index + 1 < len(steps) else None
                if not isinstance(next_step, Mapping) or next_step.get("activity") != "condition" or next_step.get("rule") != "http_status_not_200":
                    _issue(
                        issues,
                        "step.http_status_branch",
                        step_path,
                        "HTTP Request must be followed immediately by an exact status condition",
                    )
            if activity == "bounded_poll":
                operation_name = str(step.get("operation", ""))
                operation = operations.get(operation_name)
                if not isinstance(operation, Mapping):
                    _issue(
                        issues,
                        "step.operation",
                        step_path + ".operation",
                        "Poll step references an unknown status operation",
                    )
                elif operation.get("role") != target_role:
                    _issue(
                        issues,
                        "step.role_mismatch",
                        step_path + ".operation",
                        "Poll operation role does not match the child target role",
                    )
                attempts = int(step.get("max_attempts", 0) or 0)
                interval = int(step.get("interval_seconds", 0) or 0)
                if attempts < 1 or attempts > 100 or interval < 5 or interval > 60:
                    _issue(
                        issues,
                        "poll.bounds",
                        step_path,
                        "Polling must use 1-100 attempts and a 5-60 second interval",
                    )
                if (
                    request_timeout_valid
                    and max_parent_runtime_valid
                    and attempts * (interval + request_timeout) > max_parent_runtime
                ):
                    _issue(
                        issues,
                        "poll.runtime",
                        step_path,
                        "Worst-case polling exceeds the parent runtime budget",
                    )
                if not step.get("terminal_statuses"):
                    _issue(
                        issues,
                        "poll.terminal_statuses",
                        step_path + ".terminal_statuses",
                        "Bounded poll requires terminal statuses",
                    )

    parent = workflows.get("parent") or {}
    parent_ids = [step.get("id") for step in parent.get("steps", []) if isinstance(step, Mapping)]
    sequence = ["plan", "approval", "dry_run", "apply", "evidence"]
    if any(item not in parent_ids for item in sequence) or [parent_ids.index(item) for item in sequence] != sorted(
        parent_ids.index(item) for item in sequence if item in parent_ids
    ):
        _issue(
            issues,
            "workflow.parent_sequence",
            "$.workflows[parent].steps",
            "Parent must order plan, approval, dry run, apply, then evidence",
        )

    approval = workflows.get("request_approval") or {}
    approval_steps = approval.get("steps") or []
    native_approval = next(
        (
            step
            for step in approval_steps
            if isinstance(step, Mapping) and step.get("activity") == "request_approval"
        ),
        None,
    )
    if not native_approval or int(native_approval.get("minimum_approvals", 0) or 0) < 1:
        _issue(
            issues,
            "approval.native_task",
            "$.workflows[request_approval]",
            "A native Meraki approval task with at least one approval is required",
        )
    elif native_approval.get("require_comment") is not True:
        _issue(
            issues,
            "approval.comment",
            "$.workflows[request_approval]",
            "Approval comment is required",
        )

    apply_workflow = workflows.get("start_apply") or {}
    if not apply_enabled:
        if apply_workflow.get("enabled") is not False:
            _issue(
                issues,
                "apply.workflow_enabled",
                "$.workflows[start_apply].enabled",
                "Apply workflow must remain disabled while package apply is disabled",
            )
        for index, step in enumerate(apply_workflow.get("steps") or []):
            if isinstance(step, Mapping) and step.get("activity") in {"http_request", "bounded_poll"}:
                if step.get("enabled") is not False:
                    _issue(
                        issues,
                        "apply.executable_step",
                        "$.workflows[start_apply].steps[{}]".format(index),
                        "Executable apply steps must also be disabled",
                    )
    else:
        if apply_workflow.get("enabled") is not True:
            _issue(
                issues,
                "apply.workflow_disabled",
                "$.workflows[start_apply].enabled",
                "Enabled package apply requires an enabled apply workflow",
            )
        for index, step in enumerate(apply_workflow.get("steps") or []):
            if isinstance(step, Mapping) and step.get("activity") in {"http_request", "bounded_poll"}:
                if step.get("enabled") is not True:
                    _issue(
                        issues,
                        "apply.executable_step_disabled",
                        "$.workflows[start_apply].steps[{}]".format(index),
                        "Enabled package apply requires enabled executable steps",
                    )

    rendered = json.dumps(document, sort_keys=True).lower()
    for marker, code in (
        ("ngrok", "transport.ngrok"),
        ("verify=false", "transport.tls_disabled"),
        ("/api/v2/", "api.legacy_v2"),
    ):
        if marker in rendered:
            _issue(issues, code, "$", "Forbidden production marker found: {}".format(marker))
    if safety.get("allow_absolute_request_urls") is not False:
        _issue(
            issues,
            "transport.absolute_urls",
            "$.safety.allow_absolute_request_urls",
            "Absolute request URLs must be forbidden",
        )
    if safety.get("allow_redirects") is not False or safety.get("allow_sensitive_header_redirects") is not False:
        _issue(
            issues,
            "transport.redirects",
            "$.safety",
            "HTTP and sensitive-header redirects must be forbidden",
        )

    errors = [item for item in issues if item.severity == "error"]
    warnings = [item for item in issues if item.severity == "warning"]
    production_ready = not errors and production_flag and importable_exports and apply_enabled
    return {
        "manifest_hash": _canonical_hash(document),
        "safe_to_build": not errors,
        "production_ready": production_ready,
        "importable_exports_present": importable_exports,
        "apply_enabled": apply_enabled,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [item.as_dict() for item in issues],
    }


def compile_workflow_build_plan(document: Mapping[str, Any]) -> Dict[str, Any]:
    validation = validate_workflow_package(document)
    if not validation["safe_to_build"]:
        raise ValueError("Invalid Meraki workflow package")
    operations = document["api_operations"]
    targets = {item["role"]: item for item in document["targets"]}
    compiled: List[Dict[str, Any]] = []
    for workflow in document["workflows"]:
        steps: List[Dict[str, Any]] = []
        for source in workflow.get("steps", []):
            step = dict(source)
            if step.get("activity") in {"http_request", "bounded_poll"}:
                operation = dict(operations[step["operation"]])
                role = operation["role"]
                step["request"] = {
                    "method": operation["method"],
                    "relative_url": operation["path"],
                    "success_statuses": operation["success_statuses"],
                    "content_type": "application/json",
                    "accept": "application/json",
                    "target_binding": targets[role]["binding"],
                    "allow_auto_redirect": False,
                    "allow_sensitive_headers_redirect": False,
                }
            if step.get("activity") == "bounded_poll" and step.get("terminal_statuses") == "runtime.terminal_statuses":
                step["terminal_statuses"] = list(document["runtime"]["terminal_statuses"])
            steps.append(step)
        compiled.append(
            {
                "id": workflow["id"],
                "name": workflow["name"],
                "kind": workflow["kind"],
                "enabled": workflow.get("enabled", True),
                "description": workflow["description"],
                "steps": steps,
            }
        )
    result = {
        "build_plan_schema_version": "1.0",
        "package_id": document["package"]["id"],
        "package_version": document["package"]["version"],
        "manifest_hash": validation["manifest_hash"],
        "native_export_required": True,
        "credentials_included": False,
        "native_serialization": {
            "capture_export_sha256": document["native_serialization"]["capture_export_sha256"],
            "configured_properties_complete": document["native_serialization"].get(
                "configured_properties_complete", False
            ),
            "workflow_type": document["native_serialization"]["workflow"]["type"],
            "workflow_property_keys": sorted(
                document["native_serialization"]["workflow"]["observed_property_keys"]
            ),
            "activity_types": {
                name: item["type"]
                for name, item in sorted(
                    document["native_serialization"]["activities"].items()
                )
            },
            "activity_property_keys": {
                name: sorted(item["observed_property_keys"])
                for name, item in sorted(
                    document["native_serialization"]["activities"].items()
                )
            },
            "serialization_topology": document["native_serialization"][
                "serialization_topology"
            ],
        },
        "workflows": compiled,
    }
    result["build_plan_hash"] = _canonical_hash(result)
    return result


def workflow_operation_matrix(document: Mapping[str, Any]) -> List[Dict[str, Any]]:
    operations = document.get("api_operations") or {}
    matrix: List[Dict[str, Any]] = []
    for workflow in document.get("workflows") or []:
        if not isinstance(workflow, Mapping):
            continue
        for step in workflow.get("steps") or []:
            if not isinstance(step, Mapping) or step.get("activity") not in {
                "http_request",
                "bounded_poll",
            }:
                continue
            operation = operations.get(step.get("operation")) or {}
            matrix.append(
                {
                    "workflow_id": workflow.get("id"),
                    "step_id": step.get("id"),
                    "operation": step.get("operation"),
                    "method": operation.get("method"),
                    "path": operation.get("path"),
                    "role": operation.get("role"),
                    "enabled": workflow.get("enabled", True) and step.get("enabled", True),
                }
            )
    return matrix
