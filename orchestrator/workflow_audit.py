"""Static production checks for exported Cisco Workflows JSON packages."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping


@dataclass(frozen=True)
class WorkflowIssue:
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


def _walk_actions(actions: Any, path: str, issues: List[WorkflowIssue]) -> None:
    if not isinstance(actions, list):
        return
    for index, action in enumerate(actions):
        if not isinstance(action, Mapping):
            continue
        action_path = "{}[{}]".format(path, index)
        action_type = str(action.get("type", ""))
        properties = action.get("properties") or {}
        if not isinstance(properties, Mapping):
            properties = {}
        script = str(properties.get("script", ""))
        if action_type == "python3.script":
            if "verify=False" in script.replace(" ", ""):
                issues.append(
                    WorkflowIssue(
                        "transport.tls_verification_disabled",
                        action_path,
                        "Python activity disables TLS certificate verification",
                    )
                )
            if "/api/v2/" in script:
                issues.append(
                    WorkflowIssue(
                        "api.legacy_v2",
                        action_path,
                        "Python activity calls the legacy relay API",
                    )
                )
            if "requests." in script and "Authorization" not in script:
                issues.append(
                    WorkflowIssue(
                        "transport.unauthenticated_request",
                        action_path,
                        "Direct Python HTTP request has no explicit authentication",
                    )
                )
        if properties.get("continue_on_failure") is True and action_type == "python3.script":
            issues.append(
                WorkflowIssue(
                    "failure.continue_python",
                    action_path,
                    "Python activity continues after failure; downstream handling must be proven",
                    "warning",
                )
            )
        _walk_actions(action.get("actions"), action_path + ".actions", issues)
        blocks = action.get("blocks") or []
        if isinstance(blocks, list):
            for block_index, block in enumerate(blocks):
                if isinstance(block, Mapping):
                    _walk_actions(
                        block.get("actions"),
                        "{}.blocks[{}].actions".format(action_path, block_index),
                        issues,
                    )


def audit_workflow_export(document: Mapping[str, Any]) -> Dict[str, Any]:
    workflow = document.get("workflow") if isinstance(document, Mapping) else None
    issues: List[WorkflowIssue] = []
    if not isinstance(workflow, Mapping):
        return {
            "production_ready": False,
            "error_count": 1,
            "warning_count": 0,
            "issues": [
                WorkflowIssue(
                    "workflow.missing", "$", "Export must contain a workflow object"
                ).as_dict()
            ],
        }

    properties = workflow.get("properties") or {}
    target = properties.get("target") if isinstance(properties, Mapping) else None
    if isinstance(target, Mapping) and target.get("no_target") is True:
        issues.append(
            WorkflowIssue(
                "target.missing",
                "$.workflow.properties.target",
                "Production workflow must use a configured target and account key",
            )
        )

    description = properties.get("description") if isinstance(properties, Mapping) else None
    if not isinstance(description, str) or not description.strip():
        issues.append(
            WorkflowIssue(
                "documentation.workflow_description",
                "$.workflow.properties.description",
                "Workflow description is required",
            )
        )

    variables = workflow.get("variables") or []
    for index, variable in enumerate(variables if isinstance(variables, list) else []):
        variable_properties = variable.get("properties") if isinstance(variable, Mapping) else {}
        if not isinstance(variable_properties, Mapping):
            continue
        name = str(variable_properties.get("name", ""))
        description = str(variable_properties.get("description", ""))
        if not description.strip():
            issues.append(
                WorkflowIssue(
                    "documentation.variable_description",
                    "$.workflow.variables[{}]".format(index),
                    "Variable {!r} has no description".format(name),
                )
            )
        value = str(variable_properties.get("value", ""))
        if "ngrok" in value.lower() or "ngrok" in description.lower():
            issues.append(
                WorkflowIssue(
                    "transport.ngrok",
                    "$.workflow.variables[{}]".format(index),
                    "Public development tunnel references are forbidden",
                )
            )

    _walk_actions(workflow.get("actions"), "$.workflow.actions", issues)
    required_markers = {
        "plan": False,
        "approval": False,
        "idempotency": False,
        "evidence": False,
    }
    rendered = str(document).lower()
    for marker in required_markers:
        required_markers[marker] = marker in rendered
        if not required_markers[marker]:
            issues.append(
                WorkflowIssue(
                    "control.{}.missing".format(marker),
                    "$.workflow",
                    "Production workflow does not expose a {} control".format(marker),
                )
            )

    errors = [issue for issue in issues if issue.severity == "error"]
    warnings = [issue for issue in issues if issue.severity == "warning"]
    return {
        "production_ready": not errors,
        "error_count": len(errors),
        "warning_count": len(warnings),
        "issues": [issue.as_dict() for issue in issues],
    }
