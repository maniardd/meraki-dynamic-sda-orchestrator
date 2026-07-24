"""Fail-closed validation for production acceptance evidence.

The registry is deliberately outside the device execution path.  It gives
operators and reviewers one deterministic place to prove whether all release
gates and independent sign-offs are complete.  It cannot enable Apply.
"""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional, Sequence

import jsonschema
import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCHEMA = ROOT / "schemas" / "production-acceptance.schema.json"

_SECRET_KEY_FRAGMENTS = (
    "api_key",
    "authorization",
    "bearer",
    "credential",
    "password",
    "private_key",
    "secret_value",
    "token",
)
_ALLOWED_CONTROL_KEYS = {
    "apply_authorization_requested",
}


def load_acceptance_registry(path: Path | str) -> Dict[str, Any]:
    """Load one YAML or JSON registry and require an object root."""

    source = Path(path)
    text = source.read_text(encoding="utf-8")
    if source.suffix.lower() == ".json":
        document = json.loads(text)
    else:
        document = yaml.safe_load(text)
    if not isinstance(document, dict):
        raise ValueError("Production acceptance registry must be an object")
    return document


def _canonical_hash(document: Mapping[str, Any]) -> str:
    payload = json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _issue(
    issues: List[Dict[str, str]], code: str, path: str, message: str
) -> None:
    issues.append({"code": code, "path": path, "message": message})


def _walk_secret_keys(
    value: Any, issues: List[Dict[str, str]], path: str = "$"
) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if (
                normalized not in _ALLOWED_CONTROL_KEYS
                and any(fragment in normalized for fragment in _SECRET_KEY_FRAGMENTS)
            ):
                _issue(
                    issues,
                    "registry.secret_key",
                    f"{path}.{key}",
                    "Acceptance registries may contain references and hashes, not secret-bearing fields",
                )
            _walk_secret_keys(child, issues, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_secret_keys(child, issues, f"{path}[{index}]")


def _detect_dependency_cycles(
    gates: Mapping[str, Mapping[str, Any]],
    issues: List[Dict[str, str]],
) -> None:
    state: Dict[str, int] = {}

    def visit(gate_id: str, stack: List[str]) -> None:
        marker = state.get(gate_id, 0)
        if marker == 2:
            return
        if marker == 1:
            cycle_start = stack.index(gate_id) if gate_id in stack else 0
            cycle = stack[cycle_start:] + [gate_id]
            _issue(
                issues,
                "gate.dependency_cycle",
                "$.gates",
                "Dependency cycle: " + " -> ".join(cycle),
            )
            return
        state[gate_id] = 1
        stack.append(gate_id)
        for dependency in gates[gate_id].get("dependencies") or []:
            if dependency in gates:
                visit(str(dependency), stack)
        stack.pop()
        state[gate_id] = 2

    for gate_id in gates:
        if state.get(gate_id, 0) == 0:
            visit(gate_id, [])


def _workflow_apply_state(
    workflow_manifest: Optional[Mapping[str, Any]],
) -> Dict[str, bool]:
    if workflow_manifest is None:
        return {
            "manifest_supplied": False,
            "apply_enabled": False,
            "apply_workflow_enabled": False,
            "apply_executable_steps_enabled": False,
        }
    safety = workflow_manifest.get("safety") or {}
    apply_enabled = safety.get("apply_enabled") is True
    apply_workflow_enabled = False
    executable_steps_enabled = False
    for workflow in workflow_manifest.get("workflows") or []:
        if not isinstance(workflow, Mapping) or workflow.get("id") != "start_apply":
            continue
        apply_workflow_enabled = workflow.get("enabled") is True
        for step in workflow.get("steps") or []:
            if (
                isinstance(step, Mapping)
                and step.get("activity") in {"http_request", "bounded_poll"}
                and step.get("enabled") is True
            ):
                executable_steps_enabled = True
    return {
        "manifest_supplied": True,
        "apply_enabled": apply_enabled,
        "apply_workflow_enabled": apply_workflow_enabled,
        "apply_executable_steps_enabled": executable_steps_enabled,
    }


def validate_production_acceptance(
    document: Mapping[str, Any],
    *,
    workflow_manifest: Optional[Mapping[str, Any]] = None,
    schema_path: Path | str = DEFAULT_SCHEMA,
    evidence_root: Path | str = ROOT,
) -> Dict[str, Any]:
    """Validate structure, dependencies, evidence, sign-offs, and Apply locks."""

    registry = deepcopy(dict(document))
    issues: List[Dict[str, str]] = []
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema, format_checker=jsonschema.FormatChecker()
    )
    for error in sorted(
        validator.iter_errors(registry),
        key=lambda item: "/".join(str(part) for part in item.absolute_path),
    ):
        location = "$"
        for part in error.absolute_path:
            location += f"[{part}]" if isinstance(part, int) else f".{part}"
        _issue(issues, "registry.schema", location, error.message)

    _walk_secret_keys(registry, issues)

    gates_by_id: MutableMapping[str, Mapping[str, Any]] = {}
    evidence_ids: set[str] = set()
    resolved_evidence_root = Path(evidence_root).resolve()
    for index, gate in enumerate(registry.get("gates") or []):
        if not isinstance(gate, Mapping):
            continue
        gate_id = str(gate.get("id", ""))
        gate_path = f"$.gates[{index}]"
        if gate_id in gates_by_id:
            _issue(
                issues,
                "gate.duplicate",
                f"{gate_path}.id",
                f"Duplicate gate id {gate_id}",
            )
        else:
            gates_by_id[gate_id] = gate

        evidence = gate.get("evidence") or []
        for evidence_index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                continue
            evidence_id = str(item.get("id", ""))
            if evidence_id in evidence_ids:
                _issue(
                    issues,
                    "evidence.duplicate",
                    f"{gate_path}.evidence[{evidence_index}].id",
                    f"Duplicate evidence id {evidence_id}",
                )
            evidence_ids.add(evidence_id)
            evidence_ref = str(item.get("ref", ""))
            if evidence_ref.startswith("evidence://"):
                relative_ref = evidence_ref.removeprefix("evidence://")
                candidate_path = (resolved_evidence_root / relative_ref).resolve()
                try:
                    candidate_path.relative_to(resolved_evidence_root)
                except ValueError:
                    _issue(
                        issues,
                        "evidence.path_escape",
                        f"{gate_path}.evidence[{evidence_index}].ref",
                        "Evidence reference escapes the approved repository root",
                    )
                    continue
                if not candidate_path.is_file():
                    _issue(
                        issues,
                        "evidence.missing",
                        f"{gate_path}.evidence[{evidence_index}].ref",
                        "Referenced evidence file does not exist",
                    )
                    continue
                actual_hash = hashlib.sha256(candidate_path.read_bytes()).hexdigest()
                if actual_hash != item.get("sha256"):
                    _issue(
                        issues,
                        "evidence.hash_mismatch",
                        f"{gate_path}.evidence[{evidence_index}].sha256",
                        "Evidence file hash does not match the registry",
                    )

        status = gate.get("status")
        results = [
            item.get("result")
            for item in evidence
            if isinstance(item, Mapping)
        ]
        if status == "passed" and (not results or any(result != "passed" for result in results)):
            _issue(
                issues,
                "gate.passed_without_evidence",
                gate_path,
                "A passed gate requires at least one passed evidence record and no failed evidence",
            )
        if status == "failed" and "failed" not in results:
            _issue(
                issues,
                "gate.failed_without_evidence",
                gate_path,
                "A failed gate requires failed evidence",
            )
        if status == "not_applicable" and not str(gate.get("rationale", "")).strip():
            _issue(
                issues,
                "gate.not_applicable_rationale",
                gate_path,
                "A not-applicable gate requires an explicit rationale",
            )

    for index, gate in enumerate(registry.get("gates") or []):
        if not isinstance(gate, Mapping):
            continue
        gate_id = str(gate.get("id", ""))
        for dependency in gate.get("dependencies") or []:
            if dependency not in gates_by_id:
                _issue(
                    issues,
                    "gate.dependency_missing",
                    f"$.gates[{index}].dependencies",
                    f"{gate_id} references unknown dependency {dependency}",
                )
            elif gate.get("status") == "passed" and gates_by_id[dependency].get("status") != "passed":
                _issue(
                    issues,
                    "gate.dependency_not_passed",
                    f"$.gates[{index}].dependencies",
                    f"Passed gate {gate_id} depends on non-passed gate {dependency}",
                )
    _detect_dependency_cycles(gates_by_id, issues)

    required_roles = set(registry.get("required_signoff_roles") or [])
    signoffs_by_role: Dict[str, Mapping[str, Any]] = {}
    for index, signoff in enumerate(registry.get("signoffs") or []):
        if not isinstance(signoff, Mapping):
            continue
        role = str(signoff.get("role", ""))
        if role in signoffs_by_role:
            _issue(
                issues,
                "signoff.duplicate",
                f"$.signoffs[{index}].role",
                f"Duplicate sign-off role {role}",
            )
        signoffs_by_role[role] = signoff
        if signoff.get("status") in {"approved", "rejected"}:
            required_decision_fields = (
                "principal_ref",
                "decision_at",
                "evidence_ref",
                "evidence_sha256",
            )
            missing = [
                field
                for field in required_decision_fields
                if not str(signoff.get(field, "")).strip()
            ]
            if missing:
                _issue(
                    issues,
                    "signoff.decision_evidence",
                    f"$.signoffs[{index}]",
                    "Decided sign-off is missing: " + ", ".join(missing),
                )

    missing_signoff_records = sorted(required_roles - set(signoffs_by_role))
    for role in missing_signoff_records:
        _issue(
            issues,
            "signoff.missing",
            "$.signoffs",
            f"Missing required sign-off record for {role}",
        )

    required_gates = [
        gate
        for gate in gates_by_id.values()
        if gate.get("required") is True
    ]
    incomplete_gate_ids = sorted(
        str(gate.get("id"))
        for gate in required_gates
        if gate.get("status") != "passed"
    )
    rejected_gate_ids = sorted(
        str(gate.get("id"))
        for gate in required_gates
        if gate.get("status") == "failed"
    )
    pending_signoff_roles = sorted(
        role
        for role in required_roles
        if signoffs_by_role.get(role, {}).get("status") != "approved"
    )
    rejected_signoff_roles = sorted(
        role
        for role, signoff in signoffs_by_role.items()
        if role in required_roles and signoff.get("status") == "rejected"
    )

    workflow_state = _workflow_apply_state(workflow_manifest)
    controls = registry.get("controls") or {}
    requested = controls.get("apply_authorization_requested") is True
    registry_claims_write = (
        controls.get("apply_workflow_present") is True
        or controls.get("device_writes_permitted") is True
    )
    acceptance_complete = (
        not incomplete_gate_ids
        and not pending_signoff_roles
        and not rejected_gate_ids
        and not rejected_signoff_roles
        and not issues
    )

    if requested and not acceptance_complete:
        _issue(
            issues,
            "apply.request_before_acceptance",
            "$.controls.apply_authorization_requested",
            "Apply authorization cannot be requested before every required gate and sign-off passes",
        )
    if registry_claims_write and not acceptance_complete:
        _issue(
            issues,
            "apply.write_before_acceptance",
            "$.controls",
            "Apply presence or device-write permission cannot be claimed before acceptance is complete",
        )
    manifest_executable = any(
        (
            workflow_state["apply_enabled"],
            workflow_state["apply_workflow_enabled"],
            workflow_state["apply_executable_steps_enabled"],
        )
    )
    if manifest_executable and not acceptance_complete:
        _issue(
            issues,
            "apply.manifest_fail_open",
            "$.workflow_manifest",
            "The workflow manifest exposes Apply before production acceptance is complete",
        )

    acceptance_complete = (
        not incomplete_gate_ids
        and not pending_signoff_roles
        and not rejected_gate_ids
        and not rejected_signoff_roles
        and not issues
    )
    ready_for_controlled_enablement = acceptance_complete and requested
    production_ready = (
        ready_for_controlled_enablement
        and registry_claims_write
        and workflow_state["manifest_supplied"]
        and workflow_state["apply_enabled"]
        and workflow_state["apply_workflow_enabled"]
        and workflow_state["apply_executable_steps_enabled"]
    )

    return {
        "registry_valid": not issues,
        "registry_hash": _canonical_hash(registry),
        "acceptance_complete": acceptance_complete,
        "ready_for_controlled_enablement": ready_for_controlled_enablement,
        "production_ready": production_ready,
        "apply_authorization_requested": requested,
        "workflow_apply_state": workflow_state,
        "required_gate_count": len(required_gates),
        "passed_required_gate_count": len(required_gates) - len(incomplete_gate_ids),
        "incomplete_gate_ids": incomplete_gate_ids,
        "rejected_gate_ids": rejected_gate_ids,
        "pending_signoff_roles": pending_signoff_roles,
        "rejected_signoff_roles": rejected_signoff_roles,
        "issues": issues,
        "contains_secret_values": False,
    }


def load_workflow_manifest(path: Path | str) -> Dict[str, Any]:
    document = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("Workflow manifest must be an object")
    return document
