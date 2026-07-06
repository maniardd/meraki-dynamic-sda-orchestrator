"""Authenticated API boundary for fabric intent, planning, and guarded runs."""

from __future__ import annotations

import os
import re
import uuid
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Set

from flask import Flask, g, jsonify, request
import yaml

from .allocator import AllocationError
from .auth import load_hashed_token_identities, match_hashed_principal
from .intent import validate_intent
from .planner import PlanValidationError, create_plan
from .renderer import RenderError, render_configuration
from .simulator import process_dry_run
from .store import (
    ApprovalRequiredError,
    ConflictError,
    ExecutionDisabledError,
    MaintenanceWindowError,
    NotFoundError,
    StateStore,
    StoreError,
    create_state_store,
)


API_VERSION = "0.5.0"
REQUEST_ID = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")


def _boolean_environment(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _environment_hashed_token_identities() -> Dict[str, Dict[str, Any]]:
    path = os.getenv("ORCHESTRATOR_TOKEN_IDENTITIES_FILE", "").strip()
    if not path:
        return {}
    return load_hashed_token_identities(path)


def create_app(config: Optional[Dict[str, Any]] = None) -> Flask:
    app = Flask(__name__)
    default_database = str(Path(app.instance_path) / "sda-orchestrator.sqlite3")
    default_guardrails = str(Path(__file__).resolve().parents[1] / "policy" / "guardrails.yaml")
    app.config.update(
        MAX_CONTENT_LENGTH=1024 * 1024,
        ORCHESTRATOR_TOKEN_HASH_IDENTITIES=_environment_hashed_token_identities(),
        ORCHESTRATOR_DATABASE_PATH=os.getenv("ORCHESTRATOR_DATABASE_PATH", default_database),
        ORCHESTRATOR_DATABASE_URL=os.getenv("ORCHESTRATOR_DATABASE_URL", ""),
        ORCHESTRATOR_EXECUTION_ENABLED=_boolean_environment("ORCHESTRATOR_EXECUTION_ENABLED"),
        ORCHESTRATOR_SECRET_PROVIDER=os.getenv("ORCHESTRATOR_SECRET_PROVIDER", ""),
        ORCHESTRATOR_GUARDRAILS_PATH=os.getenv(
            "ORCHESTRATOR_GUARDRAILS_PATH", default_guardrails
        ),
    )
    if config:
        app.config.update(config)

    store_holder: Dict[str, StateStore] = {}

    def store() -> StateStore:
        if "store" not in store_holder:
            location = str(app.config.get("ORCHESTRATOR_DATABASE_URL") or "").strip()
            if not location:
                location = str(app.config["ORCHESTRATOR_DATABASE_PATH"])
            store_holder["store"] = create_state_store(location)
        return store_holder["store"]

    policy_holder: Dict[str, Mapping[str, Any]] = {}

    def guardrails() -> Mapping[str, Any]:
        if "policy" not in policy_holder:
            policy_path = Path(str(app.config["ORCHESTRATOR_GUARDRAILS_PATH"]))
            document = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
            if not isinstance(document, dict):
                raise StoreError("Guardrail policy must be a YAML object")
            policy_holder["policy"] = document
        return policy_holder["policy"]

    @app.before_request
    def authorize_v1_requests():
        supplied_request_id = request.headers.get("X-Request-ID", "")
        g.request_id = (
            supplied_request_id
            if REQUEST_ID.fullmatch(supplied_request_id)
            else "req_" + uuid.uuid4().hex
        )
        if not (request.path.startswith("/v1/") or request.path == "/ready"):
            return None
        supplied = request.headers.get("Authorization", "")
        prefix = "Bearer "
        candidate = supplied[len(prefix) :] if supplied.startswith(prefix) else ""
        if not candidate:
            return jsonify({"error": "unauthorized"}), 401

        hashed_identities = app.config.get("ORCHESTRATOR_TOKEN_HASH_IDENTITIES") or {}
        principal = match_hashed_principal(candidate, hashed_identities)
        if principal is None:
            configured = bool(hashed_identities)
            return jsonify(
                {
                    "error": "unauthorized" if configured else "service_not_configured",
                    "message": None if configured else "API authentication is not configured",
                }
            ), (401 if configured else 503)
        g.principal = principal
        return None

    @app.after_request
    def security_headers(response):
        response.headers["X-Request-ID"] = str(
            getattr(g, "request_id", "req_" + uuid.uuid4().hex)
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.path.startswith("/v1/") or request.path == "/ready":
            response.headers["Cache-Control"] = "no-store"
        return response

    def require_roles(*required_roles: str):
        required: Set[str] = set(required_roles)

        def decorator(function):
            @wraps(function)
            def wrapped(*args, **kwargs):
                roles = set(g.principal.get("roles", set()))
                if not required.intersection(roles):
                    return jsonify(
                        {
                            "error": "forbidden",
                            "required_any_role": sorted(required),
                        }
                    ), 403
                return function(*args, **kwargs)

            return wrapped

        return decorator

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "request_too_large", "max_bytes": 1024 * 1024}), 413

    @app.errorhandler(NotFoundError)
    def not_found(error):
        return jsonify({"error": "not_found", "message": str(error)}), 404

    @app.errorhandler(ConflictError)
    def conflict(error):
        return jsonify({"error": "conflict", "message": str(error)}), 409

    @app.errorhandler(ApprovalRequiredError)
    def approval_required(error):
        return jsonify({"error": "approval_required", "message": str(error)}), 409

    @app.errorhandler(ExecutionDisabledError)
    def execution_disabled(error):
        return jsonify({"error": "execution_disabled", "message": str(error)}), 409

    @app.errorhandler(MaintenanceWindowError)
    def maintenance_window(error):
        return jsonify({"error": "maintenance_window", "message": str(error)}), 409

    @app.errorhandler(StoreError)
    def store_error(error):
        return jsonify({"error": "state_error", "message": str(error)}), 500

    @app.get("/health")
    def health():
        return jsonify(
            {
                "status": "ok",
                "service": "sda-orchestrator",
                "version": API_VERSION,
                "execution_enabled": bool(app.config["ORCHESTRATOR_EXECUTION_ENABLED"]),
            }
        )

    @app.get("/ready")
    def ready():
        checks: Dict[str, Any] = {
            "authentication": bool(
                app.config.get("ORCHESTRATOR_TOKEN_HASH_IDENTITIES")
            ),
            "guardrails": False,
            "database": False,
            "audit_chain": False,
            "execution_enabled": bool(app.config["ORCHESTRATOR_EXECUTION_ENABLED"]),
        }
        try:
            guardrails()
            checks["guardrails"] = True
            database = store().readiness()
            checks.update(database)
        except Exception:
            app.logger.exception("Readiness check failed")
        if checks["execution_enabled"]:
            checks["secret_provider"] = bool(
                str(app.config.get("ORCHESTRATOR_SECRET_PROVIDER", "")).strip()
            )
        ready_state = all(
            bool(checks.get(name))
            for name in ("authentication", "guardrails", "database", "audit_chain")
        ) and (not checks["execution_enabled"] or bool(checks.get("secret_provider")))
        return jsonify(
            {
                "status": "ready" if ready_state else "not_ready",
                "service": "sda-orchestrator",
                "version": API_VERSION,
                "checks": checks,
            }
        ), (200 if ready_state else 503)

    def json_object():
        if not request.is_json:
            return None, (jsonify({"error": "content_type", "message": "Use application/json"}), 415)
        document = request.get_json(silent=True)
        if not isinstance(document, dict):
            return None, (jsonify({"error": "body", "message": "JSON object required"}), 400)
        return document, None

    @app.post("/v1/intents/validate")
    @require_roles("viewer", "planner", "approver", "operator")
    def validate():
        document, error = json_object()
        if error:
            return error
        result = validate_intent(document)
        return jsonify(result.as_dict()), (200 if result.is_valid else 422)

    @app.post("/v1/plans")
    @require_roles("planner")
    def plan_compatibility():
        """Compatibility endpoint: create a deterministic plan without persistence."""
        document, error = json_object()
        if error:
            return error
        try:
            generated = create_plan(document)
        except PlanValidationError as exc:
            return jsonify(exc.result.as_dict()), 422
        return jsonify(generated), 201

    @app.post("/v1/intents")
    @require_roles("planner")
    def persist_intent():
        document, error = json_object()
        if error:
            return error
        validation = validate_intent(document)
        if not validation.is_valid:
            return jsonify(validation.as_dict()), 422
        record, created = store().save_intent(document, g.principal["actor"])
        record["validation"] = validation.as_dict()
        return jsonify(record), (201 if created else 200)

    @app.post("/v1/workflow-actions/plan")
    @require_roles("planner")
    def workflow_action_plan():
        """Fixed-path Meraki action: validate, persist, plan, and render."""
        document, error = json_object()
        if error:
            return error
        intent_document = document.get("intent")
        reservation = None
        if not isinstance(intent_document, dict):
            requirements = document.get("requirements")
            if not isinstance(requirements, dict):
                return jsonify({"error": "intent_or_requirements_required"}), 422
            try:
                reservation, _created = store().reserve_design(
                    requirements=requirements,
                    policy=guardrails(),
                    idempotency_key=str(document.get("idempotency_key", "")),
                    actor=g.principal["actor"],
                )
            except (AllocationError, ValueError) as exc:
                return jsonify(
                    {
                        "succeeded": False,
                        "status": "allocation_failed",
                        "error": "requirements_unsatisfied",
                        "message": str(exc),
                    }
                ), 422
            intent_document = reservation["intent"]
        validation = validate_intent(intent_document)
        if not validation.is_valid:
            return jsonify(
                {
                    "succeeded": False,
                    "status": "validation_failed",
                    "validation": validation.as_dict(),
                }
            ), 422
        intent_record, _ = store().save_intent(intent_document, g.principal["actor"])
        generated = create_plan(intent_document)
        artifact = render_configuration(intent_document, generated)
        plan_record, _ = store().save_plan(
            intent_record["intent_id"],
            generated,
            g.principal["actor"],
            artifact_hash=artifact["artifact_hash"],
            intent_version=str(intent_document["schema_version"]),
            reservation_id=reservation["reservation_id"] if reservation else None,
        )
        response = {
                "succeeded": True,
                "status": "plan_ready",
                "intent_id": intent_record["intent_id"],
                "intent_hash": intent_record["intent_hash"],
                "plan_id": plan_record["plan_id"],
                "plan_hash": plan_record["plan_hash"],
                "artifact_hash": artifact["artifact_hash"],
                "blocking_requirements": artifact["blocking_requirements"],
                "device_count": len(artifact["devices"]),
                "validation": validation.as_dict(),
            }
        if reservation:
            response.update(
                {
                    "reservation_id": reservation["reservation_id"],
                    "reservation_state": reservation["state"],
                    "requirements_hash": reservation["requirements_hash"],
                    "policy_hash": reservation["policy_hash"],
                    "reservation_hash": reservation["reservation_hash"],
                    "allocation_summary": {
                        "network": len(reservation["network_allocations"]),
                        "scalar": len(reservation["scalar_allocations"]),
                    },
                }
            )
        return jsonify(response), 200

    @app.get("/v1/intents/<intent_id>")
    @require_roles("viewer", "planner", "approver", "operator")
    def get_intent(intent_id: str):
        return jsonify(store().get_intent(intent_id))

    @app.post("/v1/intents/<intent_id>/plans")
    @require_roles("planner")
    def persist_plan(intent_id: str):
        intent_record = store().get_intent(intent_id)
        generated = create_plan(intent_record["document"])
        artifact = render_configuration(intent_record["document"], generated)
        record, created = store().save_plan(
            intent_id,
            generated,
            g.principal["actor"],
            artifact_hash=artifact["artifact_hash"],
            intent_version=str(intent_record["document"]["schema_version"]),
        )
        return jsonify(record), (201 if created else 200)

    @app.get("/v1/plans/<plan_id>")
    @require_roles("viewer", "planner", "approver", "operator")
    def get_plan(plan_id: str):
        return jsonify(store().get_plan(plan_id))

    @app.post("/v1/plans/<plan_id>/render")
    @require_roles("viewer", "planner", "approver", "operator")
    def render_plan(plan_id: str):
        plan_record = store().get_plan(plan_id)
        intent_record = store().get_intent(plan_record["intent_id"])
        try:
            artifact = render_configuration(intent_record["document"], plan_record["document"])
        except RenderError as exc:
            return jsonify({"error": "render_failed", "message": str(exc)}), 422
        return jsonify(artifact), 200

    @app.post("/v1/plans/<plan_id>/approvals")
    @require_roles("approver")
    def approve_plan(plan_id: str):
        document, error = json_object()
        if error:
            return error
        try:
            approval = store().record_approval(
                plan_id=plan_id,
                decision=str(document.get("decision", "")),
                approver=g.principal["actor"],
                change_reference=str(document.get("change_reference", "")),
                expires_at=str(document.get("expires_at", "")),
            )
        except ValueError as exc:
            return jsonify({"error": "invalid_approval", "message": str(exc)}), 422
        return jsonify(approval), 201

    @app.post("/v1/workflow-actions/approve")
    @require_roles("approver")
    def workflow_action_approve():
        document, error = json_object()
        if error:
            return error
        try:
            approval = store().record_approval(
                plan_id=str(document.get("plan_id", "")),
                decision=str(document.get("decision", "")),
                approver=g.principal["actor"],
                change_reference=str(document.get("change_reference", "")),
                expires_at=str(document.get("expires_at", "")),
            )
        except ValueError as exc:
            return jsonify({"error": "invalid_approval", "message": str(exc)}), 422
        return jsonify({"succeeded": True, "status": approval["decision"], **approval}), 200

    @app.post("/v1/runs")
    @require_roles("operator")
    def create_run():
        document, error = json_object()
        if error:
            return error
        window = document.get("maintenance_window") or {}
        if not isinstance(window, dict):
            return jsonify({"error": "invalid_window"}), 422
        try:
            record, created = store().create_run(
                plan_id=str(document.get("plan_id", "")),
                mode=str(document.get("mode", "dry_run")),
                idempotency_key=str(document.get("idempotency_key", "")),
                requested_by=g.principal["actor"],
                execution_enabled=bool(app.config["ORCHESTRATOR_EXECUTION_ENABLED"]),
                maintenance_start=window.get("start"),
                maintenance_end=window.get("end"),
            )
        except ValueError as exc:
            return jsonify({"error": "invalid_run", "message": str(exc)}), 422
        return jsonify(record), (201 if created else 200)

    @app.post("/v1/workflow-actions/run")
    @require_roles("operator")
    def workflow_action_run():
        document, error = json_object()
        if error:
            return error
        window = document.get("maintenance_window") or {}
        if not isinstance(window, dict):
            return jsonify({"error": "invalid_window"}), 422
        try:
            record, _created = store().create_run(
                plan_id=str(document.get("plan_id", "")),
                mode=str(document.get("mode", "dry_run")),
                idempotency_key=str(document.get("idempotency_key", "")),
                requested_by=g.principal["actor"],
                execution_enabled=bool(app.config["ORCHESTRATOR_EXECUTION_ENABLED"]),
                maintenance_start=window.get("start"),
                maintenance_end=window.get("end"),
            )
        except ValueError as exc:
            return jsonify({"error": "invalid_run", "message": str(exc)}), 422
        return jsonify({"succeeded": True, "status": record["status"], "run": record}), 200

    @app.get("/v1/runs/<run_id>")
    @require_roles("viewer", "planner", "approver", "operator")
    def get_run(run_id: str):
        return jsonify(store().get_run(run_id))

    @app.post("/v1/runs/<run_id>/process-dry-run")
    @require_roles("operator")
    def process_run_dry_run(run_id: str):
        run_record = store().get_run(run_id)
        plan_record = store().get_plan(run_record["plan_id"])
        intent_record = store().get_intent(plan_record["intent_id"])
        artifact = render_configuration(intent_record["document"], plan_record["document"])
        result = process_dry_run(store(), run_id, artifact, g.principal["actor"])
        return jsonify(result), 200

    @app.post("/v1/workflow-actions/process-dry-run")
    @require_roles("operator")
    def workflow_action_process_dry_run():
        document, error = json_object()
        if error:
            return error
        run_id = str(document.get("run_id", ""))
        run_record = store().get_run(run_id)
        plan_record = store().get_plan(run_record["plan_id"])
        intent_record = store().get_intent(plan_record["intent_id"])
        artifact = render_configuration(intent_record["document"], plan_record["document"])
        result = process_dry_run(store(), run_id, artifact, g.principal["actor"])
        return jsonify(result), 200

    @app.post("/v1/workflow-actions/status")
    @require_roles("viewer", "planner", "approver", "operator", "auditor")
    def workflow_action_status():
        document, error = json_object()
        if error:
            return error
        run_record = store().get_run(str(document.get("run_id", "")))
        return jsonify({"succeeded": True, "status": run_record["status"], "run": run_record}), 200

    @app.post("/v1/workflow-actions/evidence")
    @require_roles("auditor")
    def workflow_action_evidence():
        document, error = json_object()
        if error:
            return error
        run_id = str(document.get("run_id", ""))
        run_record = store().get_run(run_id)
        return jsonify(
            {
                "succeeded": True,
                "status": run_record["status"],
                "run_id": run_id,
                "chain_valid": store().verify_audit_chain(),
                "evidence": store().run_evidence(run_id),
                "audit": store().audit_events("run", run_id),
            }
        ), 200

    @app.get("/v1/runs/<run_id>/evidence")
    @require_roles("viewer", "planner", "approver", "operator", "auditor")
    def get_run_evidence(run_id: str):
        store().get_run(run_id)
        return jsonify({"run_id": run_id, "evidence": store().run_evidence(run_id)})

    @app.get("/v1/audit/<aggregate_type>/<aggregate_id>")
    @require_roles("viewer", "planner", "approver", "operator", "auditor")
    def get_audit(aggregate_type: str, aggregate_id: str):
        return jsonify(
            {
                "aggregate_type": aggregate_type,
                "aggregate_id": aggregate_id,
                "chain_valid": store().verify_audit_chain(),
                "events": store().audit_events(aggregate_type, aggregate_id),
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    host = os.getenv("ORCHESTRATOR_HOST", "127.0.0.1")
    port = int(os.getenv("ORCHESTRATOR_PORT", "8080"))
    app.run(host=host, port=port, debug=False)
