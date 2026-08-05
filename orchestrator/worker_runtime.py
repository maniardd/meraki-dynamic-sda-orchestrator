"""Command-line entrypoint for one isolated, explicitly enabled apply run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Mapping

import yaml

from .adapters import IosXeSshAdapter
from .ise import IseErsAdapter
from .renderer import render_configuration
from .secrets import build_secret_provider
from .store import create_state_store
from .worker import TransactionWorker
from .poc_execution import PocExecutionError, authorize_sjc23_poc_execution


class WorkerRuntimeError(RuntimeError):
    pass


def _enabled(name: str, environment: Mapping[str, str]) -> bool:
    return str(environment.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}


def _sjc23_poc_authorization(
    environment: Mapping[str, str],
    intent: Mapping[str, Any],
    plan: Mapping[str, Any],
    artifact: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Return the one blocker a separately-enabled SJC23 worker may consume."""

    if not _enabled("ORCHESTRATOR_SJC23_POC_EXECUTION_ENABLED", environment):
        return {"allowed_blocker_codes": []}
    policy_path = Path(str(environment.get("ORCHESTRATOR_GUARDRAILS_PATH", "")).strip())
    if not policy_path.is_file() or policy_path.is_symlink():
        raise WorkerRuntimeError("SJC23 POC execution requires a regular guardrails file")
    try:
        policy_bytes = policy_path.read_bytes()
        expected_policy_sha256 = str(
            environment.get("ORCHESTRATOR_SJC23_POC_GUARDRAILS_SHA256", "")
        ).strip().lower()
        if (
            len(expected_policy_sha256) != 64
            or expected_policy_sha256 != hashlib.sha256(policy_bytes).hexdigest()
        ):
            raise WorkerRuntimeError("SJC23 POC guardrails hash did not match the approved value")
        policy = yaml.safe_load(policy_bytes.decode("utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise WorkerRuntimeError("SJC23 POC guardrails could not be loaded") from exc
    if not isinstance(policy, Mapping):
        raise WorkerRuntimeError("SJC23 POC guardrails must be an object")
    try:
        return authorize_sjc23_poc_execution(
            intent,
            plan,
            artifact,
            policy,
            {
                "change_reference": str(environment.get("ORCHESTRATOR_SJC23_POC_CHANGE_REFERENCE", "")),
                "plan_hash": str(environment.get("ORCHESTRATOR_SJC23_POC_PLAN_HASH", "")),
                "artifact_hash": str(environment.get("ORCHESTRATOR_SJC23_POC_ARTIFACT_HASH", "")),
            },
        )
    except PocExecutionError as exc:
        raise WorkerRuntimeError("SJC23 POC authorization was rejected") from exc


def process_run(run_id: str, environment: Mapping[str, str]) -> Mapping[str, Any]:
    if not _enabled("ORCHESTRATOR_EXECUTION_ENABLED", environment):
        raise WorkerRuntimeError("API execution enablement is false")
    if not _enabled("ORCHESTRATOR_WORKER_ENABLED", environment):
        raise WorkerRuntimeError("Worker enablement is false")
    database = str(
        environment.get("ORCHESTRATOR_DATABASE_URL")
        or environment.get("ORCHESTRATOR_DATABASE_PATH")
        or ""
    ).strip()
    if not database:
        raise WorkerRuntimeError("A worker database location is required")

    store = create_state_store(database)
    run = store.get_run(run_id)
    if run["mode"] != "apply" or run["status"] != "apply_queued":
        raise WorkerRuntimeError("Only a queued apply run may be processed")
    plan_record = store.get_plan(str(run["plan_id"]))
    intent_record = store.get_intent(str(plan_record["intent_id"]))
    artifact = render_configuration(intent_record["document"], plan_record["document"])
    if artifact["artifact_hash"] != plan_record["artifact_hash"]:
        raise WorkerRuntimeError("Rendered artifact hash changed after approval")

    poc_authorization = _sjc23_poc_authorization(
        environment,
        intent_record["document"],
        plan_record["document"],
        artifact,
    )

    secrets = build_secret_provider(environment)

    def adapter_factory(device):
        return IosXeSshAdapter(device, secrets.resolve_credentials)

    def ise_adapter_factory(manifest):
        return IseErsAdapter(
            manifest,
            secrets.resolve_credentials,
            secrets.resolve_value,
        )

    worker = TransactionWorker(
        store=store,
        adapter_factory=adapter_factory,
        secret_resolver=secrets.resolve_value,
        actor=str(environment.get("ORCHESTRATOR_WORKER_IDENTITY", "sda-worker")),
        ise_adapter_factory=ise_adapter_factory,
    )
    return worker.process_apply(
        run_id,
        intent_record["document"],
        plan_record["document"],
        artifact,
        allowed_blocker_codes=list(poc_authorization["allowed_blocker_codes"]),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    try:
        result = process_run(args.run_id, os.environ)
    except Exception as exc:
        print(json.dumps({"succeeded": False, "error_type": type(exc).__name__}))
        return 2
    print(
        json.dumps(
            {
                "succeeded": bool(result.get("succeeded")),
                "run_id": args.run_id,
                "status": result.get("run", {}).get("status"),
                "rolled_back": bool(result.get("rolled_back")),
            },
            sort_keys=True,
        )
    )
    return 0 if result.get("succeeded") else 1


if __name__ == "__main__":
    raise SystemExit(main())
