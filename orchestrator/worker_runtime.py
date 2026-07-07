"""Command-line entrypoint for one isolated, explicitly enabled apply run."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any, Mapping

from .adapters import IosXeSshAdapter
from .renderer import render_configuration
from .secrets import build_secret_provider
from .store import create_state_store
from .worker import TransactionWorker


class WorkerRuntimeError(RuntimeError):
    pass


def _enabled(name: str, environment: Mapping[str, str]) -> bool:
    return str(environment.get(name, "")).strip().lower() in {"1", "true", "yes", "on"}


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

    secrets = build_secret_provider(environment)

    def adapter_factory(device):
        return IosXeSshAdapter(device, secrets.resolve_credentials)

    worker = TransactionWorker(
        store=store,
        adapter_factory=adapter_factory,
        secret_resolver=secrets.resolve_value,
        actor=str(environment.get("ORCHESTRATOR_WORKER_IDENTITY", "sda-worker")),
    )
    return worker.process_apply(
        run_id,
        intent_record["document"],
        plan_record["document"],
        artifact,
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
