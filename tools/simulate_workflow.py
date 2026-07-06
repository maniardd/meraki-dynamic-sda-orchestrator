#!/usr/bin/env python3
"""Run the complete approved dry-run lifecycle without contacting devices."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from orchestrator.intent import load_intent, validate_intent
from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration
from orchestrator.simulator import process_dry_run
from orchestrator.store import StateStore


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("intent", help="Fabric intent YAML file")
    parser.add_argument("--database", default=":memory:", help="SQLite state path")
    parser.add_argument("--output", help="Optional *.evidence.json summary")
    args = parser.parse_args()

    intent = load_intent(args.intent)
    validation = validate_intent(intent)
    if not validation.is_valid:
        print(json.dumps(validation.as_dict(), indent=2))
        return 2

    store = StateStore(args.database)
    intent_record, _ = store.save_intent(intent, "simulation-planner")
    plan = create_plan(intent)
    artifact = render_configuration(intent, plan)
    plan_record, _ = store.save_plan(
        intent_record["intent_id"],
        plan,
        "simulation-planner",
        artifact_hash=artifact["artifact_hash"],
        intent_version=str(intent["schema_version"]),
    )
    approval = store.record_approval(
        plan_id=plan_record["plan_id"],
        decision="approved",
        approver="simulation-approver",
        change_reference=str(intent["metadata"].get("change_reference", "SIMULATION")),
        expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
    )
    run, _ = store.create_run(
        plan_id=plan_record["plan_id"],
        mode="dry_run",
        idempotency_key="simulation-{}".format(plan_record["plan_id"]),
        requested_by="simulation-operator",
        execution_enabled=False,
    )
    processed = process_dry_run(store, run["run_id"], artifact, "simulation-worker")

    report = {
        "validation": validation.as_dict(),
        "intent_id": intent_record["intent_id"],
        "intent_hash": intent_record["intent_hash"],
        "plan_id": plan_record["plan_id"],
        "plan_hash": plan_record["plan_hash"],
        "artifact_hash": artifact["artifact_hash"],
        "approval_id": approval["approval_id"],
        "run_id": run["run_id"],
        "run_status": processed["run"]["status"],
        "summary": processed["summary"],
        "audit_chain_valid": store.verify_audit_chain(),
        "device_calls_made": 0,
        "secret_values_resolved": 0,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.output:
        output = Path(args.output)
        if not output.name.endswith(".evidence.json"):
            raise SystemExit("Output filename must end with .evidence.json")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print("Saved simulation evidence to {}".format(output))
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
