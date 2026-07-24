# Master workflow output contract

## Problem observed

The accepted Meraki parent run
`02X9JVCOBMP2K3GOW0AF5Kp89bIudK5YFUT` completed the native
plan -> approval -> dry-run -> evidence sequence successfully. The parent
result, however, did not surface the complete orchestrator result:

- `runId` was empty;
- `dryRunStatus` was empty; and
- evidence retrieval succeeded without returning a useful evidence-chain
  summary to the parent.

This is a tenant assembly/data-flow defect, not a planner or execution defect.
No Apply child was present and no device or ISE write occurred.

## Contract

`workflows/production_workflow_manifest.yaml` version 0.3.0 declares exact,
typed, required outputs for:

1. `validate_and_plan`;
2. `request_approval`;
3. `start_dry_run`;
4. disabled `start_apply`;
5. `export_evidence`; and
6. the integrated `parent`.

Child outputs may only come from a declared authenticated API response body.
Parent outputs may only come from a declared child output. Every binding names
the producing step and exact response JSONPath or child field.

The parent ends with `show_final_result`, a non-blocking result summary carrying
the immutable plan/artifact identity, approval decision, dry-run run ID/status,
blockers, and audit-chain validity. It has no output dependency on Apply.

Bounded polling now uses the exact persisted terminal-state vocabulary. In
particular, `dry_run_blocked` and `dry_run_failed` terminate the dry-run poll
instead of exhausting its attempt budget, and the rollback terminal state is
`rolled_back` (not the previously unreachable `rollback_succeeded` spelling).

## Fail-closed behavior

The package validator rejects:

- missing, reordered, renamed, or extra outputs;
- changed JSONPaths;
- outputs bound to an unknown step;
- child outputs not sourced from `response_body`;
- parent outputs not sourced from `child_output`;
- blocking result prompts; and
- missing or modified master summary fields.

The compiler copies all bindings into the deterministic build plan and therefore
binds any change into `build_plan_hash`.

## Tenant acceptance still required

This change does not fabricate Meraki export JSON and does not modify the live
tenant. An operator must assemble the pinned workflow variables and JSONPath
Query mappings in the development tenant, retain tenant-generated identifiers,
validate and lock the workflows, then run a new zero-write parent acceptance.

Acceptance requires all of these values to be non-empty and mutually
consistent in the parent result:

- plan ID, plan hash, and artifact hash;
- approval ID, approved decision, and expiry;
- orchestrator run ID and `dry_run_succeeded`;
- evidence run ID equal to the dry-run run ID; and
- `evidence_chain_valid:true`.

Apply remains disabled in the package and absent from the live parent.
