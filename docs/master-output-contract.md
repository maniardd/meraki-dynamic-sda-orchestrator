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

## Development-tenant acceptance

The native output contract was assembled and accepted in the development
tenant on 2026-07-24. `SDA Fabric - Plan, Approve, and Execute v4` declares and
maps all fourteen contract outputs across the planner, Approval v2, Dry Run v4,
and Evidence v3 children. The legacy approval and dry-run children remain in
the graph only as explicitly skipped compatibility nodes; Apply is absent.

The first acceptance attempt failed closed because Evidence v3 still referenced
the skipped Dry Run v3 `runId`. No device or ISE write occurred. The stale
reference was cleared, Evidence v3 was bound only to Dry Run v4 `runId`, and
the corrected zero-write run completed successfully in 21.7 seconds. The
hash-bound record is
`acceptance/evidence/meraki-master-output-accepted-20260724.json`.

This proves the development-tenant assembly and output propagation contract.
It does not make tenant-generated exports portable, clear
`meraki.native_export_import`, or authorize Apply. Duplicate-tenant import and
the remaining hardware, ISE, ingress, recovery, observability, and security
acceptance gates remain pending.
