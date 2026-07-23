# Meraki Native SDA Workflow — Live Build Status

Date: 2026-07-23  
Tenant/network: CiscoWLAN / SJC23-SDA  
Safety state: planning and simulation only; Apply remains disabled.

## Completed in the Meraki development tenant

All four native workflows below show `Validated` in Meraki Dashboard:

| Workflow | Meraki workflow ID | Implemented behavior |
| --- | --- | --- |
| SDA Fabric - Validate and Plan | `02X844LMD049N0MPwXuLX9NkkYa8lnZtRmK` | Sends versioned user requirements to the Planner endpoint, rejects HTTP failure, extracts the immutable intent/plan/artifact contract, and exposes eight workflow outputs. |
| SDA Fabric - Request Approval | `02X8XU5DM3D0R5EBWrSPxNpfn0sC2CxMbar` | Native Meraki Administrator approval, one approval required, Approve/Reject choices, explicit review instructions, and 72-hour due/expiration limits. |
| SDA Fabric - Start Dry Run | `02X8XYX9GND810lPZxtIygI3DZ1Ba8PNDnY` | Requires `planId` and `idempotencyKey`, requires a runtime-selected HTTP Endpoint, creates an idempotent `dry_run`, extracts `runId`, and invokes synchronous dry-run processing. |
| SDA Fabric - Export Evidence | `02X8YMDJV4RAJ2Q3nqApl74Fd9lkHoEhXiV` | Requires `runId`, requires a runtime-selected HTTP Endpoint, and requests the redacted evidence/audit-chain contract. Redirects are disabled. |

## Live acceptance already completed

`SDA Fabric - Validate and Plan` was run successfully with:

- idempotency key: `meraki-plan-poc-20260723-004`
- status: `plan_ready`
- intent ID: `intent_5c190e795331e8e7`
- plan ID: `plan_c03b00c69a484048`
- intent hash: `5c190e795331e8e7afe33e15fc5482f58afec3137d558fc2638675b14f54cd5c`
- plan hash: `c03b00c69a484048dfbc815b7214c25856b1fb05cf0d8ab03f43adbd7c9b24a9`
- artifact hash: `6f96d2750c270904b45e5c1981d6c279db3e9a5d0647538218b6e8e761031252`
- blocking requirements: `[]`

The run populated all eight mapped outputs:

`succeeded`, `status`, `intentId`, `intentHash`, `planId`, `planHash`, `artifactHash`, and `blockingRequirements`.

No switch configuration, ISE object, or Apply operation was executed.

## Intentionally not executed yet

The following live runs require role-specific Meraki HTTP Endpoint targets and tokens:

1. Operator target for `SDA Fabric - Start Dry Run`.
2. Auditor target for `SDA Fabric - Export Evidence`.
3. Approver callback target for recording the native approval decision in the orchestrator.

The Planner token must not be reused for these roles. The workflows are built so the target is selected at workflow start, which prevents a hard-coded cross-role credential.

## Remaining production work

1. Create the Operator, Approver, and Auditor role-specific targets/account keys.
2. Run the native approval acceptance test and verify the approver identity, decision, expiry, and change reference are persisted.
3. Run the complete dry-run acceptance path and verify the returned `runId`, terminal status, evidence hash, and append-only audit-chain result.
4. Assemble and validate the parent workflow that orders Plan → Approval → Dry Run → Evidence. Keep the Apply child absent or disabled.
5. Export the four tenant-native JSON definitions through **More Actions → Share → Export as JSON**, run the structural auditor, and keep raw tenant exports uncommitted.
6. Complete the documented IOS XE, multicast, LISP Pub/Sub, reconciliation, ISE ERS, and SXP hardware/API acceptance matrices before clearing any production blocker.
7. Only after all blockers are closed: add the separately approved Apply child, maintenance-window gate, plan/artifact hash equality gates, rollback acceptance, and production change authorization.

## Current release posture

- Deterministic planner/orchestrator software: complete and independently reviewed.
- Meraki native child workflows: built and validated.
- Plan-only live test: passed.
- Role-separated dry-run/evidence live test: pending target creation.
- Parent orchestration: pending.
- Hardware/API acceptance: pending by design.
- Production Apply: disabled.
