# Meraki Production SDA-Style Workflow Specification

## Purpose

This package turns Meraki Workflows into the operator-facing control plane for
planning, approving, deploying, verifying, and rolling back an IOS XE
LISP/VXLAN fabric with an IS-IS underlay and per-VRF BGP handoffs.

The package replaces the monolithic `SDA Fabric Full Deployment` POC workflow.
The POC export remains evidence and is not overwritten.

## Non-negotiable boundaries

- Workflows owns the operator experience, orchestration, approvals, and run
  monitoring.
- The orchestrator owns intent validation, immutable plans, state, locks,
  device transactions, evidence, and rollback.
- Workflows never stores switch passwords, LISP keys, RADIUS secrets, or
  private keys in ordinary variables or Python activities.
- Workflows uses configured HTTPS targets and account keys. It does not call an
  inline ngrok URL and does not disable TLS verification.
- A plan cannot be approved after its hash changes.
- A single identity cannot plan, approve, and apply a production change.
- Apply remains disabled until the lab rollback acceptance suite passes.

## Required targets and account keys

Create three HTTP Endpoint targets that use the same orchestrator base URL but
different account keys and roles:

| Target | API role | Used by |
|---|---|---|
| SDA Orchestrator - Planner | planner | validation, intent, plan, render |
| SDA Orchestrator - Approver | approver | approval sub-workflow only |
| SDA Orchestrator - Operator | operator | run creation, processing, status |

Create a fourth read-only target for reporting if the platform team requires
separate audit access:

| Target | API role | Used by |
|---|---|---|
| SDA Orchestrator - Auditor | auditor | evidence and audit export |

Each target must use a trusted HTTPS certificate and an HTTP Bearer
Authentication or client-certificate Account Key. Account-key values are
entered directly in Meraki Dashboard and are never exported to Git.

## Package structure

### Parent workflow: SDA Fabric - Plan, Approve, and Execute

Operator-facing workflow. It presents the input wizard, calls the child
workflows, displays the plan summary, requests approval, starts a run, monitors
status, and returns evidence links and final status.

### Child workflow: SDA Fabric - Validate and Plan

1. Accept a fabric-intent JSON document.
2. `POST /v1/workflow-actions/plan` with the intent in the JSON body.
3. Stop and aggregate all validation errors when HTTP status is 422.
4. Capture `intent_id`, `intent_hash`, `plan_id`, and `plan_hash`.
5. Capture artifact hash, device count, phases, command-block counts, and
   blocking requirements.
6. Return a review summary to the parent workflow.

### Child workflow: SDA Fabric - Request Approval

1. Display fabric, environment, plan hash, artifact hash, change reference,
   maintenance window, affected devices, and blockers.
2. Use a Meraki User Task for approve/reject.
3. Require an approval comment.
4. On rejection, call
   `POST /v1/workflow-actions/approve` with `decision=rejected`.
5. On approval, call the same endpoint with `decision=approved`, the external
   change reference, and an expiring `expires_at` value.
6. Return approval ID, approver, decision, and expiry.

The Approver target is available only to this child workflow.

### Child workflow: SDA Fabric - Start Dry Run

1. Generate an idempotency key from the Meraki workflow instance ID and plan
   hash.
2. `POST /v1/workflow-actions/run` with `mode=dry_run`.
3. Capture `run_id`.
4. `POST /v1/workflow-actions/process-dry-run` while the simulator is the active
   worker.
5. Poll `POST /v1/workflow-actions/status` with bounded retries.
6. Retrieve `POST /v1/workflow-actions/evidence`.
7. Return blockers and evidence summary.

### Child workflow: SDA Fabric - Start Apply

This workflow is installed but locked and disabled until the acceptance gates
are met.

1. Confirm the dry run used the same `plan_hash` and `artifact_hash`.
2. Confirm approval is unexpired.
3. Confirm the current time is inside the approved maintenance window.
4. `POST /v1/workflow-actions/run` with `mode=apply`, maintenance window, and a new
   idempotency key.
5. Poll status at a bounded interval; never use an unbounded loop.
6. Surface phase evidence and stop immediately on a failed gate.
7. If the worker enters rollback, display rollback status prominently and do
   not submit another apply request.

### Child workflow: SDA Fabric - Export Evidence

1. Retrieve run evidence.
2. Retrieve the run audit chain.
3. Verify `chain_valid=true`.
4. Produce a final structured workflow result containing IDs and hashes, not
   raw device output or secrets.

## Parent workflow input wizard

The first production UI version accepts a versioned fabric-intent JSON document
to keep the backend contract unambiguous. The final Figma-guided wizard will
construct this document from structured screens.

Required inputs:

- Environment: lab, staging, or production
- Fabric intent JSON
- Change reference
- Requested mode: plan only, dry run, or apply
- Maintenance-window start and end for apply
- Approval expiry
- Notification recipients

Hidden/system values:

- Workflow instance ID
- Intent ID/hash
- Plan ID/hash
- Artifact hash
- Approval ID
- Run ID
- Idempotency-key hash

## Operator states

| State | Meaning | UI treatment |
|---|---|---|
| Validation failed | Intent is structurally or semantically unsafe | Red, show every issue and field path |
| Plan ready | Immutable plan and artifact exist | Blue, review only |
| Approval pending | Waiting for a different authorized user | Amber, no execute control |
| Dry run queued/running | Simulator or worker is processing | Blue progress with phase list |
| Dry run blocked | Plan is valid but missing deployment requirements | Amber, list blockers |
| Apply queued/running | Device transaction is active | Blue progress, disable duplicate actions |
| Rollback running | Recovery is active | Red/amber, prominent warning |
| Succeeded | All gates passed | Green with evidence export |
| Failed/rollback failed | Manual intervention required | Red with escalation data |

## Error contract

Every child workflow returns:

```json
{
  "succeeded": false,
  "status": "validation_failed",
  "message": "Human-readable summary",
  "intent_id": null,
  "plan_id": null,
  "approval_id": null,
  "run_id": null,
  "errors": [],
  "blocking_requirements": []
}
```

Errors from all relevant validation activities are aggregated. Raw response
headers, tokens, credentials, and full running configurations are never
returned as workflow outputs.

## Workflow limits and scaling behavior

- The parent workflow contains orchestration only; device loops execute in the
  backend worker.
- Polling stops well before the 30-minute Workflows runtime limit.
- Long deployments return a run ID and are resumed by a monitoring workflow or
  automation rule rather than keeping one workflow instance open indefinitely.
- Site deployments use one fabric lock per fabric and bounded concurrency per
  site/device group.
- Bulk intent creation uses backend transactions, not thousands of Workflow
  activities.

## Production-ready and Exchange checklist

Before marking each workflow Production Ready:

- Lock the workflow.
- Pass Workflows validation with no errors.
- Add a workflow description.
- Add descriptions for every input and output variable.
- Confirm every target and account key is mapped through the installation
  wizard.
- Test import as a duplicate before updating the installed copy.
- Export the workflow package to Git.
- Verify no Secure String value is in the export.
- Verify success means completion, not merely that the workflow started.

Publishing to Exchange is deferred until the lab and production pilot pass.
