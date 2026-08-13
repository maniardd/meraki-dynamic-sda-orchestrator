# SJC23 POC — End-to-End Blueprint (review → confirm → apply → rollback)

**Goal:** A network admin initiates a workflow in Meraki, **reviews the derived design**, optionally **changes parameters from Meraki**, **confirms**, and the config is **applied to the two switches** — with **rollback**. Minimal human intervention; safe by construction.

**Three lanes:**
- **Lane A — Meraki (Codex):** the operator-facing workflow (intake → review → confirm → status → result → rollback). Codex has Meraki write access.
- **Lane B — Operator (you):** one-time setup (device creds, OOB, arm gates) + per-run review/confirm. Minimal.
- **Lane C — Backend (Claude, autonomous via GitHub/CI):** endpoints, queue consumer, per-run hash binding, rollback logic, deploy, drive the execution window.

---

## 1. Target operator journey (the flow)

1. Operator opens the Meraki master workflow and enters the 8 demand values.
2. Planner derives the full design and returns a **redacted preview** (subnets, VLANs, VNIs, loopbacks, phase list, command count, blockers, `deployment_authorized:false`).
3. **Meraki displays the plan for review.** Operator chooses:
   - **Change** → edit values → re-plan (idempotent; same demand = same plan).
   - **Confirm** → proceed.
4. On **Confirm**, Meraki records a **plan-bound approval** and **queues an apply run** (bound to *that* plan's hash).
5. The **queue consumer** picks up the approved run and applies it through the worker: phase-by-phase, checkpoint → configure → verify, **auto-rollback + quarantine on any failure**.
6. Meraki **polls run status** and shows phase progress, then the **redacted result/evidence**.
7. Operator may **trigger a rollback** of a successful run from Meraki (explicit confirm — it removes the fabric config).

---

## 2. Architecture & the shared API contract

Meraki never gets device access; it calls the authenticated Planner API. The worker (dedicated `sda-worker` user) is the only path to the switches. The **queue consumer runs as `sda-worker`** and invokes `worker_runtime` directly for approved runs (so no `sudoers` wildcard is needed — closes the CI-runner lateral-movement risk).

**API contract (the interface between Lane A and Lane C):**

| Endpoint | Method | Purpose | Key response |
|---|---|---|---|
| `/v1/workflow-actions/poc-guided-options` | POST | Load the reviewed option lists (existing) | option arrays |
| `/v1/workflow-actions/poc-guided-plan` | POST | 8 demand values → plan + preview (existing) | `plan_id, plan_hash, artifact_hash, poc_deployment_preview, deployment_authorized:false` |
| `/v1/workflow-actions/poc-confirm-apply` | POST | **NEW** — confirm: record plan-bound approval + queue an apply run | `{ run_id, status:"queued", plan_hash }` |
| `/v1/workflow-actions/poc-run-status` | POST | **NEW** — poll run progress (redacted) | `{ run_id, status, phase, phases_done, phases_total, succeeded, blocking, evidence_summary }` |
| `/v1/workflow-actions/poc-rollback` | POST | **NEW** — operator-initiated rollback of a completed run | `{ rollback_run_id, status }` |

All responses are **secret-free**; HTTP errors **fail the workflow** (Continue-on-error stays off); no bearer values are shown anywhere.

---

## 3. Added requirements (safety + gaps to close)

These are the requirements to fold in — several were implicit or missing:

1. **Per-run hash binding, not static env pinning.** So the operator can change parameters and apply the *new* plan, the worker validates against the **approved run's** `plan_hash`/`artifact_hash` (from the approval record), not the static `worker.env` values. `worker.env` static pins become an allowlist/last-resort, not the source of truth.
2. **Fresh precheck at apply time.** The apply's first phase is read-only precheck (inventory/topology/addressing/services/checkpoint-ready); it must pass before underlay. A stale plan cannot skip it.
3. **Auto-rollback + quarantine on failure.** On any phase failure the worker reverts to checkpoint and **quarantines** the reservation (never auto-releases). Operator sees the failure + rollback evidence.
4. **Operator rollback = explicit, confirmed.** Undoing a *successful* fabric deploy removes LISP/VXLAN and drops endpoint connectivity — so the Meraki rollback action requires a deliberate confirm and is itself a verified, evidence-producing run.
5. **The three safety demonstrations before auto-apply is trusted:** (a) precheck failure → zero changes, (b) injected mid-phase failure → clean rollback/quarantine, (c) successful apply → verified. The queue consumer's auto-trigger is enabled only after these pass.
6. **Single-operator role model for the POC** (initiator also reviews/confirms), with production role separation (planner/approver/operator/auditor) noted as the graduation path. Decision needed — POC default: single operator.
7. **Idempotency + fabric lock** (built): a double-confirm or retry cannot double-apply; concurrent runs are locked out.
8. **Status visibility in Meraki:** bounded polling of run status so the operator watches phase progress and sees a redacted evidence summary — no raw device output.
9. **Arm-the-system is a deliberate one-time step:** flipping `EXECUTION_ENABLED` + `WORKER_ENABLED` + `SJC23_POC_EXECUTION_ENABLED` to `true` is acknowledged as a security-model change, done once at setup with OOB + rollback authority confirmed.
10. **Maintenance-window / rollback-authority attestation** carried on the run (for the POC, the operator's confirm attests the window is open and they are the rollback authority with OOB up).

---

## 4. Phasing (sequence that de-risks)

- **Phase 0 — Contract freeze** (Claude): finalize the endpoints above so Lane A and Lane C build against the same interface.
- **Phase 1 — Backend build** (Claude): the three new endpoints + queue consumer + per-run hash binding + rollback logic → tests → deploy via CI.
- **Phase 2 — Meraki workflow** (Codex): extend the master workflow with review → confirm → status → result → rollback (Dashboard-native).
- **Phase 3 — Integration in dry-run** (all): full path Meraki → endpoints → queue → worker in **dry-run** (zero device writes) end to end.
- **Phase 4 — Manual execution window** (you + Claude): real creds, OOB, arm gates → apply to the switches once, plus the **three safety demonstrations**. Endpoints get DHCP.
- **Phase 5 — Enable auto-apply** (Claude): turn on the queue consumer's automatic trigger so Confirm → push happens hands-off.

---

## 5. Rough timeline

| Phase | Owner | Effort |
|---|---|---|
| 0 Contract freeze | Claude | ~0.5 day |
| 1 Backend (endpoints, queue consumer, rollback) | Claude | ~3–5 days |
| 2 Meraki workflow | Codex | ~1–2 days (parallel with 1) |
| 3 Integration (dry-run) | all | ~1 day |
| 4 Execution window + safety demos | you + Claude | ~1–2 days (gated by hardware windows) |
| 5 Enable auto-apply | Claude | ~0.5 day |

**Minimum-viable end-to-end** (initiate → review → confirm → apply → auto-rollback-on-failure, apply manually-triggered): **~4–6 days.**
**Full hands-off** (Confirm→auto-push + operator rollback button): **~1.5–2.5 weeks.**
Pacing is gated by **live hardware windows** (≈one clean attempt per window), not dev time.
