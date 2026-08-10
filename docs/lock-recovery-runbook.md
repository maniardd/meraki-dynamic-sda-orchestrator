# Lock recovery runbook (PostgreSQL)

Fabric locks never expire automatically. A worker crash in `apply_running` or
`rollback_running` leaves `fabric_locks` permanently occupied, blocking every
subsequent `create_run(mode=apply)` until an operator explicitly drives the run
to a terminal state. Because `create_run` validates the maintenance window before
inserting the lock row, a stuck lock burns the entire window.

**Recovery rule**: all writes go through Python `store.transition_run()` or
`store.transition_design_reservation()`. These calls atomically update the run
status, delete the lock row, and append a signed audit event. Raw psql
`UPDATE`/`DELETE` skips the audit event and the lock deletion — see section 4.

---

## 0. Connect to the database

```bash
echo $ORCHESTRATOR_DATABASE_URL
# expected: postgresql:///sda_orchestrator?host=/var/run/postgresql
# peer authentication — no password prompt

psql "$ORCHESTRATOR_DATABASE_URL"
```

Inside psql, enable expanded output for readable single-row results:

```
\x
```

Confirm the Python store imports correctly in the same virtualenv:

```bash
python3 -c "from orchestrator.store import create_state_store; print('ok')"
```

---

## 1. Pre-window checks (all read-only)

Run these before the maintenance window opens.

### 1a. Run the read-only inspector first

```bash
python3 tools/inspect_runtime_recovery.py
```

This tool uses `SET TRANSACTION READ ONLY` with a 5-second statement timeout and
hashes all identifiers before printing. It fails closed when any lock has expired,
when a lock belongs to a run outside `apply_queued`/`apply_running`/`rollback_running`,
or when the lease window is invalid. A non-zero exit code means manual recovery is
required. **Always run this before any manual query.**

The inspector accepts only the peer-authenticated URL
`postgresql:///sda_orchestrator?host=/var/run/postgresql`; any other value raises
`RuntimeRecoveryInspectionError`.

### 1b. Check fabric_locks directly

```sql
SELECT fabric_id, run_id, acquired_at, expires_at
FROM fabric_locks;
```

Any row here represents a lock that has not been released. The `expires_at` value
is an observational staleness signal only — it is never acted on automatically.
A row with an expired `expires_at` still blocks new runs. Note the `run_id` for
the next step.

### 1c. Check run status for the locked run

Replace `run_REPLACE` with the `run_id` from 1b.

```sql
SELECT run_id, status, requested_by, created_at, updated_at
FROM runs
WHERE run_id = 'run_REPLACE';
```

Expected stuck statuses: `apply_running` or `rollback_running`. If the status
is already terminal (`apply_failed`, `rolled_back`, etc.) but the lock row
persists, the lock is an orphan — still recover via section 2.

To see the full join with lock timing (same query as the inspector):

```sql
SELECT
    lock.fabric_id,
    lock.run_id,
    lock.acquired_at,
    lock.expires_at,
    run.status,
    run.updated_at
FROM fabric_locks AS lock
INNER JOIN runs AS run ON run.run_id = lock.run_id;
```

### 1d. Check quarantined and reserved reservations

```sql
SELECT
    dr.reservation_id,
    dr.state,
    dr.fabric_id,
    na.prefix,
    na.resource_pool_id
FROM design_reservations dr
LEFT JOIN network_allocations na
    ON na.reservation_id = dr.reservation_id
WHERE dr.state IN ('quarantined', 'reserved')
ORDER BY dr.created_at;
```

`quarantined` reservations hold prefixes and scalar ranges indefinitely.
`reserved` reservations that pre-date the stuck run may need to be released
before re-cutting the plan. Note the `reservation_id` for section 3 if needed.

### 1e. Verify audit chain integrity

No native SQL query can verify the hash chain. Use Python:

```python
from orchestrator.store import create_state_store
import os

store = create_state_store(os.environ["ORCHESTRATOR_DATABASE_URL"])
ok = store.verify_audit_chain()
print("audit chain:", "INTACT" if ok else "BROKEN — do not proceed, investigate first")
```

If this returns `False`, stop. Recovery writes on a broken chain extend a
corrupted ledger.

---

## 2. Lock recovery — Python writes only

### 2a. Open the store

```python
from orchestrator.store import create_state_store
import os

store = create_state_store(os.environ["ORCHESTRATOR_DATABASE_URL"])
```

### 2b. Inspect the stuck run

```python
RUN_ID = "run_REPLACE"   # from section 1b
run = store.get_run(RUN_ID)
print("status  :", run["status"])
print("fabric  :", run["fabric_id"])
print("plan    :", run["plan_id"])
print("updated :", run["updated_at"])
```

### 2c. Choose the terminal transition

| Current status     | Recovery transition   | When to use                                              |
|--------------------|-----------------------|----------------------------------------------------------|
| `apply_running`    | `"apply_failed"`      | **Default at 2am.** Worker crashed; config push status unknown. |
| `apply_running`    | `"rollback_running"`  | Only if you are about to manually verify and push a rollback. Requires a second `transition_run` call to reach terminal. |
| `rollback_running` | `"rollback_failed"`   | **Default at 2am.** Rollback incomplete or unverifiable. |
| `rollback_running` | `"rolled_back"`       | Rollback completed and independently verified.           |

Default to the simpler terminal unless you have strong evidence the operation
completed.

### 2d. Execute the transition

```python
ACTOR = "operator-YOUR-NAME-HERE"   # written verbatim into the audit event

result = store.transition_run(RUN_ID, "apply_failed", ACTOR)
# or for rollback_running:
# result = store.transition_run(RUN_ID, "rollback_failed", ACTOR)

print("new status:", result["status"])
```

This call atomically (`store.py:991-1024`):
1. Updates `runs.status` to the terminal value
2. DELETEs the `fabric_locks` row (`store.py:1008`)
3. Appends a signed `run.status_changed` audit event

### 2e. Confirm the lock is gone

```sql
SELECT count(*) AS remaining_locks
FROM fabric_locks
WHERE fabric_id = 'REPLACE_FABRIC_ID';
```

Expected: `remaining_locks = 0`.

### 2f. Verify audit chain is still intact

```python
print("audit chain:", "INTACT" if store.verify_audit_chain() else "BROKEN")
```

---

## 3. Reservation release — Python write only

`verified=True` is mandatory. `store.py:623` raises `ConflictError` before any
write if it is omitted or `False`.

```python
RESERVATION_ID = "reservation_REPLACE"
ACTOR = "operator-YOUR-NAME-HERE"

result = store.transition_design_reservation(
    RESERVATION_ID,
    "released",
    ACTOR,
    verified=True,
)
print("reservation state:", result["state"])   # must print 'released'
```

This atomically (`store.py:607-653`):
1. Updates `design_reservations.state` → `'released'`
2. Updates all matching `network_allocations.state` → `'released'`
3. Updates all matching `scalar_allocations.state` → `'released'`
4. Appends a signed `reservation.released` audit event

Rows are not deleted. The allocation exclusion index applies only to
`state IN ('reserved','committed','quarantined')`, so released rows no longer
block re-allocation.

Allowed source states: `reserved`, `committed`, `quarantined` → `released`.
Calling with an already-released reservation raises `ConflictError`.

---

## 4. What is unsafe to touch

### Direct DELETE from `fabric_locks`

```sql
-- DO NOT RUN
DELETE FROM fabric_locks WHERE fabric_id = 'sjc23-poc-fabric';
```

The `runs` row stays in `apply_running` permanently. No audit event is written.
The run's idempotency key remains bound. Future runs against the same plan
succeed (lock is gone) but the zombie run can never reach a terminal state.
The audit chain has no gap that `verify_audit_chain` will detect — hash
continuity is preserved — but the operational state is permanently inconsistent.

### Direct UPDATE of `runs.status`

```sql
-- DO NOT RUN
UPDATE runs SET status = 'apply_failed' WHERE run_id = 'run_...';
```

`transition_run()` writes the audit event in the same transaction as the status
update. A raw UPDATE produces a chain gap and leaves the `fabric_locks` row
behind even though the run now appears terminal.

### Any direct write to `audit_events`

Each event's `event_hash` is `sha256_json(body)` where `body` includes
`previous_hash`. Any INSERT, UPDATE, or DELETE outside `_append_audit()`
creates a discontinuity that `verify_audit_chain()` will surface on the next
run (`store.py:1310-1332`). The discontinuity is permanent.

### Direct writes to `owned_state_manifests`

This is the fabric configuration baseline for the reconciliation engine.
Corrupting it can cause the next apply's owned-state diff to generate spurious
`no ` (removal) commands against live devices.

---

## 5. Post-recovery checklist

```
[ ] store.verify_audit_chain() returns True
[ ] SELECT count(*) FROM fabric_locks WHERE fabric_id = '<fabric>'; → 0
[ ] SELECT status FROM runs WHERE run_id = '<RUN_ID>'; → terminal status
[ ] SELECT state FROM design_reservations WHERE reservation_id = '<RES_ID>';
    → 'released'  (if a reservation was released)
[ ] New create_run(mode='apply', ...) succeeds without ConflictError
```

---

## 6. Safe vs unsafe at a glance

| Operation | Safe | Audit event written | Lock row cleared |
|---|---|---|---|
| `store.transition_run(run_id, terminal, actor)` | YES | YES | YES |
| `store.transition_design_reservation(id, 'released', actor, verified=True)` | YES | YES | n/a |
| `DELETE FROM fabric_locks` | NO | NO | YES (leaves zombie run) |
| `UPDATE runs SET status = ...` | NO | NO | NO |
| Any direct write to `audit_events` | NO | chain broken | n/a |
| Any direct write to `owned_state_manifests` | NO | NO | n/a |
