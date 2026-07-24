# Worker and fabric-lock recovery inspection

`tools/inspect_runtime_recovery.py` is a read-only PostgreSQL inspector for
apply-run and fabric-lock recovery state. It uses the local peer-authenticated
database URL, starts its transaction with `SET TRANSACTION READ ONLY`, applies
a five-second statement timeout, and returns only counts and SHA-256 hashes of
fabric/run identifiers.

The inspector fails closed when:

- a lock has expired;
- a lock belongs to a run outside `apply_queued`, `apply_running`, or
  `rollback_running`;
- a lease expires at or before its acquisition; or
- more than 100 locks would need to be reported.

Both `unattended_takeover_allowed` and `automatic_lock_release_allowed` are
always false. An expired lease is evidence that a human recovery workflow is
required; it is never permission for a second worker to continue Apply.

## Remaining recovery implementation

This inspector does not close `runtime.ha_worker_recovery`. Before that gate
can pass, the system still needs:

1. a reviewed dispatcher for the isolated systemd worker unit;
2. redundant worker failover without duplicate execution;
3. dual-control recovery authorization;
4. live checkpoint discovery and verified rollback for an interrupted run;
5. quarantine of allocations after unverified rollback;
6. alerting for queued/running age, expired locks, and rollback failure; and
7. a failure-injection exercise on the representative network.

No recovery implementation may release a fabric lock based only on elapsed
time or a user-supplied boolean.
