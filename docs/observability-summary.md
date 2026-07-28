# Secret-free observability summary

`GET /v1/observability/summary` is an authenticated, auditor-only endpoint for
a restricted monitoring collector. It is an aggregate health surface, not a
network inventory or configuration API.

It returns only:

- database backend and availability;
- audit-chain validity and total event count;
- counts of workflow runs grouped by state;
- counts of active and expired fabric locks;
- service version and whether execution is enabled; and
- explicit `contains_*: false` disclosure flags.

It never returns fabric IDs, run IDs, device IDs, users, plans, intent,
configuration, evidence payloads, targets, tokens, or credentials. The route
requires an `auditor` identity; planner, approver, and operator credentials do
not have permission to read it.

## Production use

The platform owner must place the endpoint behind the approved reverse proxy
and provide its auditor identity through the approved secret-management system.
The collector must alert on at least these conditions:

| Signal | Required response |
| --- | --- |
| `audit_chain_valid: false` | Stop workflow operations; investigate integrity and restore only through dual control. |
| `database: false` | Mark the relay unavailable; do not retry an Apply action. |
| `fabric_locks.expired_count > 0` | Escalate for manual recovery; expired locks are never automatically taken over or released. |
| `execution_enabled: true` outside an approved window | Escalate immediately; execution remains disabled for SJC23. |
| Run failures or rollback failures | Page the automation and network-design owners; preserve hash-bound evidence. |

This endpoint provides software support for `telemetry.observability`; it does
not close that gate. The gate still needs an approved monitoring destination,
alert delivery, audit retention, relay and device telemetry, and an
operator-response exercise with secret-free evidence.
