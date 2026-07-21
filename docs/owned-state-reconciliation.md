# Workflow-owned state reconciliation

## Safety invariant

The candidate intent is not proof of ownership. The workflow may remove a
configuration object only when that exact object and its exact negation exist
in the immutable owned-state manifest from either:

1. the last fully gated `apply_succeeded` run; or
2. a read-only discovery baseline approved by a different identity from the
   discovery operator and bound to an evidence hash and change reference.

Missing, cross-fabric, modified, duplicate, unsupported, or hash-invalid
baselines fail closed. Removal commands have a strict multicast-only grammar;
an approval-bound manifest cannot inject an arbitrary device command.

## Plan and artifact contract

Planning loads the newest fabric baseline and embeds the complete baseline in
the plan. Its hash therefore participates in `plan_hash`, `plan_id`, artifact
rendering, approval, and run idempotency. Re-rendering fails if the baseline or
reconciliation delta differs from the approved plan.

The renderer derives the candidate `owned_state` manifest and compares every
resource by `(device_id, ownership_key, state_hash)`. A resource is stale when
it is absent from the candidate or its exact state changed. Stale resources are
rendered in dependency-safe removal order in a dedicated
`multicast_reconciliation` phase after checkpoint and before underlay.

The manifest covers native multicast state created by the workflow:

- underlay RP loopbacks and MSDP peers/global settings;
- per-VRF multicast routing, exact ACLs, ASM RP/register-source or SSM policy;
- multicast segment loopbacks, LISP interfaces, and LISP database mappings;
- edge SVI, border handoff, and fusion handoff PIM/IGMP configuration; and
- per-L2-instance `broadcast-underlay` groups.

Each stale resource has an exact absence gate. A header, partial match, stale
line, or duplicate does not pass. Removed devices retain their prior
secret-reference-only connection descriptor in the approved baseline, so
decommission cleanup cannot be silently omitted.

## Persistence and rollback

SQLite and PostgreSQL both persist an append-only `owned_state_manifests`
ledger. The worker commits `apply_succeeded`, releases the fabric lock, and
inserts the resulting manifest in one database transaction. If configuration,
transport, or an absence gate fails, verified checkpoint rollback runs and the
prior baseline remains authoritative. A failed or rolled-back run never
advances the ownership ledger.

## First-deployment bootstrap

The first plan has no prior ownership proof and emits
`multicast.reconciliation_baseline_missing`. It cannot infer an empty network.
A bootstrap workflow must:

1. discover the exact candidate-owned names and lines read-only on every
   target;
2. fail on any unmanaged collision;
3. store the discovery evidence by SHA-256 hash;
4. obtain approval from a different identity; and
5. call `POST /v1/workflow-actions/adopt-owned-state-baseline`.

The bootstrap child workflow remains disabled until the discovery collector is
hardware accepted. This is intentional: supplying a Meraki form value is not a
substitute for device evidence.

## Remaining acceptance boundary

Software reconciliation is implemented and regression-tested. A non-empty
prune delta emits `multicast.reconciliation_hardware_acceptance_pending` until
the exact target IOS XE releases prove every removal command, exact absence
gate, retired-node cleanup, injected failure, and verified rollback. Native
multicast enablement independently retains
`multicast.hardware_acceptance_pending`.
