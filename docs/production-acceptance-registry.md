# Production acceptance registry

Production readiness is an evidence decision, not a test-count claim. The
machine-readable registry at
`acceptance/production-acceptance.sjc23.yaml` records every required gate,
dependency, evidence hash, owner, and independent sign-off for the SJC23
release candidate.

The registry is deliberately outside the planner, renderer, worker, device
adapter, ISE executor, and Meraki callback paths. It cannot enable Apply or
perform a device write. It provides a fail-closed answer to two different
questions:

1. Is the acceptance record structurally valid and are all local evidence
   files present and hash-correct?
2. Are all required gates and sign-offs complete enough to request a
   separately reviewed controlled enablement?

Run the structural check from the repository root:

```powershell
python tools\validate_production_acceptance.py
```

The current registry is expected to exit successfully while reporting:

- `registry_valid: true`;
- `acceptance_complete: false`;
- `ready_for_controlled_enablement: false`;
- `production_ready: false`; and
- all three workflow Apply states as `false`.

Use the stricter release gate only when every required acceptance item has
been completed:

```powershell
python tools\validate_production_acceptance.py --require-ready
```

That command exits with code `2` while acceptance is incomplete. Structural,
semantic, evidence-integrity, dependency, sign-off, or fail-open errors exit
with code `1`.

## What is enforced

The schema and semantic validator require:

- one versioned, content-bound registry;
- unique gates, evidence IDs, and sign-off roles;
- dependency references that exist and contain no cycles;
- passed gates backed by passed evidence;
- failed gates backed by failed evidence;
- local `evidence://` references that cannot escape the repository root and
  whose SHA-256 digest matches the registry;
- decided sign-offs bound to a principal reference, decision timestamp,
  evidence reference, and evidence hash;
- no secret-bearing field names or inline secret values;
- all required gates and all five required authorities before an Apply
  authorization can even be requested; and
- a hard failure if the workflow manifest exposes Apply while acceptance is
  incomplete.

The five independent sign-off roles are:

1. network design authority;
2. automation owner;
3. security owner;
4. platform owner; and
5. authorized change approver.

No individual reviewer, developer, workflow run, or test counter can replace
the other authorities.

## Current SJC23 state

The registry contains twenty required gates across software, Meraki native
workflows, ingress, runtime, IOS XE, fusion/BGP, multicast, policy/ISE,
reconciliation, telemetry, scale, security, and pilot operations.

The completed child-level and integrated-parent Meraki
plan/approval/dry-run/evidence paths and the authenticated SJC23 IOS XE
read-only precheck are backed by committed, secret-free evidence summaries.
Four of twenty required gates are passed. IOS XE license state is a distinct
pending gate because the border is configured to return to Network Essentials
at its next reboot; underlay acceptance cannot begin until both fabric devices
pass the exact current-and-next Advantage license precheck.

The first native Meraki package export was also audited and failed closed. Its
secret-free summary records twenty structural findings without property
values: obsolete embedded child versions, missing disabled Apply and baseline
workflows, inline credential fields, temporary ngrok targets, missing
descriptions, and a missing final Create Prompt. This evidence does not pass
`meraki.native_export_import`; it provides the correction checklist for the
next export. Raw Meraki exports, raw device output, credentials, and tenant
Account Keys are not committed.

Evidence files contain only reviewed summaries and immutable identifiers. They
are not a substitute for the protected source evidence retained by the owning
system.

## Closing a gate

To close a gate:

1. Perform the acceptance procedure in the capability-specific runbook.
2. Store the protected raw evidence in its approved system.
3. Add a secret-free summary under `acceptance/evidence/`.
4. Compute its SHA-256 digest and add an `evidence://` record.
5. Set the gate to `passed` only when every recorded result is `passed` and
   all dependencies have passed.
6. Run the structural validator, the `--require-ready` check, and the complete
   unit-test suite.
7. Obtain the required role sign-offs through the approved change system.

Never change a pending gate to `not_applicable` merely because the current
two-node lab lacks the capability. A production capability may be declared
not applicable only with an explicit design rationale and an independently
approved release scope; required gates remain incomplete until passed.
