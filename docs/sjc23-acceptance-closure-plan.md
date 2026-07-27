# SJC23 production-acceptance closure plan

This is the single operator handoff for the evidence that remains after the
software foundation, Meraki plan/approval/dry-run workflow, read-only IOS XE
precheck, and IOS XE licence check have passed. It is intentionally a closure
plan, not an authorisation to enable Apply, change a device, disclose a
credential, or mark a gate passed.

The source of truth is the machine-readable
[`production-acceptance.sjc23.yaml`](../acceptance/production-acceptance.sjc23.yaml).
Every evidence summary added to the repository must be secret-free and
hash-bound; raw exports, credentials, raw device output, and database backups
remain in their approved protected systems.

## Current release boundary

The SJC23 scope is a two-node, intentionally isolated fabric:

- C9500-48Y4C Border/control-plane at OOB `192.168.128.9`;
- C9300-24P Fabric Edge at OOB `192.168.128.7`; and
- `TwentyFiveGigE1/0/2` to `GigabitEthernet1/0/2` is the physical fabric link.

The `10.40.x.x` reference environment is not part of this scope. Fusion/BGP
handoff, multicast overlay, and ISE/SXP/SGT policy are explicitly unselected.
They are not missing work for this release; if a later customer requirement
selects one, the corresponding capability gate becomes required and its
dedicated acceptance procedure must be used.

## Required pending-gate evidence

| Pending gate | Owner(s) | Dependency / external input | Evidence needed before review |
| --- | --- | --- | --- |
| `meraki.native_export_import` | Automation, platform | Stable TLS endpoint; Account Key bindings which do not serialize bearer values | Secret-free structural audit passes; duplicate-workspace import passes; raw export is retained outside Git |
| `meraki.role_negative` | Security, automation | A successfully imported native package | Planner/approver/operator/auditor denial tests with no device or ISE write |
| `ingress.stable_tls` | Platform, security | Approved FQDN, trusted certificate, DNS, reverse proxy/load balancer, monitoring and renewal owner | External DNS/TLS/health proof; API stays loopback-only; proxy exposes only approved non-Apply paths |
| `runtime.postgres_backup_restore` | Platform, automation | Approved encrypted off-host backup repository, retention, recovery objectives, second recovery host | Hash-verified backup, isolated restore, retention/alert proof, and a second-host recovery exercise |
| `runtime.ha_worker_recovery` | Platform, automation | Backup/restore complete; an approved recovery/failover design | Interrupted-run recovery, verified rollback, dispatcher recovery, alerting, and dual-control evidence |
| `runtime.secret_rotation` | Security, platform | Stable TLS and approved secret/certificate lifecycle | Token, device credential, certificate, and selected external-secret rotation without disclosure or Apply |
| `iosxe.underlay` | Network design, automation | Approved SJC23 maintenance window and rollback authority | Both checkpoints, allocated underlay, exact IS-IS/BFD/MTU/loopback convergence, and verified rollback |
| `iosxe.lisp_vxlan` | Network design, automation | Underlay accepted in the same or a later approved window | Exact LISP control-plane, NVE/data-plane, endpoint registration/reachability, and verified rollback |
| `reconciliation.owned_state` | Automation, network design | LISP/VXLAN acceptance and an approved owned-state baseline | Baseline adoption, approved delta, stale-state absence gates, audit chain, and rollback proof |
| `telemetry.observability` | Platform, network design | Approved metrics/logs/alerts/retention destination and operator runbook | Relay and device telemetry, alert delivery, audit retention, and operator-response exercise |
| `scale.multisite` | Automation, network design, platform | Representative second-site topology and recovery environment | Multi-site planning, concurrent allocation/idempotency, pool exhaustion, workflow-runtime, and recovery objectives |
| `operations.pilot_change` | Change approver, network design, automation | All prerequisite gates and stakeholder communications | Approved pilot record, rollback authority, change communications, final evidence review, and decision record |

## Safe execution order

1. **Platform track:** establish `ingress.stable_tls`, then capture backup /
   restore and worker-recovery proof. Do not repoint Meraki HTTP targets until
   the FQDN, TLS, proxy restrictions, renewal and monitoring are verified.
2. **Meraki track:** replace temporary ngrok targets and ensure Account Key
   fields do not serialize into the export; audit and duplicate-import before
   executing the role-negative tests.
3. **Hardware track:** use the
   [controlled hardware-acceptance packet](sjc23-controlled-hardware-acceptance.md)
   only during an approved change window. It may close underlay, LISP/VXLAN,
   and reconciliation evidence; it does not make Apply generally available.
4. **Operational track:** connect approved telemetry, prove representative
   multi-site and recovery behaviour, then conduct the pilot change.
5. **Release decision:** collect the five independent sign-offs only after
   their linked evidence is reviewed. Run the registry validator with
   `--require-ready`; a successful result is necessary before a separately
   reviewed enablement decision, not an automatic Apply command.

## Explicit no-go conditions

Stop the relevant track and record secret-free evidence if any of these is
true:

- a raw export contains a bearer value, an endpoint is temporary or untrusted,
  or duplicate-workspace import changes the native workflow semantics;
- a certificate, DNS record, proxy allow-list, monitoring path, renewal owner,
  backup encryption, or recovery objective is absent;
- a switch maintenance window lacks a change reference, OOB recovery,
  checkpoint verification, plan/artifact/approval hashes, or rollback
  authority;
- a requested capability changes the scope to Fusion/BGP, multicast, or
  ISE/SXP/SGT without its now-required acceptance gate; or
- any validation, exact operational gate, evidence hash, or owner review
  fails.

No operator may work around a pending gate by changing it to
`not_applicable`. The only non-applicable gates are those whose controlling
customer-design conditions are explicitly excluded by the release scope.
