# Meraki Native SDA Workflow - Live Build Status

Date: 2026-07-23  
Tenant/network: CiscoWLAN / SJC23-SDA  
Safety state: planning and simulation only; production Apply remains disabled.

## Completed in the Meraki development tenant

The four native child workflows below are built and validated:

| Workflow | Meraki workflow ID | Implemented behavior |
| --- | --- | --- |
| SDA Fabric - Validate and Plan | `02X844LMD049N0MPwXuLX9NkkYa8lnZtRmK` | Sends versioned user requirements to the Planner endpoint, rejects HTTP failure, extracts the immutable intent/plan/artifact contract, and exposes the planning outputs. |
| SDA Fabric - Request Approval | `02X8XU5DM3D0R5EBWrSPxNpfn0sC2CxMbar` | Displays the plan, plan hash, artifact hash, change reference, and expiry in a native Meraki approval; records an approved decision through the role-separated Approver target. |
| SDA Fabric - Start Dry Run | `02X8XYX9GND810lPZxtIygI3DZ1Ba8PNDnY` | Creates an idempotent dry run, extracts its run ID, and invokes synchronous simulation through the role-separated Operator target. |
| SDA Fabric - Export Evidence | `02X8YMDJV4RAJ2Q3nqApl74Fd9lkHoEhXiV` | Retrieves the redacted evidence and append-only audit-chain contract through the role-separated Auditor target. |

The parent workflow is also assembled and validated:

| Workflow | Meraki workflow ID | Child ordering |
| --- | --- | --- |
| SDA Fabric - Plan, Approve, and Execute | `02X92FV8CYQLX5vsmumjTB2CsfTtalICfWS` | Validate and Plan -> Request Approval -> Start Dry Run -> Export Evidence |

The parent contains no Apply child. All tenant HTTP targets use role-separated
credentials. HTTP redirects and sensitive-header redirects are disabled.
All five live HTTP activities are configured to stop on activity or non-2xx
failure, so a failed callback cannot be reported as a successful child run.
The four child workflows are locked and remain Meraki-validated after this
check.

## Live acceptance results

### Planning

The accepted SJC23 plan is:

- plan ID: `plan_967854d7a15a063d`
- intent ID: `intent_e41b71df92c7b3e8`
- plan hash: `967854d7a15a063da1c1a276aeb2bf9c27b0dcd1d0cc8ce490125044c9d5c378`
- intent hash: `e41b71df92c7b3e8afda805b90a5314b84d6d36d927991608d8de0a5cfa51918`
- artifact hash: `d2a7be8b179394be400c4cf40632460d9a3ae376d7e0ee361de645d26f8edc68`
- blocking requirements: `[]`

### Native approval

The first live approval exposed a tenant assembly defect: the native HTTP
activity had an empty Relative URL and returned `404`. The workflow was repaired
to use the manifest-pinned path `/v1/workflow-actions/approve`.

Corrected approval run:

- Meraki run ID: `02X930JEPWG9I6kIGwCXS9QnK6ELy0uihKz`
- API result: `200 OK`
- decision: `approved`
- approver principal: role-separated Meraki approver
- plan and artifact hashes: equal to the accepted plan
- expiry: recorded as an absolute UTC timestamp

### Dry run

The first approved dry run exposed a second tenant assembly defect: the
`Process Dry Run` activity used `GET` even though the manifest and API contract
require `POST`. The activity was repaired to use:

- method: `POST`
- path: `/v1/workflow-actions/process-dry-run`
- content type: `application/json`

Corrected dry-run acceptance:

- Meraki run ID: `02X938HSR7LZJ5oS3bWJbGWdSoFEhBaDNFt`
- orchestrator run ID: `run_bd3a5f2963cd4e7e84afa9b97651a87d`
- status: `dry_run_succeeded`
- HTTP result: `200 OK`
- devices: `2`
- phases: `7`
- command blocks: `27`
- simulated commands: `203`
- blocking requirements: `[]`
- device writes: none

### Evidence

Evidence export acceptance:

- Meraki run ID: `02X939Y6KQP4T1XT6a5NSXUnmTsxTi1G4yA`
- HTTP result: `200 OK`
- audit chain: `chain_valid:true`
- terminal transition: `dry_run_running -> dry_run_succeeded`
- evidence records: seven role/phase configuration summaries plus one dry-run summary
- secret-value flag: `contains_secret_values:false` on rendered evidence
- artifact hash: equal to the accepted plan

No switch configuration, ISE object, or Apply operation was executed.

### Ubuntu relay read-only preflight

GitHub Actions run
[`30029287447`](https://github.com/maniardd/meraki-dynamic-sda-orchestrator/actions/runs/30029287447)
executed the repository-tested read-only preflight on the private Ubuntu
self-hosted runner. It performed no repository checkout, device login, sudo,
service restart, or configuration operation.

- Ubuntu: 22.04.5 LTS, 4 CPUs, approximately 8 GB RAM
- root disk: 38 GB total, 42% used
- PostgreSQL: active
- hardened orchestrator health: HTTP 200 on loopback port 8080
- legacy relay health: no service on port 5000
- Border and Edge Dashboard/OOB SSH: reachable
- Border and Edge execution-management SSH: unreachable

This proves that the relay host and switch SSH service are reachable through
the `192.168.128.x` Dashboard/OOB plane, while the required `10.40.x.x`
execution plane is not currently routed or permitted end to end. The IOS XE
read-only hardware precheck therefore remains pending; production automation
must not silently fall back to the Dashboard/OOB addresses.

### Integrated parent acceptance

An integrated parent run was started after the HTTP transport hardening:

- Meraki run ID: `02X93ZAOTHTLS0yv9NVuGfEoAvYHdUXeafP`
- plan ID: `plan_4d6cfb096a4526a1`
- plan hash: `4d6cfb096a4526a10ab9a65883715774159962e26f5516b65151f3315ac797d2`
- artifact hash: `e7a054025636e57f7b13a68006ad62612291f8f9b0dc4456522fc0562aac728a`
- change reference: `SDA-PARENT-ACCEPT-20260723`
- current state: waiting at the native Meraki human approval task
- expiry finding: approval body records `2026-07-24T23:59:59Z`, while
  the native task header displays `07/26/26`; the integrated gate cannot pass
  until this mapping is explained or corrected and re-tested
- Apply child: absent
- device writes: none

The run is intentionally not self-approved by the automation author. The
authorized user must review the immutable hashes and make the native Meraki
approval decision. The pending state is recorded in the production acceptance
registry and does not block independent software, documentation, or evidence
work.

The expiry mismatch was traced to the native Request Approval activity: both
its due date and expiration date were configured as a static relative duration
of 72 hours. The `approvalExpiresAt` input appeared in the body text but did
not control either native field. On 2026-07-23 the child was corrected so both
fields use the specified-date mode and bind to `Input.approvalExpiresAt`. The
source workflow is validated and locked. A validated, locked safety copy was
also created before editing the referenced child:

Cisco documents due date and expiration date as separate Request Approval
properties, each supporting either a specified date or a relative duration:
<https://documentation.meraki.com/Platform_Management/Workflows/Tasks/Request_Approval_Task>.

- corrected source workflow: `02X8XU5DM3D0R5EBWrSPxNpfn0sC2CxMbar`
- protected safety copy: `02X953XCLHSDO0yELFytxri7RF5o461yTwJ`
- revalidated and locked parent: `02X92FV8CYQLX5vsmumjTB2CsfTtalICfWS`
- validated and locked parent safety copy: `02X958B61494Z6C03cv0XcsE0glvF8te5wo`

The already-created task retains its original `07/26/26` deadline; the change
applies only to tasks created after the correction. Therefore the integrated
gate stays pending until the current human decision completes and a fresh
parent run proves exact native due-date and expiration-date alignment.

### Corrected integrated parent acceptance

A fresh parent run completed after the native date-binding correction:

- Meraki run ID: `02X9JVCOBMP2K3GOW0AF5Kp89bIudK5YFUT`
- status: `Success`
- runtime: 2.8 minutes
- plan ID: `plan_bf8adb411cd33f0d`
- plan hash: `bf8adb411cd33f0dbf70da733f7358a809d602b99e8977479d15894787ce15b8`
- artifact hash: `5a275651ac7e08398cf8474246670b55e56fe2bfcd0ddd7ec4d1225ffae65ce3`
- change reference: `SDA-PARENT-ACCEPT-20260724-R2`
- approval input: `2026-07-27T23:59:59Z`
- native expiration display: `07/28/26` in India time, the correct localized
  calendar date for the supplied UTC instant
- child workflows: Validate and Plan, Request Approval, Start Dry Run, and
  Export Evidence all succeeded
- dry-run child result: HTTP `200`
- evidence child result: HTTP `200`
- Apply child: absent
- device and ISE writes: none

The integrated-parent acceptance gate is now passed. Corrected native export,
duplicate-import, negative authorization, platform, and operational gates
remain pending.

## Release posture

- Deterministic planner/orchestrator software: implemented and independently reviewed.
- Ubuntu API runtime: deployed with execution disabled.
- Meraki native child workflows: built, validated, and live-tested through evidence export.
- Role-separated Planner, Approver, Operator, and Auditor targets: configured and tested.
- Parent orchestration: assembled, validated, and accepted through the complete
  native plan -> approval -> dry-run -> evidence path.
- SJC23 plan -> approval -> dry-run -> evidence path: passed through the child workflows.
- Hardware/API acceptance matrices: still pending by design.
- Production Apply: disabled and absent from the parent workflow.
- Production acceptance registry: implemented and fail-closed; incomplete
  hardware, platform, security, and operational gates remain explicit.

## Remaining gates before production Apply can exist

1. Export the corrected tenant-native definitions, run the structural auditor,
   and keep raw tenant exports uncommitted.
2. Complete the IOS XE hardware acceptance matrices for the exact target
   releases and platforms, including LISP/VXLAN, BGP/fusion, multicast,
   reconciliation, rollback, and evidence parsers.
3. Complete release-specific ISE ERS and SXP acceptance, including transactional
   rollback evidence.
4. Replace temporary ngrok ingress with stable production DNS, a trusted
   certificate, and monitored highly available runtime infrastructure.
5. Perform failure-injection, recovery, idempotency, concurrency, and scale
   acceptance against a production-like multi-site fixture.
6. Only after every blocker is closed, add a separately approved Apply child
   protected by maintenance-window, immutable-hash, dual-control, checkpoint,
   verification, and rollback gates.

The authoritative gate state is now
`acceptance/production-acceptance.sjc23.yaml`; prose checklists do not clear
production blockers.
