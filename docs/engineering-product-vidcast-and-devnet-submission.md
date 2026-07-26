# Dynamic SDA through Meraki Workflows

## Engineering, product, Vidcast, and DevNet guide

## The story

This project is an independently built workflow pattern for planning and
governing IOS XE LISP/VXLAN campus fabrics. Meraki Workflows provides the
operator experience; an external orchestrator derives and validates the design;
and a separate relay is the guarded execution boundary. It is not Cisco
Catalyst Center and is not presented as an official SD-Access replacement.

The outcome is deliberately not "click once, push CLI". The controlled path is:

`requirements -> deterministic plan -> hash-bound approval -> zero-write dry run -> redacted evidence -> controlled Apply`

The final step is disabled until all production evidence gates are accepted.

## The static-POC problem

A conventional SDA POC usually begins with fixed loopbacks, fixed underlay
links, VLANs, VNIs, VRFs, route targets, and a hand-written CLI template. It
can prove protocol mechanics but does not safely solve large-campus planning.

- A new site can overlap an existing pool, VNI, VLAN, SGT, or BGP handoff.
- A change request can drift after a person has approved it.
- A low-code workflow cannot safely own IPAM, locking, rollback, or audit.
- Direct automation can hide an unproven security, platform, or hardware risk.

## Inputs versus derived design

| Operator supplies | Planner and PostgreSQL ledger derive |
|---|---|
| Site hierarchy, roles, physical links, topology and address-pool policy | Fabric placement checks, underlay /31 or /30 links and loopbacks |
| Virtual-network names, endpoint demand, service and multicast intent | Endpoint pools, VRFs, VLAN/L2/L3 IDs, VNIs, RD/RTs and route policy |
| Fusion/BGP intent and external-route demand | Fusion attachment addressing, ASN and VRF adjacency, BGP policy |
| ISE/SXP/policy requirement | SGTs, contracts, SGACL ownership, ISE ERS manifest and SXP relationships |
| Change reference, requested mode and approval expiry | Immutable intent, plan and artifact hashes, idempotency and evidence records |

No operator enters generated per-switch IOS XE configuration, allocated
loopbacks, static endpoint pools, or static VLAN/VNI plans into Meraki.

## Components and responsibilities

Open the editable [production architecture FigJam](https://www.figma.com/online-whiteboard/create-diagram/cfde6238-8b04-43b9-96f2-5249fa75c04d?utm_source=other&utm_content=edit_in_figjam&oai_id=v1%2F2ZNyDFmNaozdTXz1UfIgF8QoZfI65sDkCNFcbUegHrfkh9EgQed7afhTOLpXkYstMEqnA7PQ6C3qYxwBEIPB8oT9mP6Q61ZluxYHI3R&request_id=7acdd773-2e00-4d3c-aaf1-fca94344046d&architecture=true)
for the recording.

| Component | Responsibility |
|---|---|
| Meraki Workflows | Requirements, native approval, status, dry-run and evidence user journey |
| Planner API | Guardrail validation, deterministic allocation, artifact rendering and blockers |
| PostgreSQL | IPAM lifecycle, fabric locks, idempotency, audit chain and allocation quarantine |
| Approver identity | Authenticated plan-bound approval only |
| Operator worker | Checkpoints, phases, operational gates, rollback and evidence |
| Ubuntu relay | Private Netmiko transport boundary to IOS XE devices |
| IOS XE fabric | C9500 Border plus Control Plane and C9300 Fabric Edge in SJC23 |
| ISE and Fusion | Production policy and external-routing integrations; optional in the isolated lab |

Meraki does not require switch SSH access. It calls the authenticated
orchestrator API. Only the guarded relay reaches the device-management plane.

## End-to-end lifecycle

1. The operator submits a versioned requirements document and requested mode.
2. Planner validation compares demand with organizational guardrails.
3. PostgreSQL locks the fabric and reserves deterministic allocations.
4. The planner emits intent, plan, artifact, blockers and immutable hashes.
5. Meraki creates a native approval task that displays the exact plan identity.
6. An authenticated approval is recorded against the plan and artifact hashes.
7. A plan-only or zero-write run creates redacted evidence and audit events.
8. Apply can run only after the full acceptance registry and sign-offs permit it.
9. A future enabled worker uses checkpoint, phase, verify and rollback-on-failure.

## What is already built

### Dynamic design foundation

- Versioned requirements and intent schemas with semantic validation.
- Guardrail-versus-derived allocation model.
- Deterministic underlay, loopback, endpoint-pool, VLAN/VNI, RD/RT, SGT,
  route-target and Fusion-handoff allocation.
- PostgreSQL CIDR overlap exclusion, allocation lifecycle, locks, idempotency,
  audit chaining, release and quarantine.
- Immutable plan/artifact hashes and plan-bound approval.

### Network automation foundation

- IOS XE artifacts for underlay, LISP/VXLAN, Fusion/BGP, shared services,
  multicast, LISP Pub/Sub, ISE/SXP/SGT and reconciliation.
- Exact operational parsers, topology-derived gates, Netmiko checkpoints and
  verified rollback paths.
- Advanced feature renderers remain explicit Apply blockers until real
  hardware/API acceptance is recorded.

### Meraki-native workflow foundation

- Captured tenant-native activity contract: HTTP Request, Prompt, Request
  Approval, conditions, loops, variables, JSON handling and child workflows.
- Master: `SDA Fabric - Plan, Approve, and Execute`.
- Children: `Validate and Plan`, `Request Approval`, `Start Dry Run`, and
  `Export Evidence`.
- Separated planner, approver, operator and auditor target identities.
- Fixed API paths, bounded polling, strict output contracts, no Python action,
  no legacy API path and double-disabled Apply.

### SJC23 lab evidence

- C9500 Border plus Control Plane and C9300 Fabric Edge roles are confirmed.
- Read-only relay access and license prechecks passed against actual OOB targets.
- Network Advantage and DNA Advantage current/next-reboot state passed on both
  fabric devices.
- Five of twenty required production gates are passed. Apply remains disabled.

## What must still happen before Apply

| Gate | Reason | Lab state |
|---|---|---|
| Stable DNS and trusted TLS | Replace temporary ngrok targets with durable ingress | Awaiting platform service |
| Native export/import | Prove safe duplicate-workspace import and target remapping | Current export has eight fail-closed findings |
| Underlay and LISP/VXLAN | Real protocol, convergence, gate and rollback acceptance | Controlled hardware test pending |
| Fusion/BGP | Redundant external handoff evidence | No Fusion node in current lab |
| Multicast | BUM, ASM/SSM, stale-state and rollback traffic proof | Pending |
| ISE/SXP/SGT | Policy ownership, enforcement and rollback proof | No ISE in current lab |
| HA, DR, telemetry and scale | Demonstrate operations at production scale | Pending platform and representative topology |
| Pilot sign-offs | Network, security, platform, automation and change authority | Pending |

## Twelve-minute technical Vidcast runbook

### 0:00–1:20 — Explain the problem

Show the FigJam architecture. Say: "The objective is not to replace Catalyst
Center or use Meraki as a raw CLI pusher. It is to create an auditable path from
site demand to a proven fabric change."

### 1:20–3:00 — Show demand becomes a dynamic plan

Show `examples/fabric-requirements.lab.yaml`. Explain that it describes site,
topology, virtual-network and address-pool demand rather than generated CLI.

Run from the repository root:

```powershell
python -c "import yaml; from pathlib import Path; from orchestrator.allocator import derive_fabric_intent; print(derive_fabric_intent(yaml.safe_load(Path('examples/fabric-requirements.lab.yaml').read_text()), yaml.safe_load(Path('policy/guardrails.yaml').read_text()))['intent_hash'])"
```

Explain that the same requirements reproduce the same plan; a changed demand
changes the immutable hash and invalidates a previous approval.

### 3:00–5:00 — Show the Meraki workflow

In **Automation > Workflows**, open the validated master workflow. Walk these
children in order:

1. `SDA Fabric - Validate and Plan`
2. `SDA Fabric - Request Approval`
3. `SDA Fabric - Start Dry Run`
4. `SDA Fabric - Export Evidence`

Explain that Meraki owns the operator journey, but the external planner owns
IPAM, locks, rendering, rollback and audit because they are stateful controls.

### 5:00–7:10 — Demonstrate a real zero-write lifecycle

Run the following locally; it cannot contact devices:

```powershell
$db = Join-Path $env:TEMP 'sda-vidcast-demo.sqlite'
$evidence = Join-Path $env:TEMP 'sda-vidcast-demo.evidence.json'
python tools\simulate_workflow.py examples\fabric-intent.lab.yaml `
  --database $db --output $evidence
Get-Content $evidence
```

Current result: a valid two-device plan with seven phases, 203 rendered
commands in 27 blocks, a valid audit chain, **zero device calls**, and **zero
resolved secrets**. It stops at `dry_run_blocked` because there is no Fusion/BGP
handoff in the isolated lab. That fail-closed result is the correct demo.

### 7:10–9:00 — Prove safety and production maturity

Show `acceptance/production-acceptance.sjc23.yaml` or the validator summary.
State that five of nineteen applicable gates are passed: software suite, Meraki child path,
integrated parent, read-only hardware precheck and licensing. Show that Apply
remains disabled. Do not present a dry-run success as configuration acceptance.

### 9:00–10:50 — Explain the production evolution

Use the gate table above. Explain that stable TLS, Fusion, ISE, telemetry, HA,
scale and pilot evidence do not change the planning contract. They supply the
proof that lets the existing Apply gate be considered.

### 10:50–12:00 — Product feedback and close

Ask product/engineering for feedback on:

1. Structured, versioned requirement forms instead of free-form JSON.
2. Portable export/import that retains Account Key references without bearer
   value serialization.
3. Native long-running monitor, approval-hash and evidence primitives.

Close with: "The success criterion is not automated CLI. It is a repeatable,
auditable path from demand to a proven fabric change."

## Recording safety rules

- Do not run Apply or configuration mode on either switch.
- Do not show raw exported JSON, Account Keys, bearer values, passwords, device
  CLI credential prompts or unredacted device output.
- Do not use the old static `SDA Fabric Full Deployment` workflow as the
  production demonstration.
- If a run waits for approval, present that as a control point; never bypass it.

## Cisco Live DevNet submission

### Recommended title

**From Static SDA POCs to Governed, Intent-Driven Fabric Automation with Meraki Workflows**

### Full abstract

LISP, VXLAN, BGP and policy-plane mechanics can be demonstrated quickly in an
SD-Access lab. The harder production challenge is different: how can a network
team turn a site request into a deterministic design, approve the exact
artifact, prove the control path without risk, and retain evidence to operate a
fabric at scale?

This DevNet-focused session presents an independently built workflow pattern
that uses Meraki Workflows as the operator experience for a dynamic SDA planner
and guarded IOS XE execution boundary. Instead of asking operators to enter
loopbacks, underlay links, VLANs, VNIs, VRFs, route targets, SGTs and CLI, the
workflow accepts versioned site, topology, address-pool, virtual-network,
policy and telemetry requirements. A ledger-backed planner validates the demand
against organization guardrails, allocates derived values deterministically,
and produces immutable intent, plan and rendered-artifact hashes.

Attendees will see a native Meraki parent/child workflow that coordinates
planning, native human approval, zero-write dry-run processing and redacted
evidence export through separated planner, approver, operator and auditor
identities. The session demonstrates why PostgreSQL IPAM, fabric locks,
idempotency, checkpoint/rollback, exact operational verification and audit
chains belong outside a low-code workflow. It also shows why stable TLS ingress,
hardware protocol acceptance, Fusion/BGP, ISE/SXP/SGT, multicast, recovery,
observability, scale and pilot change control remain explicit gates before Apply
is reachable.

This is not a replacement for Cisco Catalyst Center and does not claim a small
lab is production-ready. It is a practical architecture for using Meraki-native
workflow UX to make SDA planning, evidence and change controls repeatable.
Attendees leave with a reusable requirements-to-evidence model, separation of
control responsibilities and a checklist for evolving a static SDA POC into a
governed automation program.

### Short abstract

Learn how a Meraki Workflow can coordinate dynamic, ledger-backed SDA planning
without turning a low-code flow into an unsafe CLI pusher. This DevNet session
shows requirements-driven allocation, hash-bound approval, zero-write dry runs,
evidence, rollback boundaries and the production gates required before an IOS
XE LISP/VXLAN fabric change can be enabled.

### Learning objectives

1. Model SDA as versioned demand and topology requirements instead of static
   device configuration.
2. Build Meraki parent/child workflows around immutable plans, native approval,
   zero-write runs and evidence.
3. Define production evidence for security, platform, hardware, policy, scale
   and operations before controlled Apply.

### Likely reviewer questions

| Question | Accurate answer |
|---|---|
| Is this an official Cisco SDA product? | No. It is an independently built workflow pattern using supported IOS XE constructs and Meraki Workflow primitives. |
| Does it replace Catalyst Center? | No. It explores an operator and external orchestration pattern; platform and support decisions remain separate. |
| Is it production ready today? | The software foundation is tested; Apply is disabled until the remaining fifteen gates and sign-offs pass. |
| Is the design static? | No. Users provide demand/topology facts. The planner derives allocations and artifacts from governed pools. |
| Why not have Meraki push directly to switches? | Stateful IPAM, locks, rollback, verification and audit require a separate guarded service boundary. |
