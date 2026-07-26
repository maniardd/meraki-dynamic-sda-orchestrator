# Dynamic SDA Workflow — Vidcast and Cisco Live Demo Kit

## Positioning to use consistently

This is an independently built, production-oriented workflow pattern that uses
Meraki Workflows as the operator experience for an external SDA planner and
guarded execution boundary. It is **not** a replacement for Cisco Catalyst
Center and it does **not** claim that the SJC23 lab is production-ready today.

The demonstrated outcome is a dynamic, intent-driven journey:

`requirements -> deterministic plan -> human approval -> zero-write dry run -> redacted evidence`

Apply remains disabled until every required production acceptance gate passes.

## Vidcast: 6-minute recording plan

Use the editable [FigJam storyboard](https://www.figma.com/online-whiteboard/create-diagram/0856af2a-316e-4387-9d45-dc294be7e791)
and the existing architecture FigJam as visual cutaways. Record your own voice;
do not show API tokens, SSH sessions, raw exports, passwords, or unredacted
workflow Account Keys.

| Time | Screen | What to demonstrate | Narration cue |
|---|---|---|---|
| 0:00–0:35 | FigJam architecture | The intent-to-evidence flow | "SDA at scale is primarily a planning and change-governance problem, not just a CLI-generation problem." |
| 0:35–1:15 | Meraki Workspace, master workflow | `SDA Fabric - Plan, Approve, and Execute` is validated; its sequence is validate/plan, approval, dry run, evidence | "Meraki gives the operator a familiar workflow experience, while the planner owns deterministic design decisions." |
| 1:15–2:15 | `SDA Fabric - Validate and Plan` child | Show its description and HTTP endpoint target name only | "The operator supplies requirements, not static loopbacks, VLANs, VNIs, or per-switch commands." |
| 2:15–3:05 | Planner output or accepted run details | Show plan, intent, and artifact hash fields; redact values if a screen unexpectedly contains sensitive data | "The planner allocates addressing and fabric objects from governed pools and binds them to immutable hashes." |
| 3:05–3:45 | Approval child / accepted approval task | Show the human approval point and expiry/acknowledgement concept | "Approval is for this exact immutable plan—not a vague request that can drift afterwards." |
| 3:45–4:35 | Start Dry Run / evidence child | Show the zero-write child and redacted evidence output | "The dry run proves the integration path while device and ISE writes remain prohibited." |
| 4:35–5:20 | Production acceptance registry summary | Show 5/19 applicable gates passed and the explicit blockers | "A real production workflow must make its incomplete controls visible. Apply is deliberately unavailable." |
| 5:20–6:00 | FigJam storyboard / closing | State next steps and value | "This is the path from a static POC to a governed, repeatable fabric-automation capability." |

### Short opening script

"Most SDA POCs start with static addresses and a fixed CLI template. That can
prove protocol behaviour, but it cannot safely scale. This demonstration shows
an intent-driven workflow where an operator defines the requirement, a planner
derives the fabric design from governed pools, Meraki Workflows coordinates
approval and dry-run activity, and the system exports redacted evidence before
any change can be considered."

### Short closing script

"The important outcome is not automatic configuration at any cost. It is a
repeatable control path: plan deterministically, approve the exact artifact,
prove the path with a zero-write dry run, and permit Apply only after the
hardware, security, resilience, scale, and change-control gates are accepted."

## Cisco Live proposal draft

### Proposed title

**From Static SDA POCs to Governed, Intent-Driven Fabric Automation**

### Session abstract

An SD-Access proof of concept can quickly demonstrate LISP, VXLAN, BGP, and
policy-plane mechanics, yet static addressing plans and hand-built CLI templates
do not answer the harder production question: how does an operator safely plan,
approve, prove, audit, and eventually implement a fabric across many sites?

This session presents an independently built workflow pattern that uses Meraki
Workflows as the operator-facing experience for a dynamic SDA planner and a
guarded execution boundary. Attendees will see how high-level requirements—site
hierarchy, topology, IP pools, virtual networks, policy intent, and telemetry
needs—are validated and converted into deterministic allocations through a
ledger-backed planning service. The workflow binds approval to immutable plan
and artifact hashes, performs a zero-write dry run, and produces redacted
evidence and audit-chain output.

The session is deliberately honest about production readiness. It shows why
stable TLS ingress, hardware acceptance, Fusion/BGP validation, ISE policy
validation, recovery testing, observability, scale testing, and controlled pilot
sign-off must remain explicit gates before Apply is enabled. Rather than
presenting automation as a shortcut around engineering controls, the session
shows how workflow automation can make those controls visible, repeatable, and
auditable.

Attendees leave with a practical architecture, an intent-to-evidence sequence,
and a checklist for evolving an SDA lab POC into a governed automation program.

### Audience and prerequisites

- Enterprise network architects, SDA designers, automation engineers, and
  operations leaders.
- Familiarity with SDA concepts (LISP, VXLAN, BGP, virtual networks) is useful.
- No prior Meraki Workflows experience is required.

### Learning objectives

1. Distinguish static POC configuration from dynamic, ledger-backed SDA
   planning.
2. Explain how immutable plans, human approval, dry runs, and evidence reduce
   change risk.
3. Identify the infrastructure and operational gates required before a workflow
   can enable production fabric changes.

## Pre-record checklist

- Use the current validated master workflow—not versioned legacy copies.
- Keep the Workspace, the master workflow, one child workflow, one accepted
  zero-write run, evidence output, and the acceptance registry available in
  separate tabs.
- Verify that no token, raw export, password, device CLI credential, or customer
  configuration is visible before screen sharing.
- Do not run Apply or enter configuration mode on either switch for the video.
- If an approval is pending, present it as a control point; do not bypass it for
  recording convenience.

## Current lab fact box for the video

- SJC23 lab roles: C9500 Border plus Control Plane, and C9300 Fabric Edge.
- Dynamic software/workflow path: implemented and tested.
- Production acceptance: 5 of 19 applicable gates passed.
- Apply: disabled; no device or ISE configuration is authorized by the
  workflow.
- Current remaining external work: stable DNS/TLS ingress, safe native export
  import handling, hardware acceptance, Fusion, ISE, resilience, telemetry,
  scale, and pilot sign-offs.
