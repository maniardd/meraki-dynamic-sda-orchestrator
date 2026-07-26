# SJC23 controlled hardware-acceptance packet

This runbook is the controlled proof procedure for the two-node SJC23 lab. It
does not authorize Apply, contain device credentials, or prescribe static
configuration. The approved planner must derive one immutable plan and rendered
artifact from the active requirements at the start of the maintenance window.

## Scope and topology

| Function | Confirmed target | Fabric role |
| --- | --- | --- |
| Border/control plane | C9500-48Y4C at OOB `192.168.128.9` | Border plus control plane |
| Fabric edge | C9300-24P at OOB `192.168.128.7` | Fabric edge |
| Physical fabric link | `TwentyFiveGigE1/0/2` to `GigabitEthernet1/0/2` | One point-to-point underlay link |

The `10.40.x.x` addresses belong to a separate reference environment and are
out of scope. This lab deliberately selects an isolated border handoff, no
multicast overlay, and no ISE/SXP policy plane. Those feature gates are not
applicable to this release scope; they become required if a later customer
intent selects them.

## Required people and go/no-go criteria

The network design authority, automation owner, and authorized change approver
must be present or explicitly delegated. Before any write:

1. Confirm an approved change reference, maintenance window, business-impact
   statement, and rollback authority.
2. Confirm console or OOB recovery for both switches and connectivity from the
   Ubuntu relay to the two OOB addresses.
3. Run the allowlisted read-only precheck. It must confirm the target identity,
   software compatibility, checkpoint support, and Network/DNA Advantage
   entitlement current and next reboot.
4. Generate a new plan from the active requirements. Record its intent, plan,
   artifact, and approval hashes in the change record. Do not reuse a plan if
   requirements, inventory, or topology changed.
5. Verify that the rendered artifact has no unresolved secret reference or
   blocking requirement for the selected scope.

Any failed precheck, hash mismatch, missing approval, or unexplained topology
difference is a no-go. Stop before configuration mode and record the failure as
secret-free evidence.

## Execution sequence

The worker performs checkpoint, phase, verification, and rollback in this
order. Operators must not paste a static replacement configuration.

| Stage | Dynamic worker behavior | Acceptance evidence | Failure behavior |
| --- | --- | --- | --- |
| 1. Checkpoint | Capture and verify a per-device checkpoint before the first phase | Checkpoint identities and hashes only | Stop if either checkpoint cannot be verified |
| 2. Underlay | Render and apply only the allocated loopbacks and point-to-point underlay for the approved plan | Exact IS-IS adjacency, BFD, loopback reachability, MTU and PIM-underlay checks when selected | Restore both checkpoints and verify rollback |
| 3. LISP/VXLAN | Render only the approved control-plane, LISP and NVE blocks | Exact LISP session, map-server, NVE peer, endpoint-registration and reachability checks | Restore both checkpoints and verify rollback |
| 4. Owned state | Compare the approved owned-state baseline with the planned state | Baseline hash, absence gates, audit-chain result | Stop if the baseline is missing or the delta is not approved |
| 5. Evidence | Persist redacted phase, gate, rollback and audit evidence | Immutable evidence hash linked to plan/artifact/approval/change | Do not alter gate status without review |

`fusion.bgp_handoff`, `multicast.native_overlay`, and `policy.ise_sxp_sgt` are
excluded from this isolated scope. If any is enabled in the submitted intent,
halt this runbook and use the capability-specific acceptance procedure before
continuing.

## Gate-close criteria

The maintenance window can produce evidence for only these required gates:

- `iosxe.underlay`: every rendered underlay block accepted; exact convergence
  and rollback verification on both devices.
- `iosxe.lisp_vxlan`: every selected LISP/VXLAN block accepted; exact
  control-plane and data-plane evidence plus rollback verification.
- `reconciliation.owned_state`: approved owned baseline, verified delta, exact
  absence checks, and rollback evidence.

Passing traffic or a command prompt alone does not close a gate. The automation
owner must add a secret-free, hash-bound evidence summary to the acceptance
registry; the designated owners then review it before setting a gate to
`passed`.

## Immediate rollback triggers

Immediately halt and restore verified checkpoints if any of the following
occurs:

- lost OOB management or loss of the fabric-link recovery path;
- a phase command fails, exceeds its bounded timeout, or returns a CLI error;
- an exact operational gate is missing, duplicated, or reports an unexpected
  neighbor/session/peer;
- rollback cannot be verified against the checkpoint;
- a secret, raw configuration, or unauthorized device output would be written
  to acceptance evidence.

After rollback, retain only redacted evidence, release dynamic allocations only
after rollback verification, and leave Apply disabled.

