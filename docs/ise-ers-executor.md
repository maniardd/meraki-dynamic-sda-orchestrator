# Cisco ISE ERS executor contract 1.0

## Scope and safety state

The isolated apply worker can now consume the renderer's secret-free
`external_systems.ise` manifest. The supported ownership scope is deliberately
narrow:

1. Security Group Tags (`/ers/config/sgt`)
2. Security Group ACLs (`/ers/config/sgacl`)
3. Egress Matrix Cells (`/ers/config/egressmatrixcell`)

`policy_plane.hardware_api_acceptance_pending` remains unconditional and the
artifact remains `executable:false`. Consequently, merging this code cannot
change ISE or a switch. Hardware/API acceptance is a separate, explicit release
decision.

The implementation follows Cisco's ERS resource and method contract:

- [Cisco ISE API framework and ERS authorization](https://developer.cisco.com/docs/identity-services-engine/latest/)
- [ERS request methods and headers](https://developer.cisco.com/docs/identity-services-engine/latest/request-headers/)
- [Create semantics (`201` and `Location`)](https://developer.cisco.com/docs/identity-services-engine/latest/create-a-resource/)
- [Filtered reads and paging](https://developer.cisco.com/docs/identity-services-engine/latest/read-a-resource/)
- [Update semantics](https://developer.cisco.com/docs/identity-services-engine/latest/update-a-resource/)
- [SGT](https://developer.cisco.com/docs/identity-services-engine/latest/sgt/),
  [SGACL](https://developer.cisco.com/docs/identity-services-engine/latest/sgacl/), and
  [Egress Matrix Cell](https://developer.cisco.com/docs/identity-services-engine/latest/egressmatrixcell/)
  resource families

## Runtime boundary

The API, planner, renderer, artifact, logs, and database never receive an ISE
password. The worker resolves `credential_ref` inside the isolated runtime.
`ca_bundle_ref`, when present, must resolve to an existing local CA-bundle file;
otherwise the operating-system trust store is used. TLS verification cannot be
disabled.

The HTTP client:

- uses Basic authentication only over HTTPS;
- disables environment proxy inheritance to prevent credential forwarding;
- rejects redirects and cross-origin `Location` headers;
- uses bounded connect/read timeouts and filtered lookups capped at 100 results;
- fetches and sends an ISE CSRF token when the target exposes one; and
- never stores response bodies, authorization headers, passwords, or tokens as
  evidence.

## Transaction sequence

Before a write, the executor proves:

1. the configured write endpoint is the unique deployment node with the
   `PrimaryAdmin` role;
2. the `ANY-ANY` matrix cell is unique, enabled, and has `DENY_IP` or
   `DENY_IP_LOG` as its final rule;
3. same-name SGT/SGACL matches are unique;
4. the requested SGT value is not assigned to a different object;
5. every existing target contains the manifest's ownership marker; and
6. every existing source/destination SGT pair is unique and owned.

Operations are deterministic: SGTs, SGACLs, then matrix cells. Matrix payloads
use the real ERS IDs returned for the source SGT, destination SGT, and SGACL;
display names are never sent as ID substitutes.

Every update captures a mutable pre-change snapshot. A rollback restores owned
updates and deletes only resources created by the same transaction. Before a
rollback write, the current object must still match the transaction's verified
post-write hash. A concurrent change therefore fails closed and quarantines the
associated allocation rather than being overwritten.

The journal is created before each POST or PUT. This covers ambiguous outcomes
where ISE commits a write but the client receives an error or an unusable
`Location`. Same-origin lookup may recover a newly-created object; an ambiguous
or changed object is never guessed or deleted.

## Worker integration

The ISE read-only preflight occurs before device checkpoints. The ISE policy
transaction runs at the start of the `policy_plane` phase, before policy CLI is
sent to IOS XE. A later device or operational-gate failure first restores device
checkpoints and then reverses the ISE journal. Any unverified device or ISE
rollback moves the run to `rollback_failed` and quarantines dynamic allocations.

Evidence types are:

- `ise_ers_preflight`
- `ise_ers_transaction`
- `ise_ers_rollback`

They contain operation IDs, resource types, actions, counts, and hashes only.

## Hardware/API acceptance required to clear the blocker

Run this only in a dedicated ISE lab and with synthetic SGT/SGACL names:

1. Record the ISE version/patch and deployment topology. Enable ERS and create a
   least-privileged ERS Admin test account. Confirm the configured URL resolves
   to the active Primary PAN and has a trusted certificate chain.
2. Set and independently verify the ISE default `ANY-ANY` egress policy to deny.
   Capture the exact ERS list and by-ID response used to identify that cell.
3. Execute the software preflight with no intended changes. Confirm Primary PAN,
   default-deny, TLS, CSRF, paging, and response parsing evidence.
4. Create two synthetic SGTs, one synthetic SGACL, and one matrix cell. Confirm
   the GUI, ERS by-ID reads, and a TrustSec-capable device all show the exact
   values and references.
5. Re-run the same intent and prove zero writes. Drift one owned description or
   ACL and prove one verified update. Create a same-name unmanaged object and a
   duplicate requested SGT value and prove zero writes.
6. Inject failures after each resource type and after device policy CLI. Prove
   reverse restoration, deletion only of newly-created owned resources, and
   allocation release only after every rollback verification succeeds.
7. Change a just-written object out of band before rollback. Prove rollback is
   refused and the run/allocation are quarantined.
8. Validate ISE PAN failover. The workflow must rediscover/re-approve the active
   Primary PAN; it must never silently write to a Secondary PAN.
9. Validate the target IOS XE SXP source/password behavior and exact operational
   parsers, then run synthetic permitted and denied traffic across two edges.
10. Attach sanitized ERS requests/responses, before/after object snapshots,
    device gates, traffic proof, rollback proof, approver identity, and change
    reference to the acceptance record.

The designated network/ISE change approver—not the software test suite—owns the
final decision to remove `policy_plane.hardware_api_acceptance_pending` for an
explicit ISE and IOS XE release combination.
