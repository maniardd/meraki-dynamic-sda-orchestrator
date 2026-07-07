# Production services and policy-plane model

Schema version 1.2 adds deterministic planning contracts for the external
services that turn an isolated LISP/VXLAN fabric into a production campus.
These contracts are inputs to Meraki Workflows and the stateful planner; they
do not embed customer addresses or credentials in workflow definitions.

The model follows Cisco's current [Software-Defined Access Solution Design
Guide](https://www.cisco.com/c/en/us/td/docs/solutions/CVD/Campus/cisco-sda-design-guide.html)
and the Cisco support guidance for [fusion-router
configuration](https://www.cisco.com/c/en/us/support/docs/cloud-systems-management/dna-center/213525-sda-steps-to-configure-fusion-router.html).
It is an independently implemented automation model, not a claim that this
project is Cisco Catalyst Center or an officially validated replacement.

## Deterministic inputs and outputs

The requirements document now declares:

- External fusion nodes with independent management addresses, credential
  references, software versions, and BGP ASNs.
- Explicit border-to-fusion physical adjacencies. Production guardrails require
  a complete border/fusion adjacency matrix unless an organization deliberately
  overrides that policy.
- Shared services, their exact advertised prefixes, and the VNs allowed to
  consume each service. The default action is always deny.
- One site-wide multicast transport (`native` or `head_end_replication`),
  Anycast-RP members, and disjoint ASM and SSM VN sets.
- ISE, SXP, or hybrid policy-plane mode; ISE nodes; secret-referenced SXP
  connections; security groups; and directional contracts.

The allocator derives and reserves:

- One BGP handoff VLAN and `/30` or `/31` prefix for each
  border/fusion/VRF tuple.
- Usable peer addresses, never `/30` network or broadcast addresses.
- Shared-service import prefixes and each consumer VRF's exact fabric export
  prefixes.
- Anycast-RP address space from its own guarded IPAM pool.
- Unique SGT values from the allocation ledger when the user does not request
  an explicit tag.
- LISP Pub/Sub publisher and subscriber sets from the approved control-plane
  and border roles.

## Design guardrails

- LISP Pub/Sub is modeled as the preferred new-deployment control plane. A
  fabric and any future SD-Access transit must use compatible control-plane
  architectures.
- Fusion nodes remain outside the fabric node inventory. They terminate
  VRF-lite/eBGP handoffs and provide controlled shared-service route leaking.
- Native multicast requires PIM sparse mode on every fabric link. ASM and SSM
  cannot both be assigned to the same VN, and a production Anycast-RP requires
  at least two approved border nodes.
- Shared-service addresses must fall inside their advertised prefixes. Every
  consumer must reference an existing VN with a derived endpoint prefix.
- Policy contracts can only reference defined security groups. SGTs, SXP
  connection IDs, device IDs, management addresses, RDs, and handoff resources
  are uniqueness checked.
- ISE and SXP credentials are always `secret://` references. Inline secrets
  remain schema-invalid.

## Execution boundary

The Phase 5 renderer produces reviewable fusion VRF, VLAN, trunk, and eBGP
artifacts and creates operational BGP gates for both ends of every handoff.
Apply remains disabled for four deliberately visible blockers:

- `lisp_pubsub.renderer_pending`
- `shared_services.renderer_pending`
- `multicast.overlay_renderer_pending`
- `policy_plane.renderer_pending`

Each blocker is removed only after its release-specific renderer, rollback,
failure-injection, and hardware or API acceptance tests pass. This prevents a
valid planning document from being misrepresented as executable production
configuration.
