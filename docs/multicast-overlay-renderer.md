# Native multicast overlay renderer and acceptance boundary

## Design basis

This phase follows Cisco's [Configuring Multicast in LISP VXLAN
Fabric](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lisp_vxlan/b-179-lisp-vxlan-fabric-cg/multicast-lisp-vxlan.html)
procedure. Cisco documents IPv4 Layer-3 ASM and SSM overlays, native underlay
multicast transport, per-VRF multicast routing, multicast segment loopbacks,
PIM on LISP interfaces, IGMP on edge SVIs, and PIM on border handoffs.

The private reference configurations were used only to confirm the general
IOS XE hierarchy. No customer address, hostname, group, RP, or configuration
line is copied into the public fixture.

## Dynamic planning contract

Every enabled multicast VN has one explicit overlay policy. The policy binds:

- virtual-network name, VRF, and L3 instance ID;
- ASM or SSM mode and an exact multicast group range;
- a deterministic owned access-list name;
- for ASM, an external unicast RP address and its routed prefix;
- one unique `/32` multicast segment loopback per border and fabric edge; and
- for native transport, a non-overlapping SSM core-group prefix, first usable
  group, and bounded group count.

The allocator also reserves one unique ASM BUM group per endpoint pool. Segment
loopbacks, core groups, the underlay RP, and BUM groups are all allocated from
separate guarded IPAM pools and persisted in the same atomic ledger as the rest
of the design. Active or quarantined reservations are never reused.

The validator fails closed on missing or extra VN policies, ASM/SSM conflicts,
invalid multicast ranges, an ASM RP outside its declared prefix, duplicate or
partial segment-loopback membership, overlapping core groups, duplicate BUM
groups, and BUM metadata that does not match its endpoint pool.

For a redundant underlay Anycast-RP, every fabric node uses Loopback0 as its
PIM register source. Each selected RP border owns the shared RP loopback and a
deterministic MSDP full mesh to the other selected RP borders, with SA caching
and Loopback0 originator identity. The underlay gate requires every intended
MSDP peer to report an explicit established state.

## Rendered native IOS XE contract

For every multicast-enabled border and edge, the renderer produces:

- `ip multicast-routing vrf` for each multicast VN;
- an owned exact group ACL and per-VRF ASM RP or SSM range command;
- `Loopback<l3-instance-id>` with the allocated `/32` and PIM sparse mode;
- `LISP0.<l3-instance-id>` with native multicast transport and its allocated
  core-group range;
- a LISP database mapping for the segment-loopback address;
- PIM passive, IGMPv3, and explicit tracking on edge endpoint SVIs;
- PIM sparse mode on every border-to-fusion SVI for the multicast VRF; and
- the allocated `broadcast-underlay` group for every L2 endpoint pool.

For every fusion node participating in a multicast VRF, it also enables
per-VRF multicast routing, rebuilds the same owned group ACL, applies the ASM
RP or SSM policy, and enables PIM sparse mode on each allocated border-handoff
SVI. The workflow owns the fabric-to-fusion path; the routed external
multicast domain beyond fusion remains an explicit acceptance dependency.

Head-end replication is not emitted by this renderer. It retains a distinct
fail-closed `multicast.head_end_replication_renderer_pending` blocker.

## Verification and rollback

Every rendered VN/device tuple has blocking gates for:

- the exact global per-VRF multicast policy lines;
- the exact owned group ACL;
- explicit sparse-mode PIM rows for the multicast segment loopback, LISP
  interface, and border/fusion handoff interfaces;
- exact running configuration for passive edge SVIs (`ip pim passive`,
  IGMPv3, and explicit tracking); and
- for ASM, an exact route-table entry for the declared RP prefix.
- for redundant underlay Anycast-RP, every exact MSDP peer is established.

Header-only, partial, duplicated, or wrong-mode output fails closed. A worker
failure-injection tests reject configuration inside both a fabric-edge
multicast LISP block and a fusion multicast policy block, verify checkpoint
rollback, and release IPAM state only after rollback is verified.

The renderer also emits `multicast.reconciliation_pending` for every schema
1.2 multicast lifecycle. This blocker is independent of platform acceptance:
it cannot be removed until the last committed owned-state manifest is diffed
against the candidate and deterministic negations remove stale ACL, RP/SSM,
loopback, LISP, MSDP, and BUM configuration. It remains present even when the
candidate disables multicast, so policy removal cannot silently leave device
state behind.

## Platform acceptance still required

Native multicast emits `multicast.hardware_acceptance_pending`, and every 1.2
multicast lifecycle emits `multicast.reconciliation_pending`, so production
apply remains impossible. Remove each blocker only after its distinct
acceptance contract has passed. Hardware acceptance requires the exact target
platform and IOS XE release to pass all of the following:

1. Every generated CLI block is accepted on border, edge, and fusion roles.
2. PIM sparse-mode interfaces and the external ASM RP route match intent.
3. Native core-group and per-segment BUM groups appear in MFIB without overlap.
4. A real SSM `(S,G)` flow crosses at least two fabric edges.
5. A real ASM flow registers with the declared external RP and crosses the
   border/fusion path.
6. Border, link, and RP failure tests converge without unauthorized flooding.
7. A rejected multicast block restores the verified checkpoint.
8. The state-reconciliation implementation has separately cleared
   `multicast.reconciliation_pending` by proving removal and ASM/SSM mode-change
   negations against the last committed artifact.
9. Evidence is attached to the immutable plan, artifact, approval, and change
   record.

The SJC23 POC can prove native underlay and single-border syntax but cannot by
itself satisfy dual-border or external-RP convergence acceptance.
