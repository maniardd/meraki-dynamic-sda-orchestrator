# ISE, SGT, SGACL, and SXP policy-plane contract

## Ownership model

The workflow separates the policy plane into three independently verifiable
responsibilities:

- Cisco ISE is the source of truth for SGTs, SGACLs, and explicit egress
  matrix cells in `ise` and `hybrid` modes.
- SXP speakers propagate IP-to-SGT bindings to approved listeners in `sxp`
  and `hybrid` modes.
- Fabric edges enforce the default-deny policy on every derived endpoint VLAN.

This follows Cisco's model in which SXP propagates bindings rather than access
policy, and SGACL enforcement occurs at the egress fabric edge. Static SGACLs
are rendered only in pure `sxp` mode. In ISE-backed modes, policy is expected
to be downloaded from ISE and verified operationally.

The design basis is Cisco's [ISE API framework](https://developer.cisco.com/docs/identity-services-engine/latest/),
[IOS XE SXP configuration guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-14/configuration_guide/cts/b_1714_cts_9300_cg/configuring_sgt_exchange_protocol.html),
and [SGACL enforcement guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/cts/b_1715_cts_9300_cg/configuring_security_group_acl_policies.html).

## Dynamic planning contract

The user supplies policy mode, a mandatory deny default, ISE deployment
identity, optional SXP connections, security-group names or requested SGTs,
and directional contracts. The allocator derives:

- ledger-backed unique SGT values;
- every fabric edge and endpoint VLAN that must enforce policy;
- deterministic owned contract and SGACL names;
- exact source and destination SGT values plus SGACL ACEs;
- an SXP transport VRF, listener prefix, and source address from that
  speaker's routed border-handoff interface; and
- the single ISE PAN permitted to receive writes.

Production validation requires redundant ISE PAN nodes and redundant SXP
speakers and listeners when those modes are selected. ISE API origins must use
HTTPS. Credentials, SXP passwords, and optional CA bundles remain `secret://`
references.

Modes are exclusive: `ise` owns ISE policy without SXP, `sxp` owns local policy
and SXP without ISE, and `hybrid` requires both. A document cannot smuggle an
inactive subsystem into another mode.

## ISE reconciliation manifest

The rendered artifact contains a secret-free ERS reconciliation manifest for:

1. owned SGT resources, matched by exact name;
2. owned SGACL resources, matched by deterministic name; and
3. explicit egress matrix cells, matched by source/destination SGT pair.

The manifest never authorizes deletion of an unmanaged object. Rollback must
restore pre-change snapshots and delete only resources newly created with the
`managed-by:meraki-dynamic-sda` marker. The ISE deployment's default matrix
must already be approved as deny; the workflow does not silently change a
shared deployment-wide ANY-ANY policy.

## IOS XE contract

Every enforcement edge receives an owned default-deny role-based ACL, an
explicit default permission, and `cts role-based enforcement vlan-list` for
the exact compressed endpoint-VLAN set. Pure SXP mode also receives owned
static SGACLs and source/destination permission cells.

Each selected SXP speaker receives:

- `cts sxp enable`;
- its routed address in the approved SXP transport VRF as default source IP;
- one runtime-resolved default password;
- exact listener peers in local speaker mode, explicitly scoped to the
  transport VRF; and
- binding-change logging.

The renderer rejects multiple source addresses or password references on one
speaker because IOS XE exposes one device-wide default for each.

## Verification and rollback

Blocking device gates require:

- the exact default permission and endpoint VLAN enforcement line;
- every source/destination SGT permission to reference its exact SGACL; and
- the exact listener prefix to exist in the speaker's transport-VRF routing
  table; and
- the VRF-scoped operational view to contain exactly the intended SXP
  peer/source tuples, all reporting `Conn status: On` in speaker mode. An
  unexpected stale or unmanaged peer fails the gate.

A failure-injection test rejects the SXP connection block, verifies checkpoint
rollback, and releases IPAM state only after rollback succeeds.

## Acceptance boundary

`policy_plane.hardware_api_acceptance_pending` remains unconditional, so
production apply is impossible. Clear it only after the exact ISE and IOS XE
releases pass all of the following:

1. ERS read/write is enabled and the write target is the active primary PAN.
2. The relay trusts the ISE certificate chain; TLS verification is never
   disabled.
3. Existing same-name resources are classified as owned-and-equal,
   owned-and-drifted, or unmanaged collision before any write.
4. SGT, SGACL, and matrix-cell create/update verification passes through the
   target ISE API version.
5. An injected API failure restores every pre-change resource and deletes only
   newly created owned resources.
6. All redundant SXP sessions report the exact peer, source, speaker mode, and
   On state; peer failure and recovery preserve bindings as designed.
7. Every edge reports the approved SGACL for every contract and default deny
   for missing cells.
8. Synthetic permit and deny traffic proves classification, VXLAN SGT
   propagation, and egress enforcement across two edges.
9. ISE PAN failover and an edge reload reconverge without a temporary
   permit-any state.
10. Immutable ISE before/after snapshots, device output, traffic evidence,
    approval, and rollback evidence are attached to the change record.

The current SJC23 POC has no ISE deployment and cannot clear this blocker. It
can validate secret resolution, SXP/SGACL CLI syntax supported by its release,
and rollback behavior only after a dedicated lab listener is provided.
