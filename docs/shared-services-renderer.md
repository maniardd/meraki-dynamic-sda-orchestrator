# Shared-services renderer and acceptance boundary

This phase turns the schema 1.2 shared-services plan into deterministic,
reviewable IOS XE configuration for fusion nodes. It follows Cisco's current
[IOS XE VRF leak examples](https://www.cisco.com/c/en/us/support/docs/ip/ip-routing/216541-vrf-configuration-examples-on-ios-xe.html)
and [VRF-lite configuration
guidance](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/ip-routing/b-ip-routing/m_mp-multi-vrf-vrf-lite.html).

The private COP29 configurations were used only to confirm the general IOS XE
pattern—per-VRF BGP, route targets, prefix lists, and outbound policy. No
customer name, address, ASN, route target, or configuration line is copied into
the fixture or renderer.

## Derived service attachments

Each production fusion node requires one shared-service attachment. The
planner reserves a VLAN and a `/30` or `/31` transport prefix from dedicated
guardrail pools, then derives local and next-hop addresses. A missing,
duplicate, overlapping, or unusable attachment fails validation before
rendering.

## Deny-by-default route leaking

For every fusion node, the renderer creates:

- A service-facing trunk, SVI, and exact static routes to approved service
  prefixes.
- Bounded, hash-named prefix lists and route maps. Existing objects with those
  owned names are removed before replacement so a retry cannot retain a stale
  prefix-list sequence.
- Consumer-VRF export maps containing only that VN's endpoint prefixes.
- Consumer-VRF import maps containing only approved shared-service prefixes.
- Shared-VRF export maps containing only approved service prefixes.
- Shared-VRF import maps containing only approved consumer endpoint prefixes.
- Route-target relationships limited to approved consumer/shared-VRF pairs.
- BGP static-route redistribution only inside the shared-services VRF.

There is no permit-all route-map entry and no generated default route.

## Verification and rollback

The operational gate runs exact `show ip route vrf <vrf> <prefix>` checks on
both sides of every approved leak. The parser requires an exact `Routing entry
for` match and fails on absent-table output.

The schema 1.2 transaction test includes fusion nodes in worker inventory,
creates checkpoints for them, injects a failure during the shared-services
phase, verifies fusion rollback, and releases dynamic allocations only after
verified rollback.

## Remaining blocker

The renderer now reports `shared_services.hardware_acceptance_pending` instead
of `shared_services.renderer_pending`. Apply remains blocked because the SJC23
POC has no fusion device. The blocker can be removed only after the generated
commands, exact route gates, configuration replacement, and rollback are
accepted on compatible IOS XE fusion hardware or a trusted IOS XE virtual lab.

Stateful removal of a service prefix from a previously deployed production
intent must also be tested during that acceptance cycle; current prefix maps
immediately stop leaking a removed prefix, but cleanup of an old static route
must be proven against the target release.
