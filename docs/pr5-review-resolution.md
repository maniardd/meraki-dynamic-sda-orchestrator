# PR #5 review resolution

The independent review of commit `22387439a868f4ce17823045fd66e0e32b459c1a`
returned PASS with one Medium and four Low follow-ups. This record maps every
item to its resolution and regression coverage.

## M1: per-VRF fusion redundancy

Closed. Production allocation now enforces
`fusion.min_fusion_nodes_per_border_vrf_production`, defaulting to two. Every
border/VRF pair must therefore be expanded to at least two distinct fusion
nodes even when an adjacency explicitly narrows `virtual_networks`.

Intent validation independently rejects drift that leaves a production
border/VRF pair with fewer than two fusion peers using
`bgp.border_vrf.insufficient_fusion_redundancy`.

Regression coverage narrows `Media` on one border/fusion adjacency and proves
that allocation fails closed.

## Low follow-ups

- **L1, shared-service overlap:** allocator and intent validator now reject a
  shared-service prefix that overlaps any fabric endpoint pool. Tests cover
  requirements-time and derived-intent drift.
- **L2, SSM range:** allocator and intent validator parse `ssm_range` as a
  strict IPv4 CIDR and require it to be inside `232.0.0.0/8`.
- **L3, SXP listener reference:** ISE and hybrid modes now require every SXP
  listener address to match an approved ISE node. Pure SXP mode remains able to
  reference an external listener without an ISE node list.
- **L4, artifact version clarity:** rendered output now uses
  `artifact_schema_version` for its own contract and `intent_schema_version`
  for the input intent, eliminating the ambiguous hard-coded field.

## Additional negative coverage

The acceptance suite now explicitly covers missing fusion peers, missing
border/VRF peers, per-VRF fusion single-homing, invalid ASM-without-RP, invalid
SSM range, SGT exhaustion, duplicate policy contracts, shared-service overlap,
and unapproved hybrid SXP listeners. Existing remote-AS, multicast-mode,
duplicate-SGT, and service-address tests remain in place.
