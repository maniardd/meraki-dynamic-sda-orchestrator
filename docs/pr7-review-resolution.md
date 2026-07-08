# PR #7 review resolution

## Independent result

Claude independently ran 185 tests (180 passed, 5 skipped, 0 failed), read the
complete diff at `8fae875`, and returned **PASS — safe to merge while
`lisp_pubsub.hardware_acceptance_pending` remains enabled**.

## Finding resolution

### M1 — configuration hierarchy: closed with authoritative evidence

Cisco's IOS XE LISP VXLAN guide explicitly enters top-level/default
`router lisp` `service ipv4`, then shows `map-cache publications`,
`import publication publisher`, `route-export publications`, and
`distance publications` at the `config-router-lisp-serv-ipv4` prompt. The
renderer already matches that hierarchy. The per-IID command used by the gate
is an operational view of publication propagation, not evidence that those
commands belong under each `instance-id`.

Reference: [Cisco IOS XE 17.9 LISP VXLAN Fabric in a Box configuration
guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-9/configuration_guide/lisp_vxlan/b-179-lisp-vxlan-fabric-cg/branch-deployment-wired-devices.html).

### M2 — domain and multihoming identity: accepted as a hard prerequisite

The acceptance document now explicitly requires `domain-id` and the
topology-specific `multihoming-id` contract to be modeled in intent/guardrails,
rendered, and verified before the blocker can be cleared. The current PR does
not claim that capability is complete.

### L1 — colocated duplicate commands: fixed

The Pub/Sub subscriber block now leaves encapsulation, map-server,
map-resolver, and proxy ownership to the existing control-plane block on a
colocated node. A separated border subscriber still receives the required
encapsulation and proxy configuration.

### L2 — Ethernet/EID Pub/Sub: scoped explicitly

The acceptance document now states that this renderer covers IPv4 prefix
Pub/Sub. Existing classic Ethernet LISP behavior is unchanged; IOS XE 17.18
EID Pub/Sub or additional Layer 2 publication behavior requires its own model,
renderer, and platform acceptance before enablement.

## Safety status

The hardware/platform-acceptance blocker remains unconditional. Production
apply is still unreachable for LISP Pub/Sub artifacts.

## Independent re-review outcome (2026-07-08)

**Reviewer:** Claude (independent)

**Delta reviewed:** `8fae875` to `0101ff7`

**Method:** isolated worktree, complete delta review, and independent full-suite run.

**Final result: PASS — no remaining blocking findings.** Claude independently
reproduced 186 tests: 181 passed, 5 skipped, and 0 failed.

The re-review confirmed:

1. M1 is closed by Cisco's documented top-level/default `router lisp` to
   `service ipv4` hierarchy and a no-`instance-id` regression assertion.
2. The per-IID command is an operational `show` gate, not configuration
   placement.
3. `domain-id` and topology-specific `multihoming-id` remain explicit hard
   prerequisites before platform acceptance can pass.
4. Colocated border/control-plane nodes no longer receive duplicate
   encapsulation, proxy, map-server, or map-resolver commands.
5. Separated border/control-plane roles retain the required transport and
   proxy commands.
6. IPv4 prefix Pub/Sub is the explicit scope; Ethernet/EID Pub/Sub requires
   separate modeling and acceptance.
7. `lisp_pubsub.hardware_acceptance_pending` remains unconditional and apply
   remains unreachable.
8. No customer data, real credentials, or private configuration was added.

Claude concluded that PR #7 is safe to merge while the platform-acceptance
blocker remains enabled. The `domain-id`/`multihoming-id` implementation is the
only required carry-forward from this review.
