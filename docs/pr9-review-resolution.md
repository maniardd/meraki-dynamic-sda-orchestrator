# PR #9 independent-review resolution

This record resolves the five findings in the independent review of PR #9 at
`31fff8559966db7571922186972ca18fcc30c91a`. No device, relay, credential, or
production state was used or changed. All production blockers remain enabled.

## Resolution summary

1. **Pre-1.2 version behavior:** the new `overlay_policies` and
   `l2_bum_groups` fields are required only by the schema 1.2 conditional.
   Schema 1.0/1.1 documents that inject the 1.2 top-level `multicast` contract
   now fail with the explicit `multicast.unexpected` validator code or the
   allocator message `Top-level multicast requirements require schema_version
   1.2`; they no longer fail with misleading missing-property errors. The
   legacy `fabric.multicast` contract and its renderer fallbacks remain intact.
2. **PIM parser:** sparse-mode acceptance uses an exact allow-list of `S` and
   `SM`. Sparse-dense (`SD`) and dense (`D`) rows fail closed.
3. **Stale-state safety:** every schema 1.2 multicast lifecycle now emits the
   independent `multicast.reconciliation_pending` blocker. It remains present
   when multicast is disabled, preventing removal from stranding prior state.
   A regression also flips both VNs between ASM and SSM, proves their owned ACL
   identities change, and verifies the blocker remains. This blocker may be
   removed only after a last-committed owned-state manifest and deterministic
   prune/negation phase are implemented and accepted.
4. **Passive edge SVIs:** passive SVIs are no longer interpreted as sparse-mode
   operational rows. Each receives an exact running-config gate for
   `ip pim passive`, IGMPv3, and explicit tracking. Loopback, LISP, border, and
   fusion interfaces retain the strict operational sparse-mode gate.
5. **Fusion rollback:** a dedicated failure-injection test rejects an ASM
   `ip pim vrf ... rp-address ...` command on `fusion-01`, proves verified
   checkpoint rollback, and proves the IPAM reservation is released only after
   rollback succeeds.

## Verification

- Focused regression set: 117 tests passed after the single test-expectation
  correction; no implementation failure remained.
- Full local `unittest` discovery: **206 tests, 5 skipped, 0 failures**.
- `git diff --check`: clean (line-ending notices only).
- The unconditional `multicast.hardware_acceptance_pending` blocker remains.
- The new `multicast.reconciliation_pending` blocker is also unconditional for
  schema 1.2 multicast lifecycle changes.
- `executable:false` remains derived from the non-empty blocker set.

The five review findings are closed at the software-review boundary. Hardware
acceptance and state-reconciliation implementation are still separate, visible
release gates and must not be represented as complete.
