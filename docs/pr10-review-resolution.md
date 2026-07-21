# PR #10 independent-review resolution

This record addresses the independent findings reported against PR #10 at
`12c03a7b0fe2dc776bcc868c8454f28cd3e9da6c`. The branch was first rebased onto
the accepted PR #9 head `bfd3e9cec9d293aaf7fbf181731ba1716fa86c1d`.

## Resolution decisions

1. **Intra-1.2 compatibility:** the strong policy contract now declares
   `policy_plane.contract_version: "1.0"`. New required fields are conditional
   on that discriminator. Stored pre-contract schema 1.2 requirements and
   intents are rejected with one explicit migration-required error rather than
   generic missing-field cascades. They are not silently upgraded or replayed.
2. **VRF-scoped SXP defaults:** the release-dependent device-global
   source/password behavior is an explicit hardware-acceptance item. The
   unconditional `policy_plane.hardware_api_acceptance_pending` blocker remains
   enabled, and captured target-release output is required before removal.
3. **ISE URL ports:** both JSON schemas restrict optional ports to `1..65535`.
   The allocator and intent validator also parse and range-check the port.
   Regression coverage rejects `0`, `65536`, and `99999`, while accepting
   `65535`.
4. **Operational and API proof:** SXP/role parser fixtures and the ISE executor
   remain hardware/API acceptance work. The manifest is still structurally
   unreachable from the transaction worker; documentation now makes the
   executor, owned-resource snapshots, verify-after-write, and injected API
   rollback proof explicit prerequisites.

No acceptance blocker is cleared. No ISE credential, device, relay, Meraki
organization, or customer configuration is used by these changes.

## Verification

- Focused migration, URL-boundary, Fusion rollback, and SXP rollback tests:
  **4 passed, 0 failed**.
- Full rebased local suite: **216 tests, 5 skipped, 0 failures**.
- Both JSON schemas parse successfully and `git diff --check` is clean.
- `policy_plane.hardware_api_acceptance_pending`,
  `multicast.hardware_acceptance_pending`, and
  `multicast.reconciliation_pending` remain enforced; `executable:false`
  remains intact.
