# PR #16 review resolution: configured Meraki serialization

## Scope

This change replaces the structural-only first capture with a configured,
root-only export of `SDA Native Activity Capture v1`. The capture was created
in the development tenant without assigning a workflow target, Account Key, or
credential and without validating or running the workflow. Every executable
activity and the child-workflow invocation has `skip_execution` enabled.

The tenant-specific raw export is not committed. Only structural metadata,
property-key names, native types, collection-key topology, and the canonical
export SHA-256 are retained.

## Capture and audit evidence

- Canonical export SHA-256:
  `0550cc91613a5d8d91b1e81d0e9c9670c1dea5b259de2d7592f49d35054bf4aa`
- Export mode: root workflow only; dependent child workflow not embedded.
- Auditor result: `native_export_valid: true`, `error_count: 0`,
  `warning_count: 0`, `workflow_count: 1`, `action_count: 9`.
- Auditor privacy flag: `contains_property_values: false`.
- No Python, inline secret, ngrok, legacy `/api/v2/`, disabled TLS, target
  binding, or credential is present in the committed fingerprint.

## Pinned native contract

The manifest, validator, fingerprint, and compiled build plan agree on these
native types:

| Portable activity | Captured Meraki type |
|---|---|
| `http_request` | `web-service.http_request` |
| `create_prompt` | `task.prompt_request` |
| `condition` | `logic.if_else` |
| `condition_branch` | `logic.condition_block` |
| `completed` | `logic.completed` |
| `request_approval` | `task.request_approval` |
| `child_workflow` | `workflow.sub_workflow` |

The configured property-key inventory is exact for the workflow and every
native activity. The topology contract additionally pins:

- root action order: HTTP, prompt, condition, approval, child workflow;
- condition children under `blocks`;
- branch activities under each branch's `actions`; and
- dependent child workflow IDs under root `dependent_workflows`, with child
  internals excluded from the export.

## Fail-closed behavior

Package validation rejects:

- `configured_properties_complete` other than `true`;
- missing, extra, or renamed native activity mappings;
- changed native activity or workflow identifier prefixes;
- missing, extra, malformed, or renamed property keys; and
- altered condition or child-workflow topology.

The compiler carries the provenance hash, configured-complete flag, exact
workflow/activity property keys, native types, and topology into the
deterministic build-plan hash.

## Safety and release state

- `package.production_ready` remains `false`.
- `package.importable_exports_present` remains `false`.
- `safety.apply_enabled` remains `false`.
- The `start_apply` child and both executable apply steps remain disabled.
- No planner, worker, renderer, ISE, reconciliation, device adapter, relay, or
  switch execution path changed.

## Verification

- Configured native export audit: zero errors and zero warnings.
- Focused Meraki package/native-export tests: 21 passed.
- Full unittest discovery: 259 tests, 254 passed, 5 environment skips,
  0 failures.
- Package compiler: `safe_to_build: true`, `error_count: 0`,
  `production_ready: false`, `importable_exports_present: false`,
  `apply_enabled: false`.
- Deterministic build-plan hash:
  `4a5d0a5a879815800302ecf92b665822a163689968793e7316bfe69234b80aae`.

## Independent review checklist

1. Re-run the full suite and confirm 259 tests with 5 environmental skips.
2. Confirm the raw tenant export is absent from the diff.
3. Confirm the fingerprint contains keys/types/topology only and no property
   values, credentials, owner email, target ID, or child-workflow ID.
4. Confirm all seven types and their exact property-key sets match the manifest
   and validator constants.
5. Tamper each configured-complete flag, property-key set, type, identifier
   prefix, and topology key; each must make `safe_to_build` false.
6. Confirm the compiler folds the complete native contract into the build-plan
   hash.
7. Confirm production/importable/apply flags and the disabled apply steps are
   unchanged.
