# PR 17 review resolution: complete Meraki native primitive capture

## Scope

This change extends the genuine development-tenant capture used by the Meraki
workflow compiler. It does not create an import package, enable apply, invoke a
target, or run a workflow. The tenant-specific raw export remains outside the
repository.

The configured root-only export was created with no workflow target, no
Account Key, all activities marked `skip_execution`, and child workflows
excluded. Its canonical SHA-256 is:

`efb6d7806a1ad26447cafbfeb5c3cabd85f2c01ae9ec5b06547eaa3743ba1187`

The structural-only audit reports one workflow, fifteen actions, zero errors,
no Python activity, and no embedded child workflow.

## Genuine native contracts added

The capture adds five Meraki-native types needed to implement the portable
workflow abstractions:

| Portable primitive | Captured Meraki type |
|---|---|
| `while_loop` | `logic.while` |
| `set_variables` | `core.set_multiple_variables` |
| `sleep` | `core.sleep` |
| `parse_json` | `core.parsejson` |
| `json_path_query` | `corejava.jsonpathquery` |

Their exact configured property-key sets are pinned in both the fingerprint
and production manifest. The capture also pins the workflow-variable wrapper,
the `variable_workflow_` identifier prefix, loop branch nesting, the root
action sequence, and the child-workflow dependency reference.

## Fail-closed verification

`verify_capture_fingerprint` compares a raw tenant capture with the committed
structural fingerprint without returning property values. It verifies:

1. the canonical export hash;
2. no-property-value and no-execution safety declarations;
3. export and workflow top-level key sets;
4. workflow type, base type, object type, label, and identifier prefix;
5. workflow property keys and variable wrapper/property keys;
6. every native activity type, base/object type, identifier prefix, and exact
   property-key set;
7. the complete native activity inventory and root order;
8. condition branch/terminal nesting;
9. while-loop branch nesting; and
10. the non-embedded child-workflow dependency cross-reference.

The CLI accepts `--fingerprint` for this check and requires exactly one raw
export. Hash, activity, wrapper, prefix, root-sequence, condition, loop, and
child-dependency tampering fail closed with typed issue codes.

## Safety posture

- The raw tenant export is not committed.
- No property values, credentials, owner email, target IDs, workflow IDs, or
  child-workflow internals are present in the fingerprint.
- `production_ready` remains `false`.
- `importable_exports_present` remains `false`.
- `apply_enabled` remains `false`.
- The Apply child workflow and both executable Apply steps remain disabled.
- No planner, allocator, renderer, worker, reconciliation, ISE executor,
  device adapter, relay, or network execution path changed.

## Verification

Run:

```powershell
python tools/validate_meraki_workflow_package.py --compile --matrix
python tools/audit_meraki_native_export.py `
  --fingerprint workflows/native/capture/activity-fingerprint.v1.json `
  <raw-capture.json>
python -m unittest discover -s tests -q
```

Expected results:

- package validation: `safe_to_build: true`, zero errors;
- capture verification: `capture_fingerprint_valid: true`, zero errors and
  `contains_property_values: false`;
- complete suite: 261 tests, 256 passed, 5 skipped, 0 failures.

## Independent review checklist

1. Verify the PR head exactly and read the complete diff.
2. Reproduce 261 tests: 256 passed, 5 skipped, 0 failures.
3. Confirm the raw Meraki export is not committed.
4. Confirm the new hash and all five native types match this record.
5. Confirm configured property-key sets match across fingerprint, manifest,
   compiler constants, compiled build plan, and tests.
6. Confirm the workflow-variable wrapper and identifier prefix are genuine and
   contain no values or tenant identifiers.
7. Run `--fingerprint` against the separately supplied raw capture and confirm
   zero errors and no property-value output.
8. Confirm hash, type, property-key, prefix, root-order, condition, loop, and
   child-dependency tampering fail closed.
9. Confirm the native serialization contract remains part of the deterministic
   build-plan hash.
10. Confirm all production/import/apply locks remain unchanged.
11. Confirm no execution-path module or customer data was added.

