# PR 18 review resolution: Meraki native assembly contract

## Scope

This change converts the portable workflow vocabulary into a deterministic
assembly contract using only the genuine native Meraki primitives captured and
accepted in PR 17. It does not create importable JSON, fabricate tenant
identifiers, enable Apply, run a workflow, or touch the orchestrator execution
path.

## Contract

Every portable activity has exactly one reviewed recipe. Direct mappings cover
HTTP Request, Create Prompt, Request Approval, and child workflows. Composite
recipes cover conditions, approval decisions, JSON body preparation, and
bounded polling. Aliases cover JSONPath extraction and non-blocking result
summaries.

The JSON recipe parses the complete JSON input before use, permits only a fixed
request-body template, forbids quoted interpolation of user-controlled scalar
text, and explicitly requires tenant evidence for payload substitution. This
avoids claiming that Parse JSON is a serializer and preserves the no-Python
package policy.

The compiler copies the complete assembly contract into the deterministic
build plan and attaches the matching recipe to every compiled step. Validation
requires exact equality with the reviewed contract, complete portable-activity
coverage, and references only to captured native primitives.

## Fail-closed behavior

The following changes make the package unsafe to build and prevent compilation:

- changing the tenant-identifier policy;
- adding or removing a portable recipe;
- changing a native sequence or loop-body sequence; or
- referencing an uncaptured primitive such as Python.

## Safety posture

- `compiler_emits_importable_json` remains `false`.
- `tenant_identifier_policy` is `tenant_generated_only`.
- `production_ready`, `importable_exports_present`, and `apply_enabled` remain
  `false`.
- The Apply child workflow and its HTTP/poll execution steps remain disabled
  in both the manifest and compiled build plan.
- No raw tenant export, property value, credential, target binding, tenant ID,
  customer data, or network configuration was added.
- No planner, allocator, renderer, worker, reconciliation, ISE executor,
  adapter, relay, or network execution path changed.

## Verification

Run:

```powershell
python tools/validate_meraki_workflow_package.py --compile --matrix
python -m unittest discover -s tests -q
```

Expected results:

- package validation: `safe_to_build: true`, zero errors,
  `production_ready: false`, `importable_exports_present: false`, and
  `apply_enabled: false`;
- complete suite: 263 tests, 258 passed, 5 skipped, 0 failures.

## Independent review checklist

1. Verify the exact PR head and read the complete diff.
2. Reproduce 263 tests: 258 passed, 5 skipped, 0 failures.
3. Confirm all ten portable activity types have exactly one recipe.
4. Confirm every recipe uses only a primitive in the accepted PR 17 capture.
5. Confirm the five explicit expansions: approval rule, bounded poll, JSON
   build, JSONPath extraction, and result summary.
6. Confirm JSON parsing precedes state assignment, no arbitrary scalar
   interpolation is permitted, and payload-substitution acceptance remains
   required.
7. Confirm every compiled step carries the matching native recipe.
8. Confirm tampered identifier policy, recipe coverage, sequence, or primitive
   fails closed and cannot compile.
9. Confirm the complete assembly contract participates in the deterministic
   build-plan hash.
10. Confirm tenant identifiers remain tenant-generated and the compiler does
   not claim to emit importable JSON.
11. Confirm all production/import/apply locks remain enforced in the manifest
    and compiled plan.
12. Confirm no execution-path module, raw export, credentials, endpoints,
    target bindings, customer data, or network configuration were added.
