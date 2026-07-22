# Meraki native assembly contract

## Purpose

This contract translates the portable SDA workflow manifest into the genuine
Meraki Workflow primitives captured from the development tenant. It is a
deterministic assembly recipe, not fabricated importable JSON. Meraki must
generate every `definition_workflow_*`, `definition_activity_*`, and
`variable_workflow_*` identifier when an operator creates the tenant objects.

The contract is pinned in `workflows/production_workflow_manifest.yaml`,
validated by `orchestrator/meraki_workflow_package.py`, and copied into the
compiled build plan and every compiled step. Changing a recipe, primitive,
sequence, invariant, or identifier policy makes validation fail closed.

## Portable-to-native mapping

| Portable activity | Native Meraki assembly |
|---|---|
| `create_prompt` | `task.prompt_request` |
| `request_approval` | `task.request_approval` |
| `http_request` | `web-service.http_request` |
| `child_workflow` | `workflow.sub_workflow` |
| `condition` | `logic.if_else` with `logic.condition_block` branches and explicit `logic.completed` termination |
| `approval_task_rule` | The same condition/branch/termination structure, matching the exact approval outcome |
| `build_json` | Validate the complete JSON input with `core.parsejson`, then use `core.set_multiple_variables` for constrained state; the HTTP body uses a fixed template |
| `json_path_extract` | `corejava.jsonpathquery` limited to the declared output contract |
| `result_summary` | Non-blocking `task.prompt_request` with `wait_for_prompt_response` disabled |
| `bounded_poll` | Initialize with `core.set_multiple_variables`; execute `logic.while`; inside the loop run HTTP request, exact condition, bounded sleep, and counter update |

The compiler uses portable names in its recipes because those names are stable
and map one-to-one to the captured native type table in
`native_serialization.activity_types`. Tests prove every referenced primitive
exists in that captured table.

## JSON body safety

Cisco documents that text composed directly in the HTTP Request body does not
escape nested quotes. This package therefore does not interpolate arbitrary
user-controlled scalar strings into quoted JSON positions and does not use a
Python activity. The requirements document is parsed before use and is inserted
only as one complete JSON value into a fixed request template. IDs, modes,
timestamps, and counters must come from typed workflow values, fixed enums, or
backend-generated outputs.

This substitution behavior must be proven in the development tenant with
quotes, backslashes, Unicode, empty values, nested arrays/objects, and the
maximum accepted payload before native exports can be accepted. The recipe
carries `payload_substitution_acceptance_required`; the production/import/apply
locks remain closed until that evidence exists. See Cisco's
[HTTP Request activity guidance](https://documentation.meraki.com/Platform_Management/Workflows/Workflows/Activities/HTTP_Request).

## Bounded polling assembly

The polling composite must be assembled in this order:

1. Initialize the attempt counter and terminal-state flag.
2. Enter a `While` activity bounded by the configured maximum attempts.
3. Send the fixed-path status HTTP request.
4. Immediately branch on HTTP status; an unexpected status terminates the
   workflow as failed.
5. Parse the returned run status and compare it with the exact terminal status
   allow-list.
6. Terminate on a recognized terminal status.
7. Sleep only when the state is non-terminal and attempts remain.
8. Increment the counter before the next evaluation.
9. Exit as pending when the attempt budget is exhausted; never create an
   unbounded loop.

## Tenant assembly rules

1. Create the six child workflows in the runbook order, then the parent.
2. Use the compiled step order and the `native_implementation` attached to each
   step.
3. Use only tenant-generated workflow, action, and variable identifiers.
4. Bind role-specific targets through the installation wizard; never put a
   URL, token, Account Key, or credential in the export or repository.
5. Keep the Bootstrap child, Apply child, and both executable Apply steps
   disabled.
6. Validate in the Meraki editor, export without running, and audit the export
   before any plan-only test.

## Release boundary

This contract closes the portable-to-native design ambiguity. It does not
claim that tenant exports already exist and does not authorize execution:

- `compiler_emits_importable_json` is `false`;
- `tenant_identifier_policy` is `tenant_generated_only`;
- `production_ready` is `false`;
- `importable_exports_present` is `false`;
- `apply_enabled` is `false`; and
- the Apply workflow and executable steps remain disabled.

The next release artifact is a set of genuine tenant exports assembled from
this contract, independently audited, re-imported into a duplicate workspace,
and proven with plan-only and dry-run tests. Hardware and API acceptance are
separate later gates.
