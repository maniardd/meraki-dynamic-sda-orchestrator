# PR #13 review resolution

## Reviewed head

- Original head: `52fc232`
- Verdict: PASS WITH FINDINGS
- Finding: one Low runtime-budget validation gap

## Resolution

The shipped manifest already declared a 60-second request timeout and a
1,500-second parent runtime budget. The validator previously converted absent
or zero values to zero and guarded the duration comparison with
`if max_parent_runtime`. That allowed an edited manifest to skip the aggregate
poll-duration check while remaining bounded to 100 attempts.

The validator now requires both `request_timeout_seconds` and
`max_parent_runtime_seconds` to be positive, non-Boolean integers. Missing,
zero, negative, Boolean, and string values produce typed fail-closed issues:

- `runtime.request_timeout`
- `runtime.parent_budget`

The duration comparison executes only after both required values pass type and
range validation. This avoids both the original bypass and unhandled integer
conversion errors.

## Regression coverage

- Each runtime field is tested with missing, zero, negative, Boolean, and
  string values.
- The reported 100-attempt, 60-second poll with a zero parent budget is
  reproduced and rejected.
- The shipped manifest remains unchanged and validates with zero issues.

No workflow route, role, target, HTTP operation, approval rule, compiler
output, apply flag, execution path, or native-export claim changed.
