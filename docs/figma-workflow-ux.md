# Meraki dynamic SDA workflow UX

The editable Cisco-enterprise Figma storyboard is:

<https://www.figma.com/design/7vFainpEldsvd2ho0AGgfO>

It uses CiscoSansTT and reusable Cisco Momentum for Web primitives. The
`SDA Production Workflow` page contains three 1440 × 1024 desktop views:

1. **Plan Fabric** — business intent, hierarchy, address pools, VNs, policy
   selection, live derived allocation count, and preflight blockers.
2. **Review & Approve** — immutable plan/artifact hashes, topology and role
   assignments, derived allocations, approval expiry, change reference,
   acknowledgement, and dual-control decision.
3. **Dry Run & Evidence** — zero-write proof, phase timeline, hash-bound
   evidence, production acceptance progress, and a visibly unavailable Apply
   action.

## Native Meraki mapping

The storyboard is a product and interaction specification. It does not claim
that Meraki Workflows supports arbitrary custom screens.

| Storyboard interaction | Meraki-native implementation |
| --- | --- |
| Requirements form | Workflow inputs and Create Prompt tasks |
| Generate design | HTTP Request child calling `/v1/workflow-actions/plan` |
| Immutable review | Create Prompt summary built from plan response |
| Approval decision | Request Approval with separate due and expiration bindings |
| Dry-run timeline | Start Dry Run plus bounded status polling |
| Evidence view/export | Evidence child plus result-summary prompt |
| Apply unavailable | Apply child and executable activities remain absent/disabled |

The richer control-center view can later be implemented as a separate portal,
but Meraki remains the workflow entry point and approval surface. Any portal
must call the same authenticated, hash-bound orchestrator APIs and cannot
bypass the production acceptance registry.

## QA record

- Three screens, each exactly 1440 × 1024.
- CiscoSansTT is the only text family.
- Primary navigation targets are at least 45 px high.
- No unnamed nodes remain within the three screens.
- Screenshots were inspected after each major section for clipping and
  overflow.
- The final evidence screen contains an explicit
  `Apply unavailable — 16 gates pending` state.
