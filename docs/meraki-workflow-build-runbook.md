# Meraki Dynamic SDA Workflow Build Runbook

## Current release status

The portable workflow contract is complete and validated. It is not yet a
tenant-native Meraki import package and it is not authorized to apply changes.
These are separate gates:

| Gate | State | Meaning |
|---|---|---|
| Dynamic planner/API | Complete | Requirements produce deterministic allocations, intent, plan, and rendered artifacts. |
| Portable Meraki build specification | Complete | Workflows, roles, paths, inputs, outputs, bounds, and failure branches are machine validated. |
| Native Meraki serialization schema | Complete | Configured activity, logic, and child-workflow shapes were captured from the development tenant without execution. |
| Native Meraki assembly contract | Complete | Every portable step is mapped to captured native primitives with deterministic sequencing and fail-closed invariants. |
| Native Meraki package exports | In progress | Parent and four dry-run children are assembled and child-tested in the development tenant; corrected exports, structural audit, and duplicate import remain pending. |
| Dry-run workflow | Software complete | It can be assembled and tested without touching switches. |
| Apply workflow | Disabled | Native export validation plus SJC23 hardware/API/reconciliation acceptance are required first. |
| Exchange publication | Disabled | Pilot evidence and publishing review are required first. |

Do not relabel the old `SDA Fabric Full Deployment` export as production. It
uses an inline relay URL, Python HTTP calls, disabled TLS verification, the
legacy V2 API, one static fabric, and no separated service identities.

## Development-tenant observation (2026-07-22)

The SJC23-SDA development tenant was inspected without running a workflow. A
non-executable, no-target capture workflow was created solely to export the
native activity envelope. The catalog and export contain the required building
blocks:

- `HTTP Request` under Web Service (including the separate Swagger variant),
- `Create Prompt` under Task,
- `Request Approval` under Task, and
- reusable workflows through the Workflows tab.

The workspace originally contained four workflows. `SDA Fabric Full Deployment`
is the original static POC and must remain a reference only. The genuine
`Test Import - Minimal_Meraki_Exported.json` export proves the native envelope:
`generic.workflow`, tenant-generated `definition_workflow_*` IDs, and
tenant-generated `definition_activity_*` IDs. It does not provide the native
HTTP, prompt, approval, or child-workflow property schema, so those activity
definitions must still be captured from a tenant-created workflow rather than
invented.

`SDA Native Activity Capture v1` now supplies the complete configured schema
capture. The root-only export was generated without running or validating the
workflow, with every activity marked `skip_execution`, no workflow target, and
no Account Key. Its canonical export hash is
`efb6d7806a1ad26447cafbfeb5c3cabd85f2c01ae9ec5b06547eaa3743ba1187`.
The secret-safe auditor reports one workflow, fifteen native actions, zero errors,
no Python activity, and no embedded child-workflow internals.

The capture pins the configured property-key shapes for
`web-service.http_request`, `task.prompt_request`,
`task.request_approval`, `logic.if_else`, `logic.condition_block`,
`logic.completed`, `workflow.sub_workflow`, `logic.while`,
`core.set_multiple_variables`, `core.sleep`, `core.parsejson`, and
`corejava.jsonpathquery`. It also pins the native workflow-variable envelope,
`blocks`/`actions` condition and loop nesting, and the root
`dependent_workflows` reference used by a child-workflow invocation. Only the secret-free structural
fingerprint is committed at
`workflows/native/capture/activity-fingerprint.v1.json`; the tenant-specific
raw export and all property values remain outside the repository.

## Source-of-truth files

- `workflows/production_workflow_manifest.yaml` is the portable workflow and
  security contract.
- `workflows/environment-bindings.example.yaml` lists names that are bound in
  the Meraki installation wizard; it contains no endpoint or credential.
- `workflows/operator-request.example.yaml` shows a plan-only request.
- `schemas/fabric-requirements.schema.json` defines the dynamic user
  requirements accepted by the planner.
- `orchestrator/meraki_workflow_package.py` validates and compiles the build
  contract.
- `docs/meraki-native-assembly-contract.md` defines how each portable activity
  is assembled from the genuine captured Meraki primitives.
- `tools/validate_meraki_workflow_package.py` is the operator/CI command.
- `orchestrator/meraki_native_export.py` inventories real tenant exports
  without emitting property values and fails closed on unsafe or incomplete
  packages.
- `tools/audit_meraki_native_export.py` is the native-export intake command.

Run the validation from the repository root:

```powershell
python tools/validate_meraki_workflow_package.py --compile --matrix
```

Success means `safe_to_build: true`. It intentionally reports
`production_ready: false`, `importable_exports_present: false`, and
`apply_enabled: false` at this stage.

Validate the independent production evidence and sign-off registry:

```powershell
python tools/validate_production_acceptance.py
python tools/validate_production_acceptance.py --require-ready
```

The first command proves the registry is structurally and cryptographically
valid. The second remains blocked until every required gate and sign-off is
complete. See `docs/production-acceptance-registry.md`.

Audit a newly exported native workflow without requiring the whole package:

```powershell
python tools/audit_meraki_native_export.py --inventory-only path\to\export.json
```

Verify the exact configured capture against the committed structural
fingerprint before changing the compiler contract:

```powershell
python tools/audit_meraki_native_export.py `
  --fingerprint workflows\native\capture\activity-fingerprint.v1.json `
  path\to\SDA-Native-Activity-Capture.json
```

This binds the provenance hash, workflow/variable wrappers, native activity
types, property-key sets, identifier prefixes, and root topology while still
returning no property values.

After all parent and child workflows are exported, validate the set against
the portable manifest:

```powershell
python tools/audit_meraki_native_export.py `
  --manifest workflows\production_workflow_manifest.yaml `
  workflows\native\*.json
```

The command reports only workflow/action structure and property-key names. It
does not print property values, Account Keys, or target credentials.

## Why the first Meraki UI accepts requirements JSON

Meraki Create Prompt tasks provide text, checkbox, and dropdown form elements.
They are suitable for change controls, mode selection, approval, and status,
but not for safely editing an arbitrary repeating hierarchy of sites, devices,
links, VNs, subnets, fusion adjacencies, multicast policy, ISE nodes, SXP
sessions, security groups, and contracts.

The first production workflow therefore collects:

1. A versioned requirements JSON document.
2. Requested mode: plan only, dry run, or apply.
3. Change reference.
4. Approval expiry.
5. Maintenance window for apply.

The requirements document contains demand and topology facts. It does not
contain allocated underlay/overlay prefixes, VLAN/VNI values, route targets,
SGTs, or generated CLI. The orchestrator derives and reserves those values in
the PostgreSQL ledger. This is dynamic planning, not a renamed static template.

A guided multi-screen UI can later construct the same requirements document.
It must not create a second planning contract.

## Build the native Meraki objects

### 1. Prepare trusted ingress

Provide the orchestrator with a stable DNS name and a publicly trusted HTTPS
certificate. Do not use an ngrok URL, an IP-address certificate exception, or
disabled TLS validation. Keep `/health` and `/ready` unauthenticated only as
implemented; every workflow action remains authenticated and role-authorized.

### 2. Create four service identities

Create independent API identities for `planner`, `approver`, `operator`, and
`auditor`. Store only their hashes and role grants in the orchestrator. Enter
their plaintext values once in Meraki Account Keys; do not place them in Git,
workflow descriptions, ordinary variables, screenshots, or evidence.

### 3. Create four HTTP Endpoint targets

Create these exact target names with the same trusted base URL and different
Account Keys:

| Target | Role | Permitted workflow actions |
|---|---|---|
| SDA Orchestrator - Planner | planner | plan, retrieve owned-state baseline |
| SDA Orchestrator - Approver | approver | record approval, adopt baseline |
| SDA Orchestrator - Operator | operator | create/process run, status |
| SDA Orchestrator - Auditor | auditor | evidence and audit chain |

Use HTTP Bearer Authentication when it is available in the tenant. HTTP Custom
Header Authentication or client-certificate authentication is an acceptable
planned alternative. The role must still be a separate backend identity.

### 4. Assemble child workflows first

Use the compiled `native_implementation` on every step and the exact composite
sequences in `docs/meraki-native-assembly-contract.md`. The compiler does not
fabricate Meraki identifiers or claim to emit importable JSON; the tenant must
generate those values.

Build the child workflows in this order:

1. `SDA Fabric - Validate and Plan`
2. `SDA Fabric - Request Approval`
3. `SDA Fabric - Start Dry Run`
4. `SDA Fabric - Export Evidence`
5. `SDA Fabric - Bootstrap Owned-State Baseline` (disabled)
6. `SDA Fabric - Start Apply` (disabled)

For every HTTP Request activity:

- Select the role-specific target.
- Use the explicit relative URL from the manifest; do not use a variable for
  the path.
- Use `POST` and `application/json` for Content-Type and Accept.
- Disable auto redirect and sensitive-header redirect.
- Enable continuation on HTTP error status, then immediately branch on the
  exact expected status code.
- Build complex JSON bodies in a dedicated JSON-building activity; never
  concatenate unescaped input into JSON.
- Extract only the fields in the corresponding output contract.

### 5. Configure native approval

Use the Meraki Request Approval activity, not a Boolean input pretending to be
approval. Show the plan ID/hash, artifact hash, device count, blockers, change
reference, expiry, and rollback scope. Require at least one approval, the
acknowledgement checkbox, and a comment. The approval callback must run through
the Approver target so the backend records the authenticated approver.

For production, the backend rejects requester self-approval. Assignment by
Meraki role is acceptable for the lab; production assignment must follow the
organization's change-approval group.

### 6. Configure bounded status polling

The dry-run and apply children use 16 attempts at 15-second intervals. A run
that does not reach a terminal state is returned as pending and continued by a
separate monitor run; do not add an unbounded loop or hold a single workflow
open for a large campus deployment.

### 7. Assemble the parent

Use the exact sequence in the manifest:

```text
Prompt -> validate mode -> plan -> review -> approval -> dry run
       -> optional locked apply -> evidence
```

Plan-only stops after review. Dry-run stops after evidence. Apply remains
unreachable because the child and its two executable activities are disabled.

### 8. Validate and export

For each workflow:

1. Add a workflow description and descriptions for every input/output.
2. Run the Meraki editor validation until it has no errors.
3. Lock the workflow.
4. Export it as JSON from Meraki, including child workflows for the package
   export.
5. Import the export as a duplicate and remap all targets in the installation
   wizard.
6. Run plan-only and dry-run tests.
7. Place the sanitized exports under `workflows/native/` and run the repository
   export audit before changing `importable_exports_present`.

Meraki-generated workflow/action identifiers are intentionally not fabricated
by this repository. The first tenant export is the serialization reference for
future deterministic packaging.

## Acceptance before enabling apply

Apply may be enabled only after all of the following evidence is approved:

- Native parent and child exports import cleanly into a duplicate workspace.
- Role-negative tests prove planner cannot approve/apply, approver cannot plan
  or apply, operator cannot approve, and auditor is read-only.
- Same request and idempotency key return the same plan/run.
- Changed requirements create a different immutable hash and invalidate prior
  approval.
- SJC23 read-only precheck proves the real management plane, interfaces,
  platform, software release, and checkpoint support.
- Hardware acceptance proves underlay, LISP, VXLAN, multicast, BGP/fusion,
  policy/SXP/ISE (when selected), parsers, phase gates, and verified rollback
  on the representative topology.
- Reconciliation proves an approved owned-state baseline and removal/mode-change
  behavior.
- Every renderer `blocking_requirements` item is closed by named evidence.
- Security review confirms stable ingress, trusted TLS, secret rotation,
  database backup, audit retention, alerting, and worker recovery.

The acceptance decision is joint: the network design authority signs the
fabric behavior, the automation owner signs the software/evidence, the system
owners sign ISE/ingress/database controls, and the authorized change approver
permits the pilot. No single test counter or developer declaration clears it.
Those decisions and the hashes of their evidence are recorded in
`acceptance/production-acceptance.sjc23.yaml`.

## Official Meraki references

- [Import and Export a Workflow](https://documentation.meraki.com/Platform_Management/Workflows/Workflows/Import_and_Export_a_Workflow)
- [HTTP Request activity](https://documentation.meraki.com/Platform_Management/Workflows/Workflows/Activities/HTTP_Request)
- [Targets Account Keys](https://documentation.meraki.com/Platform_Management/Workflows/Targets/Targets_Account_Keys)
- [Request Approval Task](https://documentation.meraki.com/Platform_Management/Workflows/Tasks/Request_Approval_Task)
- [Create Prompt Task](https://documentation.meraki.com/Platform_Management/Workflows/Tasks/Create_Prompt_Task)
