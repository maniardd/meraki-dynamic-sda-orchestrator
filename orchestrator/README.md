# SDA Orchestrator Foundation

This package is the side-effect-free foundation for the production Meraki
Workflows-driven SDA-style fabric solution.

Current capabilities:

- Load versioned YAML fabric intent.
- Reject invalid topology, references, addressing, identifiers, roles, and HA.
- Reject inline credentials and require `secret://` references.
- Expose authenticated validation and planning endpoints.
- Produce deterministic plan IDs and plan hashes for later approval binding.
- Persist immutable intents, plans, approvals, runs, evidence, locks, and a
  hash-chained audit trail.
- Enforce separate planner, approver, operator, viewer, and auditor roles.
- Render deterministic per-device IS-IS, LISP/VXLAN, VRF, endpoint-pool, and
  BGP handoff command artifacts without resolving secret values.
- Simulate the complete approved dry-run path without contacting devices.
- Execute a bounded transactional worker contract with exact pre/post gates,
  checkpoints, and rollback in isolated tests.
- Keep live execution disabled until the production secret manager, durable
  queue, and hardware rollback acceptance tests pass.

Device address semantics:

- `management_ip` is the address used by the bounded execution adapter from the
  relay server.
- `dashboard_management_ip` is optional inventory metadata reported by Meraki
  Dashboard and is never selected as an execution target.
- `border_handoff.mode: isolated` explicitly acknowledges a lab with no fusion
  or external Layer-3 handoff. Production still requires enabled BGP mode.

## Supported Runtime

Use Python 3.9 or later. The CI baseline is Python 3.11.

## Validate an Intent

```powershell
python tools\validate_intent.py examples\fabric-intent.lab.yaml
```

Machine-readable output:

```powershell
python tools\validate_intent.py examples\fabric-intent.lab.yaml --json
```

The lab example is valid with two expected warnings because it has one border
and one control-plane node. The same topology is rejected when its environment
is changed to `production`.

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

## Run the Development API

Set a development token through the environment. Never commit the token.

```powershell
$env:ORCHESTRATOR_API_TOKEN = '<development-token>'
python -m orchestrator.api
```

The service listens on `127.0.0.1:8080` by default.

Health:

```powershell
Invoke-RestMethod http://127.0.0.1:8080/health
```

Validation:

```powershell
$headers = @{ Authorization = 'Bearer <development-token>' }
$intent = Get-Content -Raw examples\fabric-intent.lab.yaml
# Convert YAML to JSON in the caller before using the JSON API.
```

API endpoints:

- `GET /health`
- `POST /v1/intents/validate`
- `POST /v1/plans`
- `POST /v1/intents`
- `GET /v1/intents/<intent_id>`
- `POST /v1/intents/<intent_id>/plans`
- `GET /v1/plans/<plan_id>`
- `POST /v1/plans/<plan_id>/render`
- `POST /v1/plans/<plan_id>/approvals`
- `POST /v1/runs`
- `GET /v1/runs/<run_id>`
- `POST /v1/runs/<run_id>/process-dry-run`
- `GET /v1/runs/<run_id>/evidence`
- `GET /v1/audit/<aggregate_type>/<aggregate_id>`
- `POST /v1/workflow-actions/plan`
- `POST /v1/workflow-actions/approve`
- `POST /v1/workflow-actions/run`
- `POST /v1/workflow-actions/process-dry-run`
- `POST /v1/workflow-actions/status`
- `POST /v1/workflow-actions/evidence`

The `workflow-actions` routes use fixed paths because Meraki HTTP Request
activities require an explicit Relative URL. Identifiers are carried in the
JSON body rather than interpolated into the URL.

All `/v1` endpoints require a bearer token. Missing server-side authentication
configuration fails closed with HTTP 503. Invalid credentials return HTTP 401.
Invalid intent returns HTTP 422.

## Safety State

Every generated plan currently contains:

```json
{
  "executable": false,
  "requires_approval": true,
  "requires_maintenance_window": true,
  "requires_fabric_lock": true,
  "requires_verified_rollback": true
}
```

Do not add device execution directly to these HTTP request handlers. Execution
will be implemented through durable jobs and bounded workers after the state,
approval, locking, credential, and rollback contracts are complete.

## Authentication roles

For role separation, configure `ORCHESTRATOR_TOKEN_IDENTITIES` as a secret JSON
mapping in the runtime environment. Do not commit token values. A legacy single
`ORCHESTRATOR_API_TOKEN` receives only viewer and planner permissions.

## Next Engineering Milestone

1. Freeze the discovered lab roles, links, IOS XE baselines, and BGP handoffs.
2. Add PostgreSQL and a durable worker queue for the production runtime.
3. Connect an enterprise secret resolver to the bounded device adapter.
4. Build and import the target-backed Meraki workflow from a known-good HTTP
   Request activity export.
5. Run hardware precheck, checkpoint, failure-injection, and rollback acceptance
   tests before enabling any apply path.
