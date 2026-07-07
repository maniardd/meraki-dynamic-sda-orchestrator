# Meraki Dynamic SDA Orchestrator

An experimental, intent-driven automation foundation for planning, reviewing,
and deploying Cisco IOS XE LISP/VXLAN campus fabrics through Cisco Meraki
Workflows.

> This project is not Cisco Catalyst Center and is not an official replacement
> for Cisco SD-Access. It automates supported IOS XE LISP/VXLAN constructs and
> uses SDA design principles. Validate platform, release, scale, and support
> requirements with current Cisco documentation before production use.

## Target experience

Meraki Workflows is the operator-facing entry point. It collects business and
site requirements, requests a deterministic plan from the orchestrator,
displays the review summary, captures approval, starts a dry run or controlled
apply, and returns evidence.

The orchestrator owns stateful functions that should not live in a low-code
workflow: allocation, validation, rendering, locks, idempotency, device
transactions, verification, rollback, and audit history.

```text
Meraki Workflows
        |
        v
Intent API -> Planner/IPAM -> Renderer -> Approval -> Worker
                                             |          |
                                             v          v
                                           Audit     IOS XE
```

## Current state

Implemented foundation:

- Versioned fabric-intent schema and semantic validation
- Strict high-level requirements schema and versioned organizational guardrails
- Deterministic allocation of underlay /31s, loopbacks, overlay prefixes,
  VLAN/L2/L3 IDs, RD/RT values, and BGP handoffs
- Persistent allocation lifecycle with reserved, committed, released, and
  quarantined states
- Brownfield exclusion, pool-exhaustion, retry, and concurrent-allocation tests
- PostgreSQL production migration with CIDR GiST overlap exclusion
- PostgreSQL runtime store with domain/fabric/audit advisory locks
- Separate execution and Dashboard inventory address planes
- Immutable deterministic plans and rendered IOS XE command artifacts
- Plan-, artifact-, and intent-version-bound approvals with role separation
- Idempotent dry-run records, evidence, locks, and hash-chained audit events
- Bounded Netmiko adapter contract with checkpoints and rollback
- Exact operational parsers and topology-derived verification gates
- Fixed-path APIs designed for Meraki HTTP Request activities
- Authenticated readiness checks and hardened Gunicorn/systemd deployment assets
- Vault KV and strict host-file secret-provider boundaries used only by the
  separately enabled apply worker
- Sanitized lab and redundant production examples
- Sanitized COP29-derived large-campus acceptance fixture with dual-border,
  multi-VN, `/30` BGP handoff, deterministic scale, and data-quality tests
- Schema 1.2 production contracts for explicit fusion pairs, LISP Pub/Sub,
  shared-service route policy, native/replicated multicast, ISE, SGT, and SXP
- Fusion-side VRF-lite/eBGP review artifacts and two-sided operational gates;
  unaccepted service and policy renderers remain explicit apply blockers
- Deny-by-default shared-service route-leak rendering, exact route gates, and
  fusion-node failure/rollback coverage; hardware acceptance remains blocked
- LISP Pub/Sub border-subscriber rendering with per-IID publisher-state gates
  and failure/rollback coverage; redundant hardware acceptance remains blocked

Live apply remains disabled. SQLite remains available for local tests, while
the production runtime uses PostgreSQL. Meraki import packaging and hardware
failure/rollback acceptance remain release-candidate work.

## Quick start

Use Python 3.10 or later.

```powershell
python -m pip install -r requirements.txt
python -c "import yaml; from pathlib import Path; from orchestrator.allocator import derive_fabric_intent; print(derive_fabric_intent(yaml.safe_load(Path('examples/fabric-requirements.lab.yaml').read_text()), yaml.safe_load(Path('policy/guardrails.yaml').read_text()))['intent_hash'])"
python tools\validate_intent.py examples\fabric-intent.lab.yaml
python -m unittest discover -s tests -v
```

Start the development API with a private hashed-token identity file. The helper
returns the new bearer value once; only its SHA-256 digest is stored:

```powershell
$authFile = Join-Path $env:TEMP 'sda-token-identities.json'
$token = python tools\create_api_identity.py --output $authFile --actor local-planner --roles viewer,planner
$env:ORCHESTRATOR_TOKEN_IDENTITIES_FILE = $authFile
python -m orchestrator.api
```

The API listens on `127.0.0.1:8080` by default. `/ready` and every `/v1/`
endpoint require `Authorization: Bearer <token>`. Device execution is disabled
unless explicitly enabled in a separately reviewed worker runtime.

## Repository safety

- Never commit API keys, passwords, exported account keys, private keys, local
  intent files, inventory exports, evidence, databases, or device output.
- Public examples use documentation-only address ranges.
- Environment-specific hosts and credentials are supplied through secret
  references or repository/runtime secrets.
- The relay preflight workflow is manual, read-only, and does not check out or
  deploy repository code.

See [SECURITY.md](SECURITY.md) before connecting the orchestrator to a network.

The [COP29-derived fixture](docs/cop29-sanitized-acceptance-fixture.md) records
its sanitization boundary and the capabilities it does—and does not—prove.
The [production services and policy model](docs/production-services-policy-model.md)
records the schema 1.2 contracts, Cisco design basis, and execution blockers.
The [LISP Pub/Sub acceptance boundary](docs/lisp-pubsub-renderer.md) records
the rendered subscriber contract, operational evidence, and remaining
redundant-hardware tests.
