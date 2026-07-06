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

Start the development API only with a local development token:

```powershell
$env:ORCHESTRATOR_API_TOKEN = '<local-development-token>'
python -m orchestrator.api
```

The API listens on `127.0.0.1:8080` by default. Device execution is disabled
unless explicitly enabled in a reviewed worker runtime.

## Repository safety

- Never commit API keys, passwords, exported account keys, private keys, local
  intent files, inventory exports, evidence, databases, or device output.
- Public examples use documentation-only address ranges.
- Environment-specific hosts and credentials are supplied through secret
  references or repository/runtime secrets.
- The relay preflight workflow is manual, read-only, and does not check out or
  deploy repository code.

See [SECURITY.md](SECURITY.md) before connecting the orchestrator to a network.
