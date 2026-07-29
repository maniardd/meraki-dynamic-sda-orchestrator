# SDA requirements intake contract

The Meraki parent workflow is the operational entry point for a fabric design.
Its canonical design input is a single, versioned `requirements_json` document
that is checked against `schemas/fabric-requirements.schema.json` by the
Planner. This is intentional: a customer can describe any number of sites,
devices, links, virtual networks, endpoint pools, and selected capabilities
without creating a separate static configuration template per topology.

## What the operator supplies

The `Plan Fabric` prompt collects the following change-controlled inputs:

| Input | Purpose |
| --- | --- |
| `requirements_json` | Customer demand and topology facts, using the versioned requirements schema. |
| `requested_mode` | `plan_only`, `dry_run`, or `apply`; the deployed package still rejects Apply. |
| `change_reference` | External ticket or change record bound to approval and evidence. |
| `approval_expires_at` | Approval expiry for dry-run or a later approved execution window. |
| `maintenance_start` / `maintenance_end` | Required only by the separately controlled Apply path. |

The requirements document describes eight design dimensions:

1. Site hierarchy.
2. Device roles and physical links.
3. Endpoint demand and address pools.
4. Virtual networks and VRFs.
5. Optional border-handoff selection.
6. Optional multicast selection.
7. Optional ISE/SXP/SGT policy-plane selection.
8. Telemetry selection.

## What the operator must not supply

`requirements_json` is demand, not configuration. It must never include
generated CLI, allocated underlay or overlay prefixes, VLANs, VNIs, SGTs, or
credentials such as device, LISP, SXP, or ISE secrets. The planner reserves
those generated values in the PostgreSQL IPAM ledger only after validation.

This division matters: two identical requirements documents produce the same
plan identity, while conflicting allocation attempts are resolved against the
ledger. The Meraki UI cannot silently override the source of truth with a
hand-entered subnet or a pasted configuration block.

## How it becomes a plan

```text
Meraki Plan Fabric prompt
        |
        v
requirements_json + change controls
        |
        v
Planner validates schema and topology
        |
        v
PostgreSQL ledger reserves derived addresses and identifiers
        |
        v
Immutable intent + plan + rendered artifact hashes
        |
        v
Meraki review, approval, zero-write dry run, evidence
```

The workflow compiler pins this intake contract and the complete operator-input
set into its deterministic build-plan hash. A future edit that adds a raw-CLI
field, marks requirements secret, changes the allocation authority, or removes
the generated-value prohibition fails build validation before a tenant workflow
can be assembled.

## Native-Meraki UI boundary

Meraki native Create Prompt supports text, checkbox, and dropdown elements. It
does not provide a reliable arbitrary repeating-table editor for a multi-site
network hierarchy. The current UI therefore accepts one schema-governed JSON
document rather than pretending to be a custom SDA design portal.

The current SJC23 POC additionally uses a guided native-prompt adapter. It
collects a fabric display name, change reference, Corporate and Guest capacity,
the two already-approved attachment choices, a DHCP lease, and the approved
DNS profile. The adapter constructs the same canonical document on the relay
from a reviewed POC profile. It rejects raw interfaces, addresses, VLANs,
credentials, CLI, and extra fields, and refuses to run unless the reviewed
SJC23 POC guardrail policy is active.

For a multi-site production deployment, a guided portal may help operators
compose the canonical document. It must use this contract and submit only
`requirements_json` to the existing Planner API; it must not allocate values,
render IOS XE configuration, or bypass the hash-bound plan/approval workflow.
