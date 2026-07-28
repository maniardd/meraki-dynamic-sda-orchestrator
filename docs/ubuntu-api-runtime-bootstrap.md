# Ubuntu API runtime bootstrap

This bootstrap installs the reviewed SDA orchestrator as a separate,
loopback-only service on the Ubuntu relay host. It does not replace or modify
the legacy Flask relay on port 5000, does not contact switches, and does not
enable apply.

## Release staging

The manually dispatched `Deploy SDA Orchestrator API Release` workflow runs on
the existing `sda-relay` self-hosted runner. It:

1. checks out an exact Git commit;
2. creates an immutable release under
   `~/sda-orchestrator/releases/<full-commit-sha>`;
3. creates an isolated virtual environment and installs pinned dependencies;
4. compiles the runtime and runs the complete test suite;
5. atomically updates `~/sda-orchestrator/current`; and
6. restarts the API only when the separately installed system service exists,
   waits for health using a bounded 30-attempt retry, and restores the prior
   release if restart or health validation fails.

The workflow does not receive secrets, inspect network configuration, contact
devices, or upload host diagnostics.

## One-time service installation

After a reviewed release is staged, the operator runs:

```bash
sudo /home/sdaadmin/sda-orchestrator/current/admin/install_api_service.sh sdaadmin
```

The installer:

- requires a non-root runtime identity;
- validates PostgreSQL peer access before installing the service;
- creates private mode-`0600` runtime configuration;
- generates one Planner bearer token while storing only its SHA-256 identity
  in the service authentication file;
- temporarily stores the one-time bearer value in
  `~/.config/sda-orchestrator/bootstrap-planner-token`;
- binds Gunicorn only to `127.0.0.1:8080`;
- enforces `ORCHESTRATOR_EXECUTION_ENABLED=false`;
- installs a hardened systemd service running as the runtime user; and
- grants only the narrowly scoped service-restart permission needed by later
  immutable-release deployments.

The bearer value must be moved directly into the Meraki Planner Account Key.
It must never be pasted into chat, committed, or placed in a workflow
property. After the Account Key is verified, delete the temporary token file:

```bash
rm -f /home/sdaadmin/.config/sda-orchestrator/bootstrap-planner-token
```

## Acceptance

Local public health must return HTTP 200 and report execution disabled:

```bash
curl -sS http://127.0.0.1:8080/health
```

Only after local health passes may the POC ngrok ingress be repointed from
port 5000 to port 8080. Production still requires a stable approved ingress,
permanent DNS, and trusted TLS rather than the temporary ngrok endpoint.

## Production ingress handoff (prepared; not yet activated)

The durable handoff is deliberately separate from the loopback API service.
The platform team renders
[`deploy/nginx/sda-orchestrator.conf.template`](../deploy/nginx/sda-orchestrator.conf.template)
with its approved FQDN and certificate paths, validates it, then installs it
behind the organization-managed reverse proxy or load balancer:

```bash
python3 tools/validate_ingress_handoff.py \
  --config /etc/nginx/conf.d/sda-orchestrator.conf \
  --hostname sda-poc.<approved-domain>
```

The preflight rejects unresolved placeholders, IP-address/temporary hostnames,
ngrok, non-loopback upstreams, incomplete TLS controls, a broadened API path,
and any Apply endpoint. It makes no network call and cannot enable execution.

Before the platform owner changes Meraki targets, they must confirm all of the
following:

1. the public FQDN resolves externally and presents the trusted certificate;
2. HTTPS 443 reaches only the proxy, while the API remains `127.0.0.1:8080`;
3. the proxy permits only `/health`, `/ready`, and the six non-Apply workflow
   actions; and
4. health monitoring, certificate renewal, and incident ownership are active.

At that point, replace the temporary endpoint in each role-specific Meraki
HTTP target and capture a new **zero-write** Plan → Approval → Dry Run →
Evidence acceptance run. This is necessary evidence for `ingress.stable_tls`;
the gate is intentionally still pending until the actual controlled endpoint
is verified.

## Role-identity readiness inspection

`Inspect Meraki API Role Identity Readiness` is a manually dispatched,
read-only GitHub Actions workflow for the self-hosted relay. It reports only
the number of configured identities, the expected Meraki actor labels, missing
roles, and whether the identity file is mode `0600`. It never prints bearer
values, token digests, URL bindings, host addresses, or raw configuration; it
does not restart the service, modify the identity file, upload an artifact, or
enable execution.

## One-time Meraki Account Key bootstrap

When the four Meraki workflow targets need fresh credentials, dispatch
`Generate One-Time Meraki Account Keys` only from `main` and enter the exact
confirmation `GENERATE_FRESH_MERAKI_ACCOUNT_KEYS`. It generates unique Planner,
Approver, Operator, and Auditor values on the Ubuntu relay, writes only their
SHA-256 digests to the API identity store, and restarts the loopback-only API
with execution still disabled.

The plaintext values are never printed to Actions logs or committed. They are
written once to the private mode-`0600` local state file
`/home/sdaadmin/.local/share/sda-orchestrator/meraki-account-keys.once.json` for the
operator to enter into the matching Meraki Account Keys. Do not copy that file
to chat, screenshots, email, Git, or an export. Immediately after all four
Meraki targets have been tested, delete the one-time file from the Ubuntu
console:

```bash
rm -f /home/sdaadmin/.local/share/sda-orchestrator/meraki-account-keys.once.json
```

The workflow refuses to overwrite an existing one-time file. A second rotation
therefore requires the prior file to have been deliberately consumed and
deleted by the authorized operator. It validates the handoff file before and
after the API restart; if that validation fails, it restores the prior
hash-only identity store and fails rather than leaving unrecoverable values.
