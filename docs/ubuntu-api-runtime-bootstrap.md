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
