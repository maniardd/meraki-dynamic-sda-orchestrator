# Worker deployment checklist

The worker runs as a dedicated `sda-worker` OS user, not as `sdaadmin`. This
separation is required because the GitHub Actions self-hosted runner on the same
Ubuntu host also runs as `sdaadmin`. A `secrets.json` owned by `sdaadmin` with
mode `0600` is readable by every runner workflow — `0600` prevents access by
other users, not by other processes of the same user. A dedicated `sda-worker`
user ensures that repo push access does not become device credential access.

The deployed service follows the same pattern as the API: a system service
(`/etc/systemd/system/`) with an explicit `User=` directive. The upstream
template (`deploy/systemd/sda-orchestrator-worker@.service`) uses `%h` and is
designed as a user-service starting point; it is not the deployed artifact.

Complete these sections in order before the first execution window.

---

## 1. Create the sda-worker OS user

```bash
sudo useradd \
    --system \
    --home-dir /var/lib/sda-worker \
    --create-home \
    --shell /usr/sbin/nologin \
    sda-worker
```

`--system` marks it as a system account (UID below `SYS_UID_MAX`).
`--shell /usr/sbin/nologin` prevents interactive login.
The home directory `/var/lib/sda-worker` is outside `/home/`, so `sdaadmin`
cannot traverse it without explicit permission.

Verify:

```bash
id sda-worker
ls -ld /var/lib/sda-worker
# expected: drwx------ sda-worker sda-worker
```

---

## 2. PostgreSQL role and grants

Peer authentication maps the OS username to a database role of the same name.
Create the role and grant the minimum required privileges.

Run as a PostgreSQL superuser (e.g., via `sudo -u postgres psql`):

```sql
CREATE ROLE "sda-worker" WITH LOGIN;

GRANT CONNECT ON DATABASE sda_orchestrator TO "sda-worker";
GRANT SELECT, INSERT, UPDATE, DELETE
    ON ALL TABLES IN SCHEMA public TO "sda-worker";

-- Required for BIGSERIAL inserts (audit_events, owned_state_manifests).
-- Without this the worker fails a real run with InsufficientPrivilege when it
-- writes its first audit event.
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO "sda-worker";
```

Ensure `pg_hba.conf` has a peer-auth entry for this role:

```
# /etc/postgresql/<version>/main/pg_hba.conf
local   sda_orchestrator   sda-worker   peer
```

After adding the line, reload PostgreSQL:

```bash
sudo systemctl reload postgresql
```

Verify peer access as the new user:

```bash
sudo -u sda-worker psql \
    "postgresql:///sda_orchestrator?host=/var/run/postgresql" \
    -c "SELECT count(*) FROM runs;"
```

Expected: a row count with no password prompt. `sdaadmin` retains its own peer
access for lock-recovery operations; this does not change its grants.

---

## 3. secrets.json

`StrictJsonFileSecretProvider` (`orchestrator/secrets.py:71-92`) enforces:
- Regular file, not a symlink.
- Mode `0600`. Checked at load time; any other mode raises
  `SecretProviderError: Secret file must not be accessible by group or other`.
- Root JSON object. Keys are `secret://PATH` reference strings.

Create the file as root, transfer ownership to `sda-worker`:

```bash
sudo mkdir -p /var/lib/sda-worker/.config/sda-orchestrator
sudo install -m 0600 -o sda-worker -g sda-worker \
    /dev/null /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
```

Write the content (run as root or with sudo tee):

```bash
sudo tee /var/lib/sda-worker/.config/sda-orchestrator/secrets.json > /dev/null << 'EOF'
{
  "sda-lab/credentials/border-cp-01": {
    "username": "REPLACE",
    "password": "REPLACE",
    "enable_secret": "REPLACE"
  },
  "sda-lab/credentials/edge-01": {
    "username": "REPLACE",
    "password": "REPLACE",
    "enable_secret": "REPLACE"
  },
  "sda-lab/lisp/site-sjc23": {
    "value": "REPLACE"
  }
}
EOF
sudo chmod 0600 /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
sudo chown sda-worker:sda-worker /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
```

`enable_secret` is optional. `username` and `password` are required.
Value entries must be non-empty and must not contain a newline.

Verify ownership and permissions (must be `sda-worker`, not `sdaadmin`):

```bash
stat /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
# expected: Uid: ( .../sda-worker)  Gid: ( .../sda-worker)  Access: (0600/-)
```

Confirm that `sdaadmin` cannot read it:

```bash
cat /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
# expected: Permission denied
```

---

## 4. worker.env

```bash
sudo mkdir -p /var/lib/sda-worker/.config/sda-orchestrator
sudo install -m 0600 -o sda-worker -g sda-worker \
    deploy/worker.env.example \
    /var/lib/sda-worker/.config/sda-orchestrator/worker.env
```

Edit the file as root. Required and optional fields annotated:

```bash
# --- database connection ---
ORCHESTRATOR_DATABASE_URL=postgresql:///sda_orchestrator?host=/var/run/postgresql

# --- execution gates (both must be true to run; false → exit 2) ---
ORCHESTRATOR_EXECUTION_ENABLED=false      # flip to true only after all checks pass
ORCHESTRATOR_WORKER_ENABLED=false         # flip to true only after execution gate is set

# --- audit identity (written verbatim into audit_events.actor) ---
ORCHESTRATOR_WORKER_IDENTITY=sda-worker

# --- secret provider ---
ORCHESTRATOR_SECRET_PROVIDER=strict_json_file
ORCHESTRATOR_SECRET_FILE=/var/lib/sda-worker/.config/sda-orchestrator/secrets.json

# --- SJC23 POC execution block (omit entirely if not running SJC23 POC) ---
# All six keys must be present together or the execution gate will fail.
ORCHESTRATOR_SJC23_POC_EXECUTION_ENABLED=false
ORCHESTRATOR_GUARDRAILS_PATH=/home/sdaadmin/.config/sda-orchestrator/guardrails.sjc23-poc.yaml
ORCHESTRATOR_SJC23_POC_GUARDRAILS_SHA256=REPLACE_64_CHAR_HEX
ORCHESTRATOR_SJC23_POC_CHANGE_REFERENCE=SJC23-POC-001
ORCHESTRATOR_SJC23_POC_PLAN_HASH=REPLACE_64_CHAR_HEX
ORCHESTRATOR_SJC23_POC_ARTIFACT_HASH=REPLACE_64_CHAR_HEX
```

Verify ownership (must be `sda-worker`):

```bash
stat /var/lib/sda-worker/.config/sda-orchestrator/worker.env
# expected: Uid: ( .../sda-worker)  Access: (0600/-)
```

---

## 5. System service installation

The worker is installed as a system service with `User=sda-worker`. The upstream
template uses `%h` which expands to the user's home — `/var/lib/sda-worker` for
`sda-worker`, not `/home/sdaadmin/...` where the release lives. The deployed unit
hardcodes the release paths.

`sda-worker` needs read and execute access to the release directory, which is
owned by `sdaadmin`. The immutable release tree is world-executable by default
(755 dirs, 644/755 files); verify and correct if needed:

```bash
ls -ld /home/sdaadmin/sda-orchestrator/current
# expected: lrwxrwxrwx (symlink) pointing to a release dir
ls -ld /home/sdaadmin/sda-orchestrator/releases/<sha>
# expected: drwxr-xr-x sdaadmin sdaadmin (world-execute required)
```

Write the system service file:

```bash
sudo tee /etc/systemd/system/sda-orchestrator-worker@.service > /dev/null << 'EOF'
[Unit]
Description=Meraki Dynamic SDA Orchestrator Apply Worker %i
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=oneshot
User=sda-worker
Group=sda-worker
WorkingDirectory=/home/sdaadmin/sda-orchestrator/current
EnvironmentFile=/var/lib/sda-worker/.config/sda-orchestrator/worker.env
ExecStart=/home/sdaadmin/sda-orchestrator/current/.venv/bin/python \
    -m orchestrator.worker_runtime --run-id %i
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/sda-worker/.local/share/sda-orchestrator

[Install]
WantedBy=multi-user.target
EOF
```

Note: `ProtectHome=read-only` makes home directories read-only for this service.
`sda-worker` only needs to read the code at `/home/sdaadmin/sda-orchestrator/current`,
which read-only access satisfies. Writes go only to
`/var/lib/sda-worker/.local/share/sda-orchestrator`.

```bash
sudo mkdir -p /var/lib/sda-worker/.local/share/sda-orchestrator
sudo chown sda-worker:sda-worker /var/lib/sda-worker/.local/share/sda-orchestrator
sudo systemctl daemon-reload
```

Verify the unit is recognized:

```bash
sudo systemctl status "sda-orchestrator-worker@.service"
# expected: loaded (not found: no running instances yet)
```

### Starting a worker run

The POC has no queue consumer. Start runs manually as an operator with sudo
access. Do not add a sudoers entry for `sdaadmin` to start worker instances:
a wildcard over the instance name (`@*`) would let the GitHub Actions runner
(which runs as `sdaadmin`) start arbitrary runs as `sda-worker` and reach the
switches — the same lateral-movement risk the OS user separation was designed
to prevent.

Start a specific run (replace `${RUN_ID}` with the run_id from the API or store):

```bash
sudo systemctl start "sda-orchestrator-worker@${RUN_ID}.service"
```

This requires the operator's own account to have sudo access, which is already
present if they ran the earlier `sudo useradd`/`sudo systemctl daemon-reload`
steps. No additional sudoers entry is needed.

Watch logs for a run:

```bash
sudo journalctl -u "sda-orchestrator-worker@${RUN_ID}.service"
```

---

## 6. Fail-closed negative verification

Run all five before the maintenance window. Every test must exit non-zero and
print `"succeeded": false`. A test that exits zero means the fail-closed gate
is broken — do not proceed.

The canonical fail path is `worker_runtime.py:76-86`: both
`ORCHESTRATOR_EXECUTION_ENABLED` and `ORCHESTRATOR_WORKER_ENABLED` are checked
before any database connection. Exit code 2;
stdout is `{"succeeded": false, "error_type": "WorkerRuntimeError"}`.

For tests that call the worker directly, run under `sudo -u sda-worker`. If the
host's sudoers deliberately forbids sdaadmin from becoming sda-worker (the
correct hardening — it stops the CI runner reaching devices), `sudo -u
sda-worker` is denied; use `sudo runuser -u sda-worker -- <cmd>` instead, which
escalates to root first and cannot be done by the runner without full root:

### 6a. Execution gate disabled

```bash
sudo -u sda-worker env \
    ORCHESTRATOR_EXECUTION_ENABLED=false \
    ORCHESTRATOR_WORKER_ENABLED=true \
    ORCHESTRATOR_DATABASE_URL="postgresql:///sda_orchestrator?host=/var/run/postgresql" \
    ORCHESTRATOR_SECRET_PROVIDER=strict_json_file \
    ORCHESTRATOR_SECRET_FILE=/var/lib/sda-worker/.config/sda-orchestrator/secrets.json \
    /home/sdaadmin/sda-orchestrator/current/.venv/bin/python \
    -m orchestrator.worker_runtime --run-id run_does_not_matter
echo "exit: $?"
```

Expected: exit code 2; `"error_type": "WorkerRuntimeError"`.

### 6b. Worker gate disabled

```bash
sudo -u sda-worker env \
    ORCHESTRATOR_EXECUTION_ENABLED=true \
    ORCHESTRATOR_WORKER_ENABLED=false \
    ORCHESTRATOR_DATABASE_URL="postgresql:///sda_orchestrator?host=/var/run/postgresql" \
    ORCHESTRATOR_SECRET_PROVIDER=strict_json_file \
    ORCHESTRATOR_SECRET_FILE=/var/lib/sda-worker/.config/sda-orchestrator/secrets.json \
    /home/sdaadmin/sda-orchestrator/current/.venv/bin/python \
    -m orchestrator.worker_runtime --run-id run_does_not_matter
echo "exit: $?"
```

Expected: exit code 2; `"error_type": "WorkerRuntimeError"`.

### 6c. Secrets file with wrong permissions

```bash
sudo chmod 0644 /var/lib/sda-worker/.config/sda-orchestrator/secrets.json

sudo -u sda-worker env \
    ORCHESTRATOR_SECRET_PROVIDER=strict_json_file \
    ORCHESTRATOR_SECRET_FILE=/var/lib/sda-worker/.config/sda-orchestrator/secrets.json \
    /home/sdaadmin/sda-orchestrator/current/.venv/bin/python -c "
import os
os.environ['ORCHESTRATOR_SECRET_PROVIDER'] = 'strict_json_file'
os.environ['ORCHESTRATOR_SECRET_FILE'] = '/var/lib/sda-worker/.config/sda-orchestrator/secrets.json'
from orchestrator.secrets import build_secret_provider
build_secret_provider()
"
echo "exit: $?"

sudo chmod 0600 /var/lib/sda-worker/.config/sda-orchestrator/secrets.json   # restore immediately
```

Expected: non-zero exit; `SecretProviderError: Secret file must not be accessible
by group or other`.

### 6d. Missing secrets file

```bash
sudo -u sda-worker env \
    ORCHESTRATOR_SECRET_PROVIDER=strict_json_file \
    ORCHESTRATOR_SECRET_FILE=/nonexistent/path/secrets.json \
    /home/sdaadmin/sda-orchestrator/current/.venv/bin/python -c "
import os
os.environ['ORCHESTRATOR_SECRET_PROVIDER'] = 'strict_json_file'
os.environ['ORCHESTRATOR_SECRET_FILE'] = '/nonexistent/path/secrets.json'
from orchestrator.secrets import build_secret_provider
build_secret_provider()
"
echo "exit: $?"
```

Expected: non-zero exit; `FileNotFoundError` or `SecretProviderError`.

### 6e. Non-existent run_id

With both gates enabled and a valid secrets file:

```bash
sudo -u sda-worker env \
    ORCHESTRATOR_EXECUTION_ENABLED=true \
    ORCHESTRATOR_WORKER_ENABLED=true \
    ORCHESTRATOR_DATABASE_URL="postgresql:///sda_orchestrator?host=/var/run/postgresql" \
    ORCHESTRATOR_SECRET_PROVIDER=strict_json_file \
    ORCHESTRATOR_SECRET_FILE=/var/lib/sda-worker/.config/sda-orchestrator/secrets.json \
    /home/sdaadmin/sda-orchestrator/current/.venv/bin/python \
    -m orchestrator.worker_runtime --run-id run_does_not_exist_xxxxxxxxxxx
echo "exit: $?"
```

Expected: exit code 2; `"error_type": "NotFoundError"` or similar store exception.

### Confirmation criterion

```
[ ] 6a exit code non-zero
[ ] 6b exit code non-zero
[ ] 6c exit code non-zero, secrets.json restored to 0600 and owned sda-worker
[ ] 6d exit code non-zero
[ ] 6e exit code non-zero
[ ] sdaadmin cannot read /var/lib/sda-worker/.config/sda-orchestrator/secrets.json
```

All six must pass. If any gate exits zero, investigate `worker_runtime.py:76-86`
before proceeding.
