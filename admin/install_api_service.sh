#!/usr/bin/env bash
# Install the loopback-only production API service without enabling apply.

set -euo pipefail

fail() {
  printf 'install_error=%s\n' "$1" >&2
  exit 1
}

[ "${EUID}" -eq 0 ] || fail "root_required"

runtime_user="${1:-${SUDO_USER:-}}"
printf '%s' "${runtime_user}" | grep -Eq '^[a-z_][a-z0-9_-]*[$]?$' ||
  fail "invalid_runtime_user"
[ "${runtime_user}" != "root" ] || fail "dedicated_runtime_user_required"
id "${runtime_user}" >/dev/null 2>&1 || fail "runtime_user_not_found"

runtime_group="$(id -gn "${runtime_user}")"
home_dir="$(getent passwd "${runtime_user}" | awk -F: 'NR == 1 {print $6}')"
[ -n "${home_dir}" ] || fail "runtime_home_not_found"
printf '%s' "${runtime_group}" | grep -Eq '^[a-z_][a-z0-9_-]*[$]?$' ||
  fail "invalid_runtime_group"
printf '%s' "${home_dir}" | grep -Eq '^/[A-Za-z0-9._/-]+$' ||
  fail "unsafe_runtime_home"
case "/${home_dir#/}/" in
  *"/../"*) fail "unsafe_runtime_home" ;;
esac

runtime_root="${home_dir}/sda-orchestrator"
current_path="${runtime_root}/current"
config_dir="${home_dir}/.config/sda-orchestrator"
state_dir="${home_dir}/.local/share/sda-orchestrator"
api_environment="${config_dir}/api.env"
identity_file="${config_dir}/token-identities.json"
bootstrap_token_file="${config_dir}/bootstrap-planner-token"
service_name="sda-orchestrator-api.service"
service_path="/etc/systemd/system/${service_name}"

[ -d "${current_path}/orchestrator" ] || fail "current_release_missing"
[ -x "${current_path}/.venv/bin/gunicorn" ] || fail "release_venv_missing"
[ -x "${current_path}/.venv/bin/python" ] || fail "release_python_missing"
[ -f "${current_path}/policy/guardrails.yaml" ] || fail "guardrails_missing"

install -d -o "${runtime_user}" -g "${runtime_group}" -m 0700 \
  "${config_dir}" "${state_dir}"

if [ ! -f "${api_environment}" ]; then
  temporary_environment="$(mktemp)"
  cat >"${temporary_environment}" <<EOF
ORCHESTRATOR_BIND=127.0.0.1:8080
ORCHESTRATOR_DATABASE_URL=postgresql:///sda_orchestrator?host=/var/run/postgresql
ORCHESTRATOR_TOKEN_IDENTITIES_FILE=${identity_file}
ORCHESTRATOR_EXECUTION_ENABLED=false
ORCHESTRATOR_GUARDRAILS_PATH=${current_path}/policy/guardrails.yaml
ORCHESTRATOR_WEB_WORKERS=2
ORCHESTRATOR_WEB_THREADS=4
ORCHESTRATOR_REQUEST_TIMEOUT=60
ORCHESTRATOR_LOG_LEVEL=info
EOF
  install -o "${runtime_user}" -g "${runtime_group}" -m 0600 \
    "${temporary_environment}" "${api_environment}"
  rm -f -- "${temporary_environment}"
fi

require_single_setting() {
  local key="$1"
  local expected="$2"
  [ "$(grep -Ec "^${key}=" "${api_environment}")" -eq 1 ] ||
    fail "duplicate_or_missing_${key}"
  grep -Fxq "${key}=${expected}" "${api_environment}" ||
    fail "invalid_${key}"
}

require_single_setting "ORCHESTRATOR_EXECUTION_ENABLED" "false"
require_single_setting "ORCHESTRATOR_BIND" "127.0.0.1:8080"
require_single_setting \
  "ORCHESTRATOR_DATABASE_URL" \
  "postgresql:///sda_orchestrator?host=/var/run/postgresql"
require_single_setting "ORCHESTRATOR_TOKEN_IDENTITIES_FILE" "${identity_file}"
require_single_setting \
  "ORCHESTRATOR_GUARDRAILS_PATH" \
  "${current_path}/policy/guardrails.yaml"

if [ ! -f "${identity_file}" ]; then
  planner_token="$(
    runuser -u "${runtime_user}" -- \
      "${current_path}/.venv/bin/python" \
      "${current_path}/tools/create_api_identity.py" \
      --output "${identity_file}" \
      --actor meraki-planner \
      --roles viewer,planner
  )"
  [ "${#planner_token}" -ge 32 ] || fail "planner_token_generation_failed"
  temporary_token="$(mktemp)"
  printf '%s\n' "${planner_token}" >"${temporary_token}"
  install -o "${runtime_user}" -g "${runtime_group}" -m 0600 \
    "${temporary_token}" "${bootstrap_token_file}"
  rm -f -- "${temporary_token}"
  unset planner_token
fi

runuser -u "${runtime_user}" -- \
  env "PYTHONPATH=${current_path}" \
  "${current_path}/.venv/bin/python" -c \
  "from orchestrator.auth import load_hashed_token_identities; load_hashed_token_identities('${identity_file}')" ||
  fail "token_identity_validation_failed"

runuser -u "${runtime_user}" -- \
  psql -d sda_orchestrator -Atqc 'SELECT 1' >/dev/null ||
  fail "postgresql_peer_readiness_failed"

temporary_service="$(mktemp)"
cat >"${temporary_service}" <<EOF
[Unit]
Description=Meraki Dynamic SDA Orchestrator API
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=notify
User=${runtime_user}
Group=${runtime_group}
WorkingDirectory=${current_path}
EnvironmentFile=${api_environment}
ExecStart=${current_path}/.venv/bin/gunicorn --config deploy/gunicorn.conf.py orchestrator.api:app
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
TimeoutStartSec=60
TimeoutStopSec=30
KillSignal=SIGTERM
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
ReadWritePaths=${state_dir}

[Install]
WantedBy=multi-user.target
EOF
install -o root -g root -m 0644 "${temporary_service}" "${service_path}"
rm -f -- "${temporary_service}"

systemctl_path="$(command -v systemctl)"
sudoers_path="/etc/sudoers.d/sda-orchestrator-api-${runtime_user}"
temporary_sudoers="$(mktemp)"
printf '%s ALL=(root) NOPASSWD: %s restart %s\n' \
  "${runtime_user}" "${systemctl_path}" "${service_name}" >"${temporary_sudoers}"
visudo -cf "${temporary_sudoers}" >/dev/null
install -o root -g root -m 0440 "${temporary_sudoers}" "${sudoers_path}"
rm -f -- "${temporary_sudoers}"

systemctl daemon-reload
systemctl enable --now "${service_name}"

health_status=""
for _ in $(seq 1 30); do
  health_status="$(
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 3 http://127.0.0.1:8080/health 2>/dev/null || true
  )"
  [ "${health_status}" = "200" ] && break
  sleep 1
done

if [ "${health_status}" != "200" ]; then
  systemctl --no-pager --full status "${service_name}" || true
  fail "service_health_not_200"
fi

health_document="$(curl --silent --max-time 5 http://127.0.0.1:8080/health)"
printf '%s' "${health_document}" |
  grep -Eq '"execution_enabled"[[:space:]]*:[[:space:]]*false' ||
  fail "execution_state_not_disabled"

printf 'service_status=healthy\n'
printf 'service_bind=127.0.0.1:8080\n'
printf 'execution_enabled=false\n'
printf 'planner_token_file=%s\n' "${bootstrap_token_file}"
printf 'next_action=store_token_in_meraki_account_key_then_delete_bootstrap_token_file\n'
