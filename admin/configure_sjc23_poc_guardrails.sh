#!/usr/bin/env bash
# Bind the reviewed SJC23 POC allocation policy to this lab runtime only.
# It never enables execution and restores the preceding environment binding if
# the API does not return a healthy response after restart.

set -euo pipefail

fail() {
  printf 'poc_guardrails_error=%s\n' "$1" >&2
  exit 1
}

[ "${EUID}" -ne 0 ] || fail "run_as_runtime_user_not_root"

checkout="${1:-${GITHUB_WORKSPACE:-$PWD}}"
source_policy="${checkout}/policy/guardrails.sjc23-poc.yaml"
[ -f "${source_policy}" ] && [ ! -L "${source_policy}" ] || fail "poc_policy_missing"

config_dir="${SDA_ORCHESTRATOR_CONFIG_DIR:-${HOME}/.config/sda-orchestrator}"
env_file="${config_dir}/api.env"
target_policy="${config_dir}/guardrails.sjc23-poc.yaml"

[ -d "${config_dir}" ] && [ ! -L "${config_dir}" ] || fail "config_directory_invalid"
[ -f "${env_file}" ] && [ ! -L "${env_file}" ] || fail "api_environment_missing"
[ "$(stat -c '%a' "${env_file}")" = "600" ] || fail "api_environment_mode_must_be_600"
[ "$(stat -c '%U' "${env_file}")" = "${USER}" ] || fail "api_environment_owner_invalid"
[ ! -e "${target_policy}" ] && [ ! -L "${target_policy}" ] || fail "poc_policy_already_exists"

umask 077
install -m 0600 "${source_policy}" "${target_policy}"

backup="${config_dir}/api.env.before-sjc23-poc"
[ ! -e "${backup}" ] && [ ! -L "${backup}" ] || fail "rollback_backup_already_exists"
install -m 0600 "${env_file}" "${backup}"

rewrite_environment() {
  python3 - "${env_file}" "${target_policy}" <<'PY'
from pathlib import Path
import os
import sys
import tempfile

path = Path(sys.argv[1])
policy = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines()
matches = [index for index, line in enumerate(lines) if line.startswith("ORCHESTRATOR_GUARDRAILS_PATH=")]
if len(matches) != 1:
    raise SystemExit("guardrails_path_must_appear_once")
lines[matches[0]] = "ORCHESTRATOR_GUARDRAILS_PATH=" + policy
fd, temporary = tempfile.mkstemp(prefix=".api.env.", dir=str(path.parent))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
}

restore_environment() {
  install -m 0600 "${backup}" "${env_file}"
  sudo -n systemctl restart sda-orchestrator-api.service || true
}

trap restore_environment ERR
rewrite_environment
sudo -n systemctl restart sda-orchestrator-api.service

for _ in $(seq 1 30); do
  status="$(curl --silent --output /dev/null --write-out '%{http_code}' --max-time 3 http://127.0.0.1:8080/health 2>/dev/null || true)"
  [ "${status}" = "200" ] && break
  sleep 1
done
if [ "${status:-}" != "200" ]; then
  restore_environment
  fail "api_health_not_200"
fi

trap - ERR
printf 'poc_guardrails_configured=true\n'
printf 'execution_enabled_unchanged=true\n'
