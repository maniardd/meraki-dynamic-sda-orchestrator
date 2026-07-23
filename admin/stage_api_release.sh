#!/usr/bin/env bash
# Stage an immutable SDA orchestrator release as the unprivileged runtime user.

set -euo pipefail

fail() {
  printf 'stage_error=%s\n' "$1" >&2
  exit 1
}

if [ "${EUID}" -eq 0 ]; then
  fail "run_as_runtime_user_not_root"
fi

checkout="${1:-${GITHUB_WORKSPACE:-$PWD}}"
[ -d "${checkout}/orchestrator" ] || fail "checkout_missing_orchestrator"
[ -f "${checkout}/requirements.txt" ] || fail "checkout_missing_requirements"

release_id="${GITHUB_SHA:-}"
if [ -z "${release_id}" ] && command -v git >/dev/null 2>&1; then
  release_id="$(git -C "${checkout}" rev-parse HEAD 2>/dev/null || true)"
fi
printf '%s' "${release_id}" | grep -Eq '^[0-9a-f]{40}$' ||
  fail "release_id_must_be_full_commit_sha"

runtime_root="${SDA_ORCHESTRATOR_HOME:-${HOME}/sda-orchestrator}"
releases_root="${runtime_root}/releases"
release_path="${releases_root}/${release_id}"
current_link="${runtime_root}/current"
[ ! -e "${current_link}" ] || [ -L "${current_link}" ] ||
  fail "current_path_must_be_symlink"

umask 077
mkdir -p "${releases_root}"

temporary_release=""
cleanup() {
  if [ -n "${temporary_release}" ] && [ -d "${temporary_release}" ]; then
    case "${temporary_release}" in
      "${releases_root}"/.*) rm -rf -- "${temporary_release}" ;;
      *) printf 'cleanup_refused=%s\n' "${temporary_release}" >&2 ;;
    esac
  fi
}
trap cleanup EXIT

if [ ! -d "${release_path}" ]; then
  temporary_release="$(mktemp -d "${releases_root}/.${release_id}.XXXXXX")"
  rsync -a \
    --exclude='.git' \
    --exclude='.venv' \
    --exclude='*.log' \
    --exclude='*.sqlite3*' \
    "${checkout}/" "${temporary_release}/"

  python3 -m venv "${temporary_release}/.venv"
  "${temporary_release}/.venv/bin/python" -m pip install \
    --disable-pip-version-check \
    --requirement "${temporary_release}/requirements.txt"
  "${temporary_release}/.venv/bin/python" -m compileall -q \
    "${temporary_release}/orchestrator" \
    "${temporary_release}/tools"
  (
    cd "${temporary_release}"
    "${temporary_release}/.venv/bin/python" -m unittest discover -s tests -q
  )
  printf '%s\n' "${release_id}" >"${temporary_release}/.release-commit"
  mv -- "${temporary_release}" "${release_path}"
  temporary_release=""
else
  [ -f "${release_path}/.release-commit" ] ||
    fail "existing_release_missing_provenance"
  [ "$(tr -d '\r\n' <"${release_path}/.release-commit")" = "${release_id}" ] ||
    fail "existing_release_provenance_mismatch"
fi

previous_release=""
if [ -L "${current_link}" ]; then
  previous_release="$(readlink -f "${current_link}" || true)"
fi

temporary_link="${runtime_root}/.current.${release_id}.$$"
ln -s "${release_path}" "${temporary_link}"
mv -Tf -- "${temporary_link}" "${current_link}"

service_name="sda-orchestrator-api.service"
systemctl_path="$(command -v systemctl || true)"
if [ -n "${systemctl_path}" ] &&
  "${systemctl_path}" list-unit-files "${service_name}" --no-legend 2>/dev/null |
    grep -q "^${service_name}"; then
  if ! sudo -n "${systemctl_path}" restart "${service_name}"; then
    if [ -n "${previous_release}" ] && [ -d "${previous_release}" ]; then
      rollback_link="${runtime_root}/.current.rollback.$$"
      ln -s "${previous_release}" "${rollback_link}"
      mv -Tf -- "${rollback_link}" "${current_link}"
      sudo -n "${systemctl_path}" restart "${service_name}" || true
    fi
    fail "service_restart_not_authorized_or_failed"
  fi
  health_status="$(
    curl --silent --output /dev/null --write-out '%{http_code}' \
      --max-time 10 http://127.0.0.1:8080/health 2>/dev/null || true
  )"
  if [ "${health_status}" != "200" ]; then
    if [ -n "${previous_release}" ] && [ -d "${previous_release}" ]; then
      rollback_link="${runtime_root}/.current.rollback.$$"
      ln -s "${previous_release}" "${rollback_link}"
      mv -Tf -- "${rollback_link}" "${current_link}"
      sudo -n "${systemctl_path}" restart "${service_name}" || true
    fi
    fail "service_health_not_200"
  fi
  printf 'service_status=healthy\n'
else
  printf 'service_status=installation_required\n'
fi

printf 'release_commit=%s\n' "${release_id}"
printf 'release_path=%s\n' "${release_path}"
printf 'current_release_updated=true\n'
