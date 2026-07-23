#!/usr/bin/env bash
# Create a private, verified PostgreSQL backup for the SDA orchestrator.

set -euo pipefail

fail() {
  printf 'backup_error=%s\n' "$1" >&2
  exit 1
}

[ "${EUID}" -ne 0 ] || fail "run_as_runtime_user_not_root"

database_url="${ORCHESTRATOR_DATABASE_URL:-postgresql:///sda_orchestrator?host=/var/run/postgresql}"
[ "${database_url}" = "postgresql:///sda_orchestrator?host=/var/run/postgresql" ] ||
  fail "unsupported_database_url"
unset \
  PGAPPNAME PGDATABASE PGHOST PGOPTIONS PGPASSFILE PGPASSWORD PGPORT \
  PGSERVICE PGSERVICEFILE PGSSLMODE PGUSER

retention_count="${SDA_BACKUP_RETENTION_COUNT:-14}"
printf '%s' "${retention_count}" | grep -Eq '^[1-9][0-9]{0,2}$' ||
  fail "invalid_retention_count"
[ "${retention_count}" -le 365 ] || fail "invalid_retention_count"

runtime_user="$(id -un)"
runtime_home="$(getent passwd "${runtime_user}" | awk -F: 'NR == 1 {print $6}')"
[ -n "${runtime_home}" ] && [ "${runtime_home#/}" != "${runtime_home}" ] ||
  fail "runtime_home_unavailable"
[ "${HOME}" = "${runtime_home}" ] || fail "runtime_home_mismatch"

backup_root="${runtime_home}/.local/share/sda-orchestrator/backups"
case "${backup_root}" in
  /*/.local/share/sda-orchestrator/backups) ;;
  *) fail "unsafe_backup_root" ;;
esac

for command_name in getent pg_dump pg_restore psql realpath sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "missing_${command_name}"
done

umask 077
install -d -m 0700 "${backup_root}"
[ "$(realpath -- "${backup_root}")" = "${backup_root}" ] ||
  fail "backup_root_symlinked"
[ "$(stat -c '%a' "${backup_root}")" = "700" ] ||
  fail "backup_root_permissions"

psql "${database_url}" -v ON_ERROR_STOP=1 -Atqc \
  "SELECT current_database()" |
  grep -Fxq "sda_orchestrator" ||
  fail "database_readiness_failed"

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
archive_name="sda_orchestrator_${timestamp}.dump"
archive_path="${backup_root}/${archive_name}"
[ ! -e "${archive_path}" ] || fail "backup_already_exists"

temporary_archive="$(mktemp "${backup_root}/.${archive_name}.XXXXXX")"
cleanup() {
  if [ -n "${temporary_archive:-}" ] && [ -f "${temporary_archive}" ]; then
    case "${temporary_archive}" in
      "${backup_root}"/.*) rm -f -- "${temporary_archive}" ;;
      *) printf 'cleanup_refused=true\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT

pg_dump \
  --dbname="${database_url}" \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-privileges \
  --file="${temporary_archive}"

pg_restore --list "${temporary_archive}" >/dev/null ||
  fail "archive_catalog_invalid"

for table_name in \
  intents design_reservations plans approvals runs fabric_locks evidence \
  audit_events network_allocations scalar_allocations owned_state_manifests
do
  pg_restore --list "${temporary_archive}" |
    grep -Eq "[[:space:]]TABLE[[:space:]]public[[:space:]]${table_name}[[:space:]]" ||
    fail "archive_missing_required_table"
done

chmod 0600 "${temporary_archive}"
mv -- "${temporary_archive}" "${archive_path}"
temporary_archive=""

(
  cd "${backup_root}"
  sha256sum -- "${archive_name}" >"${archive_name}.sha256"
)
chmod 0600 "${archive_path}.sha256"

archive_sha256="$(
  awk 'NR == 1 {print $1}' "${archive_path}.sha256"
)"
printf '%s' "${archive_sha256}" | grep -Eq '^[0-9a-f]{64}$' ||
  fail "archive_checksum_invalid"

metadata_path="${archive_path}.json"
printf '%s\n' \
  '{' \
  '  "schema_version": "1.0",' \
  "  \"created_at\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"," \
  '  "database": "sda_orchestrator",' \
  '  "format": "postgresql_custom",' \
  "  \"archive_sha256\": \"${archive_sha256}\"," \
  "  \"retention_count\": ${retention_count}" \
  '}' >"${metadata_path}"
chmod 0600 "${metadata_path}"

mapfile -t expired_archives < <(
  find "${backup_root}" -maxdepth 1 -type f \
    -name 'sda_orchestrator_????????T??????Z.dump' \
    -printf '%T@ %f\n' |
    sort -rn |
    awk -v keep="${retention_count}" 'NR > keep {print $2}'
)
for expired_name in "${expired_archives[@]}"; do
  printf '%s' "${expired_name}" |
    grep -Eq '^sda_orchestrator_[0-9]{8}T[0-9]{6}Z[.]dump$' ||
    fail "unsafe_retention_candidate"
  rm -f -- \
    "${backup_root}/${expired_name}" \
    "${backup_root}/${expired_name}.sha256" \
    "${backup_root}/${expired_name}.json"
done

printf '%s\n' "${archive_path}"
