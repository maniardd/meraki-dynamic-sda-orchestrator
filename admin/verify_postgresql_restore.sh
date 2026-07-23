#!/usr/bin/env bash
# Verify an SDA PostgreSQL backup by restoring only into a disposable database.

set -euo pipefail

fail() {
  printf 'restore_verify_error=%s\n' "$1" >&2
  exit 1
}

[ "${EUID}" -ne 0 ] || fail "run_as_runtime_user_not_root"
[ "$#" -eq 1 ] || fail "backup_path_required"

unset \
  PGAPPNAME PGDATABASE PGHOST PGOPTIONS PGPASSFILE PGPASSWORD PGPORT \
  PGSERVICE PGSERVICEFILE PGSSLMODE PGUSER

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
[ -d "${backup_root}" ] || fail "backup_root_not_found"
[ "$(realpath -- "${backup_root}")" = "${backup_root}" ] ||
  fail "backup_root_symlinked"
[ "$(stat -c '%a' "${backup_root}")" = "700" ] ||
  fail "backup_root_permissions"

archive_path="$1"
archive_name="$(basename -- "${archive_path}")"
printf '%s' "${archive_name}" |
  grep -Eq '^sda_orchestrator_[0-9]{8}T[0-9]{6}Z[.]dump$' ||
  fail "invalid_backup_name"
[ "${archive_path}" = "${backup_root}/${archive_name}" ] ||
  fail "backup_outside_managed_root"
[ -f "${archive_path}" ] || fail "backup_not_found"
[ ! -L "${archive_path}" ] || fail "backup_symlink_forbidden"
[ -f "${archive_path}.sha256" ] || fail "checksum_not_found"
[ ! -L "${archive_path}.sha256" ] || fail "checksum_symlink_forbidden"
[ "$(stat -c '%a' "${archive_path}")" = "600" ] ||
  fail "backup_permissions"
[ "$(stat -c '%a' "${archive_path}.sha256")" = "600" ] ||
  fail "checksum_permissions"

for command_name in getent pg_config pg_restore psql realpath sha256sum; do
  command -v "${command_name}" >/dev/null 2>&1 ||
    fail "missing_${command_name}"
done

postgres_bindir="$(pg_config --bindir)"
printf '%s' "${postgres_bindir}" |
  grep -Eq '^/usr/lib/postgresql/[0-9]+/bin$' ||
  fail "unsafe_postgres_bindir"
for server_command in createdb initdb pg_ctl; do
  [ -x "${postgres_bindir}/${server_command}" ] ||
    fail "missing_${server_command}"
done

read -r expected_sha256 checksum_name extra_checksum_field <"${archive_path}.sha256" ||
  fail "checksum_invalid"
printf '%s' "${expected_sha256}" | grep -Eq '^[0-9a-f]{64}$' ||
  fail "checksum_invalid"
[ "${checksum_name}" = "${archive_name}" ] ||
  fail "checksum_name_mismatch"
[ -z "${extra_checksum_field:-}" ] || fail "checksum_invalid"
actual_sha256="$(sha256sum -- "${archive_path}" | awk 'NR == 1 {print $1}')"
[ "${actual_sha256}" = "${expected_sha256}" ] ||
  fail "checksum_mismatch"

pg_restore --list "${archive_path}" >/dev/null ||
  fail "archive_catalog_invalid"

scratch_database="sda_restore_verify"
scratch_root="$(mktemp -d "${backup_root}/.restore-verify.XXXXXX")"
scratch_data="${scratch_root}/data"
scratch_socket="${scratch_root}/socket"
scratch_log="${scratch_root}/postgresql.log"
scratch_port="$((49152 + ($$ % 16384)))"
cluster_running=false
cleanup() {
  if [ "${cluster_running}" = true ]; then
    "${postgres_bindir}/pg_ctl" \
      --pgdata="${scratch_data}" \
      --mode=immediate \
      --wait \
      stop >/dev/null 2>&1 || true
  fi
  if [ -n "${scratch_root:-}" ] && [ -d "${scratch_root}" ]; then
    case "${scratch_root}" in
      "${backup_root}"/.restore-verify.*) rm -rf -- "${scratch_root}" ;;
      *) printf 'cleanup_refused=true\n' >&2 ;;
    esac
  fi
}
trap cleanup EXIT

started_epoch="$(date +%s)"
install -d -m 0700 "${scratch_socket}"
"${postgres_bindir}/initdb" \
  --pgdata="${scratch_data}" \
  --auth-local=trust \
  --auth-host=reject \
  --encoding=UTF8 \
  --no-locale \
  >/dev/null ||
  fail "scratch_cluster_initialize_failed"

server_options="-c listen_addresses='' -c unix_socket_directories='${scratch_socket}' -p ${scratch_port}"
"${postgres_bindir}/pg_ctl" \
  --pgdata="${scratch_data}" \
  --log="${scratch_log}" \
  --options="${server_options}" \
  --timeout=30 \
  --wait \
  start >/dev/null ||
  fail "scratch_cluster_start_failed"
cluster_running=true

"${postgres_bindir}/createdb" \
  --host="${scratch_socket}" \
  --port="${scratch_port}" \
  --maintenance-db=postgres \
  --encoding=UTF8 \
  --template=template0 \
  -- "${scratch_database}" ||
  fail "scratch_database_create_failed"

pg_restore \
  --exit-on-error \
  --no-owner \
  --no-privileges \
  --host="${scratch_socket}" \
  --port="${scratch_port}" \
  --dbname="${scratch_database}" \
  "${archive_path}" ||
  fail "scratch_restore_failed"

required_table_count="$(
  psql \
    --host="${scratch_socket}" \
    --port="${scratch_port}" \
    --dbname="${scratch_database}" \
    -v ON_ERROR_STOP=1 \
    -Atqc "
      SELECT count(*)
      FROM pg_catalog.pg_tables
      WHERE schemaname = 'public'
        AND tablename IN (
          'intents',
          'design_reservations',
          'plans',
          'approvals',
          'runs',
          'fabric_locks',
          'evidence',
          'audit_events',
          'network_allocations',
          'scalar_allocations',
          'owned_state_manifests'
        );
    "
)"
[ "${required_table_count}" = "11" ] ||
  fail "restored_schema_incomplete"

invalid_audit_hash_count="$(
  psql \
    --host="${scratch_socket}" \
    --port="${scratch_port}" \
    --dbname="${scratch_database}" \
    -v ON_ERROR_STOP=1 \
    -Atqc "
      SELECT count(*)
      FROM audit_events
      WHERE event_hash IS NULL
         OR event_hash = ''
         OR previous_hash IS NULL;
    "
)"
[ "${invalid_audit_hash_count}" = "0" ] ||
  fail "restored_audit_hash_invalid"

"${postgres_bindir}/pg_ctl" \
  --pgdata="${scratch_data}" \
  --mode=fast \
  --timeout=30 \
  --wait \
  stop >/dev/null ||
  fail "scratch_cluster_stop_failed"
cluster_running=false

finished_epoch="$(date +%s)"
restore_seconds="$((finished_epoch - started_epoch))"
archive_sha256="${expected_sha256}"
printf '%s' "${archive_sha256}" | grep -Eq '^[0-9a-f]{64}$' ||
  fail "archive_checksum_invalid"

printf '%s\n' \
  "restore_verify_status=passed" \
  "archive_sha256=${archive_sha256}" \
  "required_table_count=${required_table_count}" \
  "invalid_audit_hash_count=${invalid_audit_hash_count}" \
  "restore_seconds=${restore_seconds}"
