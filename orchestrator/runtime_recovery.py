"""Read-only inspection of apply-run and fabric-lock recovery state."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Sequence


ACTIVE_LOCK_STATUSES = frozenset(
    {"apply_queued", "apply_running", "rollback_running"}
)
MAX_REPORTED_LOCKS = 100


class RuntimeRecoveryInspectionError(RuntimeError):
    pass


def _identity_hash(value: Any) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _utc(value: Any) -> datetime:
    if not isinstance(value, datetime):
        raise RuntimeRecoveryInspectionError("Recovery timestamp is invalid")
    if value.tzinfo is None:
        raise RuntimeRecoveryInspectionError("Recovery timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


def build_recovery_report(
    lock_rows: Sequence[Mapping[str, Any]],
    status_rows: Iterable[Mapping[str, Any]],
    inspected_at: datetime,
) -> Mapping[str, Any]:
    now = _utc(inspected_at)
    issues = []
    locks = []

    if len(lock_rows) > MAX_REPORTED_LOCKS:
        issues.append(
            {
                "code": "fabric_lock.report_limit_exceeded",
                "severity": "blocking",
            }
        )

    for row in lock_rows[:MAX_REPORTED_LOCKS]:
        status = str(row.get("status", "")).strip()
        acquired_at = _utc(row.get("acquired_at"))
        expires_at = _utc(row.get("expires_at"))
        updated_at = _utc(row.get("updated_at"))
        expired = expires_at <= now

        if status not in ACTIVE_LOCK_STATUSES:
            issues.append(
                {
                    "code": "fabric_lock.invalid_run_status",
                    "severity": "blocking",
                    "run_id_hash": _identity_hash(row.get("run_id")),
                }
            )
        if expired:
            issues.append(
                {
                    "code": "fabric_lock.expired_manual_recovery_required",
                    "severity": "blocking",
                    "run_id_hash": _identity_hash(row.get("run_id")),
                }
            )
        if expires_at <= acquired_at:
            issues.append(
                {
                    "code": "fabric_lock.invalid_lease_window",
                    "severity": "blocking",
                    "run_id_hash": _identity_hash(row.get("run_id")),
                }
            )

        locks.append(
            {
                "fabric_id_hash": _identity_hash(row.get("fabric_id")),
                "run_id_hash": _identity_hash(row.get("run_id")),
                "status": status,
                "expired": expired,
                "lease_age_seconds": max(
                    0, int((now - acquired_at).total_seconds())
                ),
                "run_update_age_seconds": max(
                    0, int((now - updated_at).total_seconds())
                ),
            }
        )

    status_counts = {}
    for row in status_rows:
        mode = str(row.get("mode", "")).strip()
        status = str(row.get("status", "")).strip()
        count = row.get("count")
        if mode not in {"dry_run", "apply"} or not status:
            raise RuntimeRecoveryInspectionError("Run status summary is invalid")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise RuntimeRecoveryInspectionError("Run status count is invalid")
        status_counts["{}:{}".format(mode, status)] = count

    return {
        "schema_version": "1.0",
        "inspection_mode": "read_only",
        "inspected_at": now.isoformat().replace("+00:00", "Z"),
        "active_lock_count": len(lock_rows),
        "expired_lock_count": sum(1 for item in locks if item["expired"]),
        "reported_lock_count": len(locks),
        "run_status_counts": dict(sorted(status_counts.items())),
        "locks": locks,
        "issues": issues,
        "safe": not issues,
        "unattended_takeover_allowed": False,
        "automatic_lock_release_allowed": False,
        "contains_raw_identifiers": False,
        "contains_secret_values": False,
    }


def inspect_postgresql(database_url: str) -> Mapping[str, Any]:
    expected = "postgresql:///sda_orchestrator?host=/var/run/postgresql"
    if database_url != expected:
        raise RuntimeRecoveryInspectionError("Unsupported recovery database URL")

    try:
        import psycopg
        from psycopg.rows import dict_row
    except ImportError as exc:
        raise RuntimeRecoveryInspectionError(
            "psycopg is required for runtime recovery inspection"
        ) from exc

    with psycopg.connect(
        database_url,
        row_factory=dict_row,
        connect_timeout=10,
        application_name="sda-runtime-recovery-inspector",
    ) as connection:
        with connection.transaction():
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '5s'")
            inspected_at = connection.execute(
                "SELECT CURRENT_TIMESTAMP AS inspected_at"
            ).fetchone()["inspected_at"]
            lock_rows = connection.execute(
                """
                SELECT
                    lock.fabric_id,
                    lock.run_id,
                    lock.acquired_at,
                    lock.expires_at,
                    run.status,
                    run.updated_at
                FROM fabric_locks AS lock
                INNER JOIN runs AS run ON run.run_id = lock.run_id
                ORDER BY lock.acquired_at, lock.fabric_id
                """
            ).fetchall()
            status_rows = connection.execute(
                """
                SELECT mode, status, count(*)::integer AS count
                FROM runs
                GROUP BY mode, status
                ORDER BY mode, status
                """
            ).fetchall()
    return build_recovery_report(lock_rows, status_rows, inspected_at)
