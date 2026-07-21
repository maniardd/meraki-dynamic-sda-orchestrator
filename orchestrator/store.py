"""Durable state, approval, idempotency, locking, and audit primitives.

SQLite is used for the local development and lab runtime. The schema and
service boundary are deliberately small so the production deployment can move
to PostgreSQL without changing the HTTP or workflow contracts.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Mapping, Optional, Tuple


class StoreError(RuntimeError):
    """Base error for persistent state operations."""


class NotFoundError(StoreError):
    pass


class ConflictError(StoreError):
    pass


class ApprovalRequiredError(StoreError):
    pass


class ExecutionDisabledError(StoreError):
    pass


class MaintenanceWindowError(StoreError):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(value: Optional[datetime] = None) -> str:
    return (value or utc_now()).astimezone(timezone.utc).isoformat()


def parse_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("A timestamp is required")
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def decode_json(value: Any) -> Any:
    """Decode SQLite JSON text while accepting native PostgreSQL JSONB values."""
    return json.loads(value) if isinstance(value, str) else value


def database_timestamp(value: Any) -> Any:
    """Canonicalize database timestamps used by the signed audit chain."""
    return isoformat(value) if isinstance(value, datetime) else value


SCHEMA = """
CREATE TABLE IF NOT EXISTS intents (
    intent_id TEXT PRIMARY KEY,
    intent_hash TEXT NOT NULL UNIQUE,
    fabric_id TEXT NOT NULL,
    environment TEXT NOT NULL,
    document_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT PRIMARY KEY,
    plan_hash TEXT NOT NULL UNIQUE,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    reservation_id TEXT,
    intent_id TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    document_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY(intent_id) REFERENCES intents(intent_id),
    FOREIGN KEY(reservation_id) REFERENCES design_reservations(reservation_id)
);

CREATE TABLE IF NOT EXISTS approvals (
    approval_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('approved', 'rejected')),
    approver TEXT NOT NULL,
    change_reference TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES plans(plan_id)
);

CREATE INDEX IF NOT EXISTS approvals_plan_idx
    ON approvals(plan_id, created_at DESC);

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    artifact_hash TEXT NOT NULL,
    intent_version TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL CHECK(mode IN ('dry_run', 'apply')),
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    maintenance_start TEXT,
    maintenance_end TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(plan_id) REFERENCES plans(plan_id)
);

CREATE TABLE IF NOT EXISTS fabric_locks (
    fabric_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    acquired_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    phase_id TEXT NOT NULL,
    device_id TEXT,
    evidence_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS evidence_run_idx
    ON evidence(run_id, phase_id, created_at);

CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_aggregate_idx
    ON audit_events(aggregate_type, aggregate_id, sequence);

CREATE TABLE IF NOT EXISTS design_reservations (
    reservation_id TEXT PRIMARY KEY,
    idempotency_key_hash TEXT NOT NULL UNIQUE,
    requirements_hash TEXT NOT NULL,
    policy_hash TEXT NOT NULL,
    reservation_hash TEXT NOT NULL UNIQUE,
    allocation_domain TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','committed','released','quarantined')),
    intent_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS design_reservations_fabric_idx
    ON design_reservations(allocation_domain, fabric_id, state);

CREATE TABLE IF NOT EXISTS network_allocations (
    allocation_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    allocation_domain TEXT NOT NULL,
    resource_pool_id TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    prefix TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','committed','released','quarantined')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(reservation_id) REFERENCES design_reservations(reservation_id)
);

CREATE INDEX IF NOT EXISTS network_allocations_active_idx
    ON network_allocations(allocation_domain, resource_pool_id, state, prefix);

CREATE TABLE IF NOT EXISTS scalar_allocations (
    allocation_id TEXT PRIMARY KEY,
    reservation_id TEXT NOT NULL,
    allocation_domain TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    fabric_id TEXT NOT NULL,
    value TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','committed','released','quarantined')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(reservation_id) REFERENCES design_reservations(reservation_id)
);

CREATE INDEX IF NOT EXISTS scalar_allocations_active_idx
    ON scalar_allocations(allocation_domain, resource_type, state, value);

CREATE TABLE IF NOT EXISTS owned_state_manifests (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    fabric_id TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK(source_type IN ('successful_apply','adopted_discovery')),
    source_reference TEXT NOT NULL UNIQUE,
    source_artifact_hash TEXT,
    evidence_hash TEXT,
    manifest_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS owned_state_fabric_idx
    ON owned_state_manifests(fabric_id, sequence DESC);
"""


class StateStore:
    backend_name = "sqlite"

    def __init__(self, database_path: str):
        self.database_path = database_path
        if database_path != ":memory:":
            Path(database_path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        self._memory_connection: Optional[sqlite3.Connection] = None
        if database_path == ":memory:":
            self._memory_connection = self._new_connection()
        self.initialize()

    def _new_connection(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if self.database_path != ":memory:":
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        return connection

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        if self._memory_connection is not None:
            yield self._memory_connection
            return
        connection = self._new_connection()
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self.connection() as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                yield connection
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def initialize(self) -> None:
        with self.connection() as connection:
            connection.executescript(SCHEMA)
            self._ensure_column(connection, "plans", "artifact_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "plans", "intent_version", "TEXT NOT NULL DEFAULT '1.0'")
            self._ensure_column(connection, "plans", "reservation_id", "TEXT")
            self._ensure_column(connection, "approvals", "artifact_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "approvals", "intent_version", "TEXT NOT NULL DEFAULT '1.0'")
            self._ensure_column(connection, "runs", "artifact_hash", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(connection, "runs", "intent_version", "TEXT NOT NULL DEFAULT '1.0'")
            connection.commit()

    @staticmethod
    def _ensure_column(
        connection: sqlite3.Connection, table: str, column: str, declaration: str
    ) -> None:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info({})".format(table)).fetchall()
        }
        if column not in columns:
            connection.execute(
                "ALTER TABLE {} ADD COLUMN {} {}".format(table, column, declaration)
            )

    @staticmethod
    def _json_record(row: sqlite3.Row, field: str = "document_json") -> Dict[str, Any]:
        result = dict(row)
        result[field[:-5] if field.endswith("_json") else field] = decode_json(result.pop(field))
        return result

    def _lock_allocation_transaction(
        self, connection: sqlite3.Connection, allocation_domain: str
    ) -> None:
        """Backend hook for a domain-scoped transactional allocation lock."""

    def _lock_fabric_transaction(
        self, connection: sqlite3.Connection, fabric_id: str
    ) -> None:
        """Backend hook for a fabric-scoped transactional execution lock."""

    def _lock_audit_transaction(self, connection: sqlite3.Connection) -> None:
        """Backend hook that serializes the global tamper-evident audit chain."""

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        actor: str,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        self._lock_audit_transaction(connection)
        previous = connection.execute(
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["event_hash"]) if previous else "GENESIS"
        created_at = isoformat()
        event_id = "evt_" + uuid.uuid4().hex
        body = {
            "event_id": event_id,
            "aggregate_type": aggregate_type,
            "aggregate_id": aggregate_id,
            "event_type": event_type,
            "actor": actor,
            "payload": dict(payload),
            "previous_hash": previous_hash,
            "created_at": created_at,
        }
        event_hash = sha256_json(body)
        connection.execute(
            """INSERT INTO audit_events
               (event_id, aggregate_type, aggregate_id, event_type, actor,
                payload_json, previous_hash, event_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event_id,
                aggregate_type,
                aggregate_id,
                event_type,
                actor,
                canonical_json(payload),
                previous_hash,
                event_hash,
                created_at,
            ),
        )
        body["event_hash"] = event_hash
        return body

    def save_intent(self, intent: Mapping[str, Any], actor: str) -> Tuple[Dict[str, Any], bool]:
        intent_hash = sha256_json(intent)
        intent_id = "intent_" + intent_hash[:16]
        fabric_id = str(intent["fabric"]["id"])
        environment = str(intent["metadata"]["environment"])
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM intents WHERE intent_hash = ?", (intent_hash,)
            ).fetchone()
            if existing:
                return self._json_record(existing), False
            created_at = isoformat()
            connection.execute(
                """INSERT INTO intents
                   (intent_id, intent_hash, fabric_id, environment, document_json,
                    created_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    intent_id,
                    intent_hash,
                    fabric_id,
                    environment,
                    canonical_json(intent),
                    created_at,
                    actor,
                ),
            )
            self._append_audit(
                connection,
                "intent",
                intent_id,
                "intent.created",
                actor,
                {"intent_hash": intent_hash, "fabric_id": fabric_id, "environment": environment},
            )
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            return self._json_record(row), True

    def get_intent(self, intent_id: str) -> Dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("Intent not found")
        return self._json_record(row)

    def reserve_design(
        self,
        requirements: Mapping[str, Any],
        policy: Mapping[str, Any],
        idempotency_key: str,
        actor: str,
    ) -> Tuple[Dict[str, Any], bool]:
        """Atomically derive and reserve every address and scalar in a design."""
        from .allocator import derive_fabric_intent

        if not isinstance(idempotency_key, str) or len(idempotency_key.strip()) < 12:
            raise ValueError("idempotency_key must contain at least 12 characters")
        key_hash = hashlib.sha256(idempotency_key.strip().encode("utf-8")).hexdigest()
        requirements_hash = sha256_json(requirements)
        policy_hash = sha256_json(policy)
        with self.transaction() as connection:
            self._lock_allocation_transaction(
                connection, str(requirements.get("allocation_domain", ""))
            )
            existing = connection.execute(
                "SELECT * FROM design_reservations WHERE idempotency_key_hash = ?",
                (key_hash,),
            ).fetchone()
            if existing:
                if (
                    str(existing["requirements_hash"]) != requirements_hash
                    or str(existing["policy_hash"]) != policy_hash
                ):
                    raise ConflictError(
                        "Idempotency key is already bound to different requirements or policy"
                    )
                return self._design_reservation_record(connection, existing), False

            network_rows = connection.execute(
                """SELECT allocation_domain, resource_pool_id, prefix, state
                   FROM network_allocations
                   WHERE state IN ('reserved','committed','quarantined')"""
            ).fetchall()
            scalar_rows = connection.execute(
                """SELECT allocation_domain, resource_type, value, state
                   FROM scalar_allocations
                   WHERE state IN ('reserved','committed','quarantined')"""
            ).fetchall()
            derived = derive_fabric_intent(
                requirements,
                policy,
                network_ledger=[dict(item) for item in network_rows],
                scalar_ledger=[dict(item) for item in scalar_rows],
            )
            reservation_id = "reservation_" + uuid.uuid4().hex
            created_at = isoformat()
            allocation_domain = str(derived["reservations"]["allocation_domain"])
            fabric_id = str(derived["reservations"]["fabric_id"])
            connection.execute(
                """INSERT INTO design_reservations
                   (reservation_id, idempotency_key_hash, requirements_hash, policy_hash,
                    reservation_hash, allocation_domain, fabric_id, state, intent_json,
                    created_at, updated_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', ?, ?, ?, ?)""",
                (
                    reservation_id,
                    key_hash,
                    str(derived["requirements_hash"]),
                    str(derived["policy_hash"]),
                    str(derived["reservation_hash"]),
                    allocation_domain,
                    fabric_id,
                    canonical_json(derived["intent"]),
                    created_at,
                    created_at,
                    actor,
                ),
            )
            for item in derived["reservations"]["network"]:
                connection.execute(
                    """INSERT INTO network_allocations
                       (allocation_id, reservation_id, allocation_domain, resource_pool_id,
                        fabric_id, prefix, state, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?)""",
                    (
                        "net_" + uuid.uuid4().hex,
                        reservation_id,
                        allocation_domain,
                        str(item["resource_pool_id"]),
                        fabric_id,
                        str(item["prefix"]),
                        created_at,
                        created_at,
                    ),
                )
            for item in derived["reservations"]["scalar"]:
                connection.execute(
                    """INSERT INTO scalar_allocations
                       (allocation_id, reservation_id, allocation_domain, resource_type,
                        fabric_id, value, state, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, 'reserved', ?, ?)""",
                    (
                        "scalar_" + uuid.uuid4().hex,
                        reservation_id,
                        allocation_domain,
                        str(item["resource_type"]),
                        fabric_id,
                        str(item["value"]),
                        created_at,
                        created_at,
                    ),
                )
            self._append_audit(
                connection,
                "reservation",
                reservation_id,
                "reservation.created",
                actor,
                {
                    "allocation_domain": allocation_domain,
                    "fabric_id": fabric_id,
                    "requirements_hash": str(derived["requirements_hash"]),
                    "policy_hash": str(derived["policy_hash"]),
                    "reservation_hash": str(derived["reservation_hash"]),
                },
            )
            row = connection.execute(
                "SELECT * FROM design_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            return self._design_reservation_record(connection, row), True

    def _design_reservation_record(
        self, connection: sqlite3.Connection, row: sqlite3.Row
    ) -> Dict[str, Any]:
        result = dict(row)
        result["intent"] = decode_json(result.pop("intent_json"))
        result.pop("idempotency_key_hash", None)
        result["network_allocations"] = [
            dict(item)
            for item in connection.execute(
                """SELECT resource_pool_id, prefix, state
                   FROM network_allocations WHERE reservation_id = ?
                   ORDER BY resource_pool_id, prefix""",
                (str(row["reservation_id"]),),
            ).fetchall()
        ]
        result["scalar_allocations"] = [
            dict(item)
            for item in connection.execute(
                """SELECT resource_type, value, state
                   FROM scalar_allocations WHERE reservation_id = ?
                   ORDER BY resource_type, value""",
                (str(row["reservation_id"]),),
            ).fetchall()
        ]
        return result

    def get_design_reservation(self, reservation_id: str) -> Dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM design_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if not row:
                raise NotFoundError("Design reservation not found")
            return self._design_reservation_record(connection, row)

    def transition_design_reservation(
        self,
        reservation_id: str,
        new_state: str,
        actor: str,
        verified: bool = False,
    ) -> Dict[str, Any]:
        """Move all resources together through the safe allocation lifecycle."""
        if new_state not in {"committed", "released", "quarantined"}:
            raise ValueError("Unsupported reservation state")
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM design_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if not row:
                raise NotFoundError("Design reservation not found")
            current = str(row["state"])
            allowed = {
                "reserved": {"committed", "released", "quarantined"},
                "committed": {"released", "quarantined"},
                "quarantined": {"released"},
                "released": set(),
            }
            if new_state not in allowed[current]:
                raise ConflictError("Invalid reservation transition {} -> {}".format(current, new_state))
            if new_state == "released" and not verified:
                raise ConflictError("Release requires verified rollback or cleanup")
            updated_at = isoformat()
            connection.execute(
                """UPDATE design_reservations SET state = ?, updated_at = ?
                   WHERE reservation_id = ?""",
                (new_state, updated_at, reservation_id),
            )
            connection.execute(
                """UPDATE network_allocations SET state = ?, updated_at = ?
                   WHERE reservation_id = ?""",
                (new_state, updated_at, reservation_id),
            )
            connection.execute(
                """UPDATE scalar_allocations SET state = ?, updated_at = ?
                   WHERE reservation_id = ?""",
                (new_state, updated_at, reservation_id),
            )
            self._append_audit(
                connection,
                "reservation",
                reservation_id,
                "reservation." + new_state,
                actor,
                {"previous_state": current, "verified": bool(verified)},
            )
            updated = connection.execute(
                "SELECT * FROM design_reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            return self._design_reservation_record(connection, updated)

    def save_plan(
        self,
        intent_id: str,
        plan: Mapping[str, Any],
        actor: str,
        artifact_hash: str,
        intent_version: str = "1.0",
        reservation_id: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], bool]:
        if not isinstance(artifact_hash, str) or len(artifact_hash) != 64:
            raise ValueError("artifact_hash must be a SHA-256 hex digest")
        if not isinstance(intent_version, str) or not intent_version.strip():
            raise ValueError("intent_version is required")
        with self.transaction() as connection:
            intent = connection.execute(
                "SELECT intent_id, intent_hash, fabric_id FROM intents WHERE intent_id = ?", (intent_id,)
            ).fetchone()
            if not intent:
                raise NotFoundError("Intent not found")
            if str(plan["intent_hash"]) != str(intent["intent_hash"]):
                raise ConflictError("Plan is not bound to the stored intent hash")
            if reservation_id:
                reservation = connection.execute(
                    """SELECT reservation_id, intent_json FROM design_reservations
                       WHERE reservation_id = ?""",
                    (reservation_id,),
                ).fetchone()
                if not reservation:
                    raise NotFoundError("Design reservation not found")
                if sha256_json(decode_json(reservation["intent_json"])) != str(
                    intent["intent_hash"]
                ):
                    raise ConflictError("Reservation is not bound to the stored intent")
            existing = connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (str(plan["plan_id"]),)
            ).fetchone()
            if existing:
                if str(existing["artifact_hash"]) != artifact_hash:
                    raise ConflictError("Plan ID is already bound to a different artifact hash")
                if str(existing["reservation_id"] or "") != str(reservation_id or ""):
                    raise ConflictError("Plan ID is already bound to a different reservation")
                return self._json_record(existing), False
            created_at = isoformat()
            connection.execute(
                """INSERT INTO plans
                   (plan_id, plan_hash, artifact_hash, intent_version, reservation_id, intent_id,
                    fabric_id, document_json, created_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    str(plan["plan_id"]),
                    str(plan["plan_hash"]),
                    artifact_hash,
                    intent_version.strip(),
                    reservation_id,
                    intent_id,
                    str(intent["fabric_id"]),
                    canonical_json(plan),
                    created_at,
                    actor,
                ),
            )
            self._append_audit(
                connection,
                "plan",
                str(plan["plan_id"]),
                "plan.created",
                actor,
                {
                    "plan_hash": str(plan["plan_hash"]),
                    "artifact_hash": artifact_hash,
                    "intent_version": intent_version.strip(),
                    "reservation_id": reservation_id,
                    "intent_id": intent_id,
                    "fabric_id": str(intent["fabric_id"]),
                },
            )
            row = connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (str(plan["plan_id"]),)
            ).fetchone()
            return self._json_record(row), True

    def get_plan(self, plan_id: str) -> Dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("Plan not found")
        return self._json_record(row)

    def record_approval(
        self,
        plan_id: str,
        decision: str,
        approver: str,
        change_reference: str,
        expires_at: str,
    ) -> Dict[str, Any]:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        if not change_reference.strip():
            raise ValueError("change_reference is required")
        expiry = parse_timestamp(expires_at)
        if expiry <= utc_now():
            raise ValueError("expires_at must be in the future")
        with self.transaction() as connection:
            plan = connection.execute(
                """SELECT plan_id, plan_hash, artifact_hash, intent_version, created_by
                   FROM plans WHERE plan_id = ?""",
                (plan_id,),
            ).fetchone()
            if not plan:
                raise NotFoundError("Plan not found")
            if str(plan["created_by"]) == approver:
                raise ConflictError("Planner cannot approve their own plan")
            if not str(plan["artifact_hash"]):
                raise ConflictError("Plan has no bound rendered artifact")
            approval_id = "approval_" + uuid.uuid4().hex
            created_at = isoformat()
            connection.execute(
                """INSERT INTO approvals
                   (approval_id, plan_id, plan_hash, artifact_hash, intent_version,
                    decision, approver, change_reference, expires_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    approval_id,
                    plan_id,
                    str(plan["plan_hash"]),
                    str(plan["artifact_hash"]),
                    str(plan["intent_version"]),
                    decision,
                    approver,
                    change_reference.strip(),
                    isoformat(expiry),
                    created_at,
                ),
            )
            self._append_audit(
                connection,
                "plan",
                plan_id,
                "plan." + decision,
                approver,
                {
                    "approval_id": approval_id,
                    "plan_hash": str(plan["plan_hash"]),
                    "artifact_hash": str(plan["artifact_hash"]),
                    "intent_version": str(plan["intent_version"]),
                    "change_reference": change_reference.strip(),
                    "expires_at": isoformat(expiry),
                },
            )
            return {
                "approval_id": approval_id,
                "plan_id": plan_id,
                "plan_hash": str(plan["plan_hash"]),
                "artifact_hash": str(plan["artifact_hash"]),
                "intent_version": str(plan["intent_version"]),
                "decision": decision,
                "approver": approver,
                "change_reference": change_reference.strip(),
                "expires_at": isoformat(expiry),
                "created_at": created_at,
            }

    def _active_approval(self, connection: sqlite3.Connection, plan_id: str) -> sqlite3.Row:
        row = connection.execute(
            """SELECT * FROM approvals
               WHERE plan_id = ? ORDER BY created_at DESC LIMIT 1""",
            (plan_id,),
        ).fetchone()
        if not row or row["decision"] != "approved":
            raise ApprovalRequiredError("A current approval is required")
        if parse_timestamp(str(row["expires_at"])) <= utc_now():
            raise ApprovalRequiredError("The plan approval has expired")
        return row

    def create_run(
        self,
        plan_id: str,
        mode: str,
        idempotency_key: str,
        requested_by: str,
        execution_enabled: bool,
        maintenance_start: Optional[str] = None,
        maintenance_end: Optional[str] = None,
        lock_ttl_seconds: int = 1800,
    ) -> Tuple[Dict[str, Any], bool]:
        if mode not in {"dry_run", "apply"}:
            raise ValueError("mode must be dry_run or apply")
        if not isinstance(idempotency_key, str) or len(idempotency_key.strip()) < 12:
            raise ValueError("idempotency_key must contain at least 12 characters")
        if mode == "apply" and not execution_enabled:
            raise ExecutionDisabledError("Apply execution is disabled")
        idempotency_key_hash = hashlib.sha256(
            idempotency_key.strip().encode("utf-8")
        ).hexdigest()

        start: Optional[datetime] = None
        end: Optional[datetime] = None
        if mode == "apply":
            if not maintenance_start or not maintenance_end:
                raise MaintenanceWindowError("Apply requires a maintenance window")
            start = parse_timestamp(maintenance_start)
            end = parse_timestamp(maintenance_end)
            now = utc_now()
            if end <= start:
                raise MaintenanceWindowError("Maintenance window end must follow start")
            if not start <= now <= end:
                raise MaintenanceWindowError("Current time is outside the maintenance window")

        with self.transaction() as connection:
            plan = connection.execute(
                "SELECT * FROM plans WHERE plan_id = ?", (plan_id,)
            ).fetchone()
            if not plan:
                raise NotFoundError("Plan not found")

            existing = connection.execute(
                "SELECT * FROM runs WHERE idempotency_key_hash = ?", (idempotency_key_hash,)
            ).fetchone()
            if existing:
                if existing["plan_id"] != plan_id or existing["mode"] != mode:
                    raise ConflictError("Idempotency key is already bound to another request")
                return dict(existing), False

            approval = self._active_approval(connection, plan_id)
            if approval["plan_hash"] != plan["plan_hash"]:
                raise ApprovalRequiredError("Approval does not match the stored plan hash")
            if approval["artifact_hash"] != plan["artifact_hash"]:
                raise ApprovalRequiredError("Approval does not match the rendered artifact hash")
            if approval["intent_version"] != plan["intent_version"]:
                raise ApprovalRequiredError("Approval does not match the intent version")

            run_id = "run_" + uuid.uuid4().hex
            created_at = isoformat()
            status = "dry_run_queued" if mode == "dry_run" else "apply_queued"
            connection.execute(
                """INSERT INTO runs
                   (run_id, plan_id, plan_hash, artifact_hash, intent_version,
                    fabric_id, idempotency_key_hash, mode, status, requested_by,
                    maintenance_start, maintenance_end, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    run_id,
                    plan_id,
                    str(plan["plan_hash"]),
                    str(plan["artifact_hash"]),
                    str(plan["intent_version"]),
                    str(plan["fabric_id"]),
                    idempotency_key_hash,
                    mode,
                    status,
                    requested_by,
                    isoformat(start) if start else None,
                    isoformat(end) if end else None,
                    created_at,
                    created_at,
                ),
            )

            if mode == "apply":
                self._lock_fabric_transaction(connection, str(plan["fabric_id"]))
                lock_expiry = utc_now().timestamp() + lock_ttl_seconds
                lock_expiry_dt = datetime.fromtimestamp(lock_expiry, tz=timezone.utc)
                current_lock = connection.execute(
                    "SELECT * FROM fabric_locks WHERE fabric_id = ?", (str(plan["fabric_id"]),)
                ).fetchone()
                # A lock's expiry is an operational staleness signal, not permission
                # for automatic takeover.  The owning run releases the lock only
                # when it reaches a terminal state; a crashed run therefore fails
                # closed until an explicit recovery workflow reconciles it.
                if current_lock:
                    raise ConflictError("Fabric is locked by another active run")
                connection.execute(
                    """INSERT INTO fabric_locks
                       (fabric_id, run_id, acquired_at, expires_at)
                       VALUES (?, ?, ?, ?)""",
                    (str(plan["fabric_id"]), run_id, created_at, isoformat(lock_expiry_dt)),
                )

            self._append_audit(
                connection,
                "run",
                run_id,
                "run.created",
                requested_by,
                {
                    "plan_id": plan_id,
                    "plan_hash": str(plan["plan_hash"]),
                    "artifact_hash": str(plan["artifact_hash"]),
                    "intent_version": str(plan["intent_version"]),
                    "fabric_id": str(plan["fabric_id"]),
                    "mode": mode,
                    "status": status,
                    "approval_id": str(approval["approval_id"]),
                    "idempotency_key_hash": idempotency_key_hash,
                },
            )
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return dict(row), True

    def get_run(self, run_id: str) -> Dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if not row:
            raise NotFoundError("Run not found")
        return dict(row)

    def transition_run(
        self,
        run_id: str,
        new_status: str,
        actor: str,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        allowed = {
            "dry_run_queued": {"dry_run_running", "dry_run_failed"},
            "dry_run_running": {"dry_run_succeeded", "dry_run_blocked", "dry_run_failed"},
            "apply_queued": {"apply_running", "apply_failed"},
            "apply_running": {"apply_succeeded", "apply_failed", "rollback_running"},
            "rollback_running": {"rolled_back", "rollback_failed"},
        }
        terminal = {
            "dry_run_succeeded",
            "dry_run_blocked",
            "dry_run_failed",
            "apply_succeeded",
            "apply_failed",
            "rolled_back",
            "rollback_failed",
        }
        with self.transaction() as connection:
            run = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if not run:
                raise NotFoundError("Run not found")
            current = str(run["status"])
            if new_status not in allowed.get(current, set()):
                raise ConflictError(
                    "Invalid run transition from {} to {}".format(current, new_status)
                )
            updated_at = isoformat()
            connection.execute(
                "UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?",
                (new_status, updated_at, run_id),
            )
            if new_status in terminal:
                connection.execute("DELETE FROM fabric_locks WHERE run_id = ?", (run_id,))
            self._append_audit(
                connection,
                "run",
                run_id,
                "run.status_changed",
                actor,
                {
                    "from": current,
                    "to": new_status,
                    "detail": dict(detail or {}),
                },
            )
            updated = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return dict(updated)

    def latest_owned_state(self, fabric_id: str) -> Optional[Dict[str, Any]]:
        """Return the immutable baseline from the newest committed ownership ledger."""

        with self.connection() as connection:
            row = connection.execute(
                """SELECT * FROM owned_state_manifests
                   WHERE fabric_id = ? ORDER BY sequence DESC LIMIT 1""",
                (fabric_id,),
            ).fetchone()
        if not row:
            return None
        from .reconciliation import make_baseline

        manifest = decode_json(row["manifest_json"])
        return make_baseline(
            manifest=manifest,
            source_type=str(row["source_type"]),
            source_reference=str(row["source_reference"]),
            source_artifact_hash=(
                str(row["source_artifact_hash"])
                if row["source_artifact_hash"]
                else None
            ),
            evidence_hash=str(row["evidence_hash"]) if row["evidence_hash"] else None,
        )

    def record_adopted_owned_state(
        self,
        fabric_id: str,
        manifest: Mapping[str, Any],
        evidence_hash: str,
        change_reference: str,
        discovered_by: str,
        approver: str,
    ) -> Dict[str, Any]:
        """Seed a baseline after independent discovery and dual-control approval."""

        from .reconciliation import validate_owned_state

        validate_owned_state(manifest, fabric_id)
        if (
            not isinstance(evidence_hash, str)
            or len(evidence_hash) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in evidence_hash)
        ):
            raise ValueError("evidence_hash must be a SHA-256 hex digest")
        if not change_reference.strip():
            raise ValueError("change_reference is required")
        if not discovered_by.strip() or not approver.strip():
            raise ValueError("discovered_by and approver are required")
        if discovered_by.strip() == approver.strip():
            raise ConflictError("Baseline discovery and approval require different actors")
        source_reference = "adoption:{}:{}".format(
            change_reference.strip(), str(manifest["manifest_hash"])
        )
        with self.transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM owned_state_manifests WHERE source_reference = ?",
                (source_reference,),
            ).fetchone()
            if existing:
                if str(existing["manifest_hash"]) != str(manifest["manifest_hash"]):
                    raise ConflictError("Adoption reference is bound to another manifest")
            else:
                created_at = isoformat()
                connection.execute(
                    """INSERT INTO owned_state_manifests
                       (fabric_id, manifest_hash, source_type, source_reference,
                        source_artifact_hash, evidence_hash, manifest_json,
                        created_at, created_by)
                       VALUES (?, ?, 'adopted_discovery', ?, NULL, ?, ?, ?, ?)""",
                    (
                        fabric_id,
                        str(manifest["manifest_hash"]),
                        source_reference,
                        evidence_hash,
                        canonical_json(manifest),
                        created_at,
                        approver.strip(),
                    ),
                )
                self._append_audit(
                    connection,
                    "fabric",
                    fabric_id,
                    "owned_state.adopted",
                    approver.strip(),
                    {
                        "manifest_hash": str(manifest["manifest_hash"]),
                        "evidence_hash": evidence_hash,
                        "change_reference": change_reference.strip(),
                        "discovered_by": discovered_by.strip(),
                    },
                )
        baseline = self.latest_owned_state(fabric_id)
        if baseline is None:
            raise StoreError("Adopted owned-state baseline was not persisted")
        return baseline

    def complete_apply(
        self,
        run_id: str,
        artifact_hash: str,
        owned_state: Mapping[str, Any],
        actor: str,
        detail: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Atomically commit apply success and its resulting owned-state manifest."""

        from .reconciliation import validate_owned_state

        validate_owned_state(owned_state)
        if not isinstance(artifact_hash, str) or len(artifact_hash) != 64:
            raise ValueError("artifact_hash must be a SHA-256 hex digest")
        with self.transaction() as connection:
            run = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if not run:
                raise NotFoundError("Run not found")
            if str(run["status"]) != "apply_running":
                raise ConflictError("Run is not active for apply completion")
            if str(run["artifact_hash"]) != artifact_hash:
                raise ConflictError("Owned-state commit artifact hash does not match run")
            if str(run["fabric_id"]) != str(owned_state["fabric_id"]):
                raise ConflictError("Owned-state manifest belongs to another fabric")
            existing = connection.execute(
                "SELECT * FROM owned_state_manifests WHERE source_reference = ?",
                (run_id,),
            ).fetchone()
            if existing:
                raise ConflictError("Run already committed an owned-state manifest")
            updated_at = isoformat()
            connection.execute(
                """INSERT INTO owned_state_manifests
                   (fabric_id, manifest_hash, source_type, source_reference,
                    source_artifact_hash, evidence_hash, manifest_json,
                    created_at, created_by)
                   VALUES (?, ?, 'successful_apply', ?, ?, NULL, ?, ?, ?)""",
                (
                    str(run["fabric_id"]),
                    str(owned_state["manifest_hash"]),
                    run_id,
                    artifact_hash,
                    canonical_json(owned_state),
                    updated_at,
                    actor,
                ),
            )
            connection.execute(
                "UPDATE runs SET status = 'apply_succeeded', updated_at = ? WHERE run_id = ?",
                (updated_at, run_id),
            )
            connection.execute("DELETE FROM fabric_locks WHERE run_id = ?", (run_id,))
            self._append_audit(
                connection,
                "run",
                run_id,
                "run.status_changed",
                actor,
                {
                    "from": "apply_running",
                    "to": "apply_succeeded",
                    "detail": dict(detail or {}),
                },
            )
            self._append_audit(
                connection,
                "fabric",
                str(run["fabric_id"]),
                "owned_state.committed",
                actor,
                {
                    "run_id": run_id,
                    "artifact_hash": artifact_hash,
                    "manifest_hash": str(owned_state["manifest_hash"]),
                },
            )
            updated = connection.execute(
                "SELECT * FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            return dict(updated)

    def add_evidence(
        self,
        run_id: str,
        phase_id: str,
        evidence_type: str,
        payload: Mapping[str, Any],
        actor: str,
        device_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload_hash = sha256_json(payload)
        evidence_identity = {
            "run_id": run_id,
            "phase_id": phase_id,
            "device_id": device_id,
            "evidence_type": evidence_type,
            "payload_hash": payload_hash,
        }
        evidence_id = "evidence_" + sha256_json(evidence_identity)[:16]
        with self.transaction() as connection:
            if not connection.execute(
                "SELECT run_id FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone():
                raise NotFoundError("Run not found")
            existing = connection.execute(
                "SELECT * FROM evidence WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
            if existing:
                item = dict(existing)
                item["payload"] = decode_json(item.pop("payload_json"))
                return item
            created_at = isoformat()
            connection.execute(
                """INSERT INTO evidence
                   (evidence_id, run_id, phase_id, device_id, evidence_type,
                    payload_json, payload_hash, created_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    evidence_id,
                    run_id,
                    phase_id,
                    device_id,
                    evidence_type,
                    canonical_json(payload),
                    payload_hash,
                    created_at,
                    actor,
                ),
            )
            self._append_audit(
                connection,
                "run",
                run_id,
                "evidence.recorded",
                actor,
                {
                    "evidence_id": evidence_id,
                    "phase_id": phase_id,
                    "device_id": device_id,
                    "evidence_type": evidence_type,
                    "payload_hash": payload_hash,
                },
            )
            return {
                "evidence_id": evidence_id,
                "run_id": run_id,
                "phase_id": phase_id,
                "device_id": device_id,
                "evidence_type": evidence_type,
                "payload": dict(payload),
                "payload_hash": payload_hash,
                "created_at": created_at,
                "created_by": actor,
            }

    def run_evidence(self, run_id: str) -> list:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM evidence WHERE run_id = ? ORDER BY created_at, evidence_id",
                (run_id,),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload"] = decode_json(item.pop("payload_json"))
            result.append(item)
        return result

    def audit_events(self, aggregate_type: str, aggregate_id: str) -> list:
        with self.connection() as connection:
            rows = connection.execute(
                """SELECT * FROM audit_events
                   WHERE aggregate_type = ? AND aggregate_id = ? ORDER BY sequence""",
                (aggregate_type, aggregate_id),
            ).fetchall()
        events = []
        for row in rows:
            item = dict(row)
            item["payload"] = decode_json(item.pop("payload_json"))
            events.append(item)
        return events

    def verify_audit_chain(self) -> bool:
        with self.connection() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY sequence"
            ).fetchall()
        previous_hash = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous_hash:
                return False
            body = {
                "event_id": row["event_id"],
                "aggregate_type": row["aggregate_type"],
                "aggregate_id": row["aggregate_id"],
                "event_type": row["event_type"],
                "actor": row["actor"],
                "payload": decode_json(row["payload_json"]),
                "previous_hash": row["previous_hash"],
                "created_at": database_timestamp(row["created_at"]),
            }
            if sha256_json(body) != row["event_hash"]:
                return False
            previous_hash = row["event_hash"]
        return True

    def readiness(self) -> Dict[str, Any]:
        with self.connection() as connection:
            row = connection.execute("SELECT 1 AS ready").fetchone()
        return {
            "backend": self.backend_name,
            "database": bool(row and int(row["ready"]) == 1),
            "audit_chain": self.verify_audit_chain(),
        }


def create_state_store(database_location: str) -> StateStore:
    if str(database_location).startswith(("postgresql://", "postgres://")):
        from .postgres_store import PostgresStateStore

        return PostgresStateStore(str(database_location))
    return StateStore(str(database_location))
