"""PostgreSQL-backed state store with database-enforced concurrency controls."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Mapping, Optional, Tuple

from .store import ConflictError, StateStore


MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "migrations"
    / "postgresql"
    / "001_production_schema.sql"
)


def _postgres_sql(statement: str) -> str:
    """Translate the store's DB-API qmark placeholders to psycopg format."""
    return statement.replace("?", "%s")


class _PostgresConnection:
    def __init__(self, raw: Any):
        self.raw = raw

    def execute(self, statement: str, parameters: Tuple[Any, ...] = ()):
        return self.raw.execute(_postgres_sql(statement), parameters)

    def commit(self) -> None:
        self.raw.commit()

    def rollback(self) -> None:
        self.raw.rollback()

    def close(self) -> None:
        self.raw.close()


class PostgresStateStore(StateStore):
    """StateStore implementation using PostgreSQL JSONB, CIDR and advisory locks."""

    backend_name = "postgresql"

    def __init__(self, database_url: str):
        if not str(database_url).startswith(("postgresql://", "postgres://")):
            raise ValueError("A PostgreSQL database URL is required")
        self.database_path = str(database_url)
        self.database_url = str(database_url)
        self._memory_connection = None
        try:
            import psycopg
            from psycopg import errors
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError(
                "psycopg[binary] is required for the PostgreSQL runtime"
            ) from exc
        self._psycopg = psycopg
        self._errors = errors
        self._dict_row = dict_row
        self.initialize()

    def _new_raw_connection(self):
        return self._psycopg.connect(
            self.database_url,
            row_factory=self._dict_row,
            connect_timeout=10,
            application_name="sda-orchestrator",
        )

    @contextmanager
    def connection(self) -> Iterator[_PostgresConnection]:
        raw = self._new_raw_connection()
        try:
            yield _PostgresConnection(raw)
        finally:
            raw.close()

    @contextmanager
    def transaction(self) -> Iterator[_PostgresConnection]:
        raw = self._new_raw_connection()
        try:
            with raw.transaction():
                yield _PostgresConnection(raw)
        finally:
            raw.close()

    def initialize(self) -> None:
        migration = MIGRATION.read_text(encoding="utf-8")
        raw = self._new_raw_connection()
        try:
            with raw.transaction():
                raw.execute(migration)
        finally:
            raw.close()

    def _lock_allocation_transaction(
        self, connection: _PostgresConnection, allocation_domain: str
    ) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
            ("allocation:" + allocation_domain,),
        )

    def _lock_fabric_transaction(
        self, connection: _PostgresConnection, fabric_id: str
    ) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
            ("fabric:" + fabric_id,),
        )

    def _lock_audit_transaction(self, connection: _PostgresConnection) -> None:
        connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended(?, 0))",
            ("audit-chain",),
        )

    def reserve_design(
        self,
        requirements: Mapping[str, Any],
        policy: Mapping[str, Any],
        idempotency_key: str,
        actor: str,
    ):
        try:
            return super().reserve_design(
                requirements, policy, idempotency_key, actor
            )
        except (self._errors.UniqueViolation, self._errors.ExclusionViolation) as exc:
            raise ConflictError(
                "PostgreSQL rejected a duplicate or overlapping allocation"
            ) from exc

    def create_run(self, *args, **kwargs):
        try:
            return super().create_run(*args, **kwargs)
        except self._errors.UniqueViolation as exc:
            raise ConflictError("PostgreSQL rejected a conflicting run or fabric lock") from exc
