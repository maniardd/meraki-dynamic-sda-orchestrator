from __future__ import annotations

import unittest
from pathlib import Path

from orchestrator.postgres_store import PostgresStateStore, _postgres_sql


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "postgresql" / "001_production_schema.sql"


class FakeConnection:
    def __init__(self):
        self.calls = []

    def execute(self, statement, parameters=()):
        self.calls.append((statement, parameters))


class PostgreSqlStoreContractTests(unittest.TestCase):
    def test_qmark_placeholders_are_translated_for_psycopg(self):
        self.assertEqual(
            "SELECT * FROM runs WHERE run_id = %s AND mode = %s",
            _postgres_sql("SELECT * FROM runs WHERE run_id = ? AND mode = ?"),
        )

    def test_allocation_and_fabric_locks_are_domain_scoped(self):
        store = object.__new__(PostgresStateStore)
        connection = FakeConnection()
        store._lock_allocation_transaction(connection, "customer-a")
        store._lock_fabric_transaction(connection, "fabric-001")
        store._lock_audit_transaction(connection)
        self.assertEqual(3, len(connection.calls))
        self.assertIn("pg_advisory_xact_lock", connection.calls[0][0])
        self.assertEqual(("allocation:customer-a",), connection.calls[0][1])
        self.assertEqual(("fabric:fabric-001",), connection.calls[1][1])
        self.assertEqual(("audit-chain",), connection.calls[2][1])

    def test_migration_matches_runtime_table_contract(self):
        rendered = MIGRATION.read_text(encoding="utf-8").lower()
        for table in (
            "intents",
            "plans",
            "approvals",
            "runs",
            "fabric_locks",
            "evidence",
            "audit_events",
            "design_reservations",
            "network_allocations",
            "scalar_allocations",
        ):
            self.assertIn("create table if not exists {}".format(table), rendered)
        self.assertIn("document_json jsonb", rendered)
        self.assertIn("payload_json jsonb", rendered)
        self.assertIn("prefix cidr", rendered)


if __name__ == "__main__":
    unittest.main()
