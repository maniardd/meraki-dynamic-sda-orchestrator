from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "migrations" / "postgresql" / "001_production_schema.sql"


class PostgreSqlMigrationContractTests(unittest.TestCase):
    def test_network_overlap_is_enforced_by_the_database(self):
        rendered = MIGRATION.read_text(encoding="utf-8").lower()
        self.assertIn("create extension if not exists btree_gist", rendered)
        self.assertIn("exclude using gist", rendered)
        self.assertIn("prefix inet_ops with &&", rendered)
        self.assertIn("allocation_domain with =", rendered)
        self.assertIn("resource_pool_id with =", rendered)

    def test_active_scalar_uniqueness_and_quarantine_are_enforced(self):
        rendered = MIGRATION.read_text(encoding="utf-8").lower()
        self.assertIn("scalar_allocations_active_unique", rendered)
        self.assertIn("where state in ('reserved','committed','quarantined')", rendered)
        self.assertGreaterEqual(rendered.count("quarantined"), 3)

    def test_approval_binds_plan_artifact_and_intent_version(self):
        rendered = MIGRATION.read_text(encoding="utf-8").lower()
        approval = rendered.split("create table if not exists approvals", 1)[1]
        self.assertIn("plan_hash text not null", approval)
        self.assertIn("artifact_hash text not null", approval)
        self.assertIn("intent_version text not null", approval)
        self.assertIn("approver text not null", approval)


if __name__ == "__main__":
    unittest.main()
