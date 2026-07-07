from __future__ import annotations

import concurrent.futures
import copy
import ipaddress
import os
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import quote

import yaml

from orchestrator.planner import create_plan
from orchestrator.postgres_store import PostgresStateStore
from orchestrator.renderer import render_configuration
from orchestrator.simulator import process_dry_run


ROOT = Path(__file__).resolve().parents[1]
POSTGRES_DSN = os.getenv("POSTGRES_TEST_DSN", "")


@unittest.skipUnless(POSTGRES_DSN, "POSTGRES_TEST_DSN is not configured")
class PostgreSqlIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.lab.yaml").read_text(encoding="utf-8")
        )
        cls.policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.yaml").read_text(encoding="utf-8")
        )
        cls.namespace = uuid.uuid4().hex[:10]
        cls.store = PostgresStateStore(POSTGRES_DSN)

    def requirements_for(self, suffix):
        candidate = copy.deepcopy(self.requirements)
        candidate["allocation_domain"] = "ci-{}".format(self.namespace)
        candidate["fabric"]["id"] = "fab-{}-{}".format(self.namespace, suffix)
        candidate["fabric"]["name"] = "FAB-{}-{}".format(self.namespace, suffix).upper()
        return candidate

    def test_audit_chain_is_timezone_independent_at_zero_microseconds(self):
        separator = "&" if "?" in POSTGRES_DSN else "?"
        offset_dsn = "{}{}options={}".format(
            POSTGRES_DSN,
            separator,
            quote("-c timezone=Asia/Kolkata", safe=""),
        )
        offset_store = PostgresStateStore(offset_dsn)
        fixed_time = datetime(2026, 7, 7, 4, 30, 0, tzinfo=timezone.utc)
        with mock.patch("orchestrator.store.utc_now", return_value=fixed_time):
            offset_store.reserve_design(
                self.requirements_for("timezone"),
                self.policy,
                "postgres-timezone-{}".format(self.namespace),
                "postgres-timezone-planner",
            )
        with offset_store.connection() as connection:
            row = connection.execute(
                "SELECT created_at FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
        self.assertEqual(timedelta(hours=5, minutes=30), row["created_at"].utcoffset())
        self.assertEqual(0, row["created_at"].microsecond)
        self.assertTrue(offset_store.verify_audit_chain())

    def test_full_persistent_dry_run_and_audit_chain(self):
        requirements = self.requirements_for("lifecycle")
        reservation, created = self.store.reserve_design(
            requirements,
            self.policy,
            "postgres-lifecycle-{}".format(self.namespace),
            "postgres-planner",
        )
        self.assertTrue(created)
        intent = reservation["intent"]
        intent_record, _ = self.store.save_intent(intent, "postgres-planner")
        plan = create_plan(intent)
        artifact = render_configuration(intent, plan)
        plan_record, _ = self.store.save_plan(
            intent_record["intent_id"],
            plan,
            "postgres-planner",
            artifact_hash=artifact["artifact_hash"],
            intent_version=intent["schema_version"],
            reservation_id=reservation["reservation_id"],
        )
        approval = self.store.record_approval(
            plan_record["plan_id"],
            "approved",
            "postgres-approver",
            "CHG-POSTGRES-CI",
            (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        self.assertEqual(artifact["artifact_hash"], approval["artifact_hash"])
        run, _ = self.store.create_run(
            plan_record["plan_id"],
            "dry_run",
            "postgres-dry-run-{}".format(self.namespace),
            "postgres-operator",
            execution_enabled=False,
        )
        result = process_dry_run(
            self.store, run["run_id"], artifact, "postgres-worker"
        )
        self.assertEqual("dry_run_succeeded", result["run"]["status"])
        self.assertTrue(self.store.run_evidence(run["run_id"]))
        self.assertTrue(self.store.verify_audit_chain())
        self.assertEqual("postgresql", self.store.readiness()["backend"])

    def test_parallel_allocations_are_non_overlapping(self):
        def reserve(index):
            store = PostgresStateStore(POSTGRES_DSN)
            return store.reserve_design(
                self.requirements_for("parallel-{}".format(index)),
                self.policy,
                "postgres-parallel-{}-{}".format(self.namespace, index),
                "postgres-planner-{}".format(index),
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(reserve, range(8)))

        networks = {}
        scalars = set()
        for result in results:
            for item in result["network_allocations"]:
                key = item["resource_pool_id"]
                candidate = ipaddress.ip_network(str(item["prefix"]))
                for existing in networks.setdefault(key, []):
                    self.assertFalse(candidate.overlaps(existing))
                networks[key].append(candidate)
            for item in result["scalar_allocations"]:
                key = (item["resource_type"], str(item["value"]))
                self.assertNotIn(key, scalars)
                scalars.add(key)


if __name__ == "__main__":
    unittest.main()
