from __future__ import annotations

import concurrent.futures
import copy
import ipaddress
import tempfile
import unittest
from pathlib import Path

import yaml

from orchestrator.store import ConflictError, StateStore


ROOT = Path(__file__).resolve().parents[1]


class AllocationStoreTests(unittest.TestCase):
    def setUp(self):
        self.requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.lab.yaml").read_text(encoding="utf-8")
        )
        self.policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.yaml").read_text(encoding="utf-8")
        )
        self.tempdir = tempfile.TemporaryDirectory()
        self.store = StateStore(str(Path(self.tempdir.name) / "state.sqlite3"))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_idempotent_retry_returns_the_same_reservation(self):
        first, created = self.store.reserve_design(
            self.requirements, self.policy, "design-request-0001", "planner-a"
        )
        second, retried = self.store.reserve_design(
            self.requirements, self.policy, "design-request-0001", "planner-a"
        )
        self.assertTrue(created)
        self.assertFalse(retried)
        self.assertEqual(first["reservation_id"], second["reservation_id"])
        self.assertEqual(first["intent"], second["intent"])

    def test_idempotency_key_cannot_be_rebound(self):
        self.store.reserve_design(
            self.requirements, self.policy, "design-request-0002", "planner-a"
        )
        changed = copy.deepcopy(self.requirements)
        changed["virtual_networks"][0]["sites"][0]["users"] += 1
        with self.assertRaisesRegex(ConflictError, "different requirements"):
            self.store.reserve_design(changed, self.policy, "design-request-0002", "planner-a")

    def test_parallel_reservations_do_not_overlap_or_duplicate_scalars(self):
        def reserve(index):
            store = StateStore(str(Path(self.tempdir.name) / "state.sqlite3"))
            candidate = copy.deepcopy(self.requirements)
            candidate["fabric"]["id"] = "fab-concurrent-{:03d}".format(index)
            candidate["fabric"]["name"] = "FAB-CONCURRENT-{:03d}".format(index)
            return store.reserve_design(
                candidate,
                self.policy,
                "concurrent-request-{:04d}".format(index),
                "planner-{}".format(index),
            )[0]

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(reserve, range(8)))

        networks = {}
        scalars = set()
        for result in results:
            for item in result["network_allocations"]:
                key = item["resource_pool_id"]
                prefix = ipaddress.ip_network(item["prefix"])
                for existing in networks.setdefault(key, []):
                    self.assertFalse(prefix.overlaps(existing), (key, prefix, existing))
                networks[key].append(prefix)
            for item in result["scalar_allocations"]:
                key = (item["resource_type"], item["value"])
                self.assertNotIn(key, scalars)
                scalars.add(key)

    def test_unverified_release_is_blocked_and_quarantine_stays_active(self):
        reservation, _ = self.store.reserve_design(
            self.requirements, self.policy, "design-request-0003", "planner-a"
        )
        with self.assertRaisesRegex(ConflictError, "verified"):
            self.store.transition_design_reservation(
                reservation["reservation_id"], "released", "worker", verified=False
            )
        quarantined = self.store.transition_design_reservation(
            reservation["reservation_id"], "quarantined", "worker"
        )
        self.assertEqual("quarantined", quarantined["state"])
        self.assertTrue(all(item["state"] == "quarantined" for item in quarantined["network_allocations"]))

        second, _ = self.store.reserve_design(
            self.requirements, self.policy, "design-request-0004", "planner-b"
        )
        first_underlay = next(
            item["prefix"]
            for item in quarantined["network_allocations"]
            if item["resource_pool_id"] == "underlay_p2p"
        )
        second_underlay = next(
            item["prefix"]
            for item in second["network_allocations"]
            if item["resource_pool_id"] == "underlay_p2p"
        )
        self.assertNotEqual(first_underlay, second_underlay)

    def test_verified_cleanup_releases_all_resources_together(self):
        reservation, _ = self.store.reserve_design(
            self.requirements, self.policy, "design-request-0005", "planner-a"
        )
        released = self.store.transition_design_reservation(
            reservation["reservation_id"], "released", "operator", verified=True
        )
        self.assertEqual("released", released["state"])
        self.assertTrue(all(item["state"] == "released" for item in released["network_allocations"]))
        self.assertTrue(all(item["state"] == "released" for item in released["scalar_allocations"]))
        self.assertTrue(self.store.verify_audit_chain())


if __name__ == "__main__":
    unittest.main()
