from __future__ import annotations

import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
import yaml

from orchestrator.intent import load_intent
from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration
from orchestrator.store import StateStore
from orchestrator.worker import TransactionWorker


ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ROOT / "examples" / "fabric-intent.production.yaml"
REQUIREMENTS = ROOT / "examples" / "fabric-requirements.lab.yaml"
GUARDRAILS = ROOT / "policy" / "guardrails.yaml"


class FakeAdapter:
    def __init__(
        self,
        device,
        fail_apply=False,
        fail_rollback=False,
        unverified_rollback=False,
    ):
        self.device = device
        self.fail_apply = fail_apply
        self.fail_rollback = fail_rollback
        self.unverified_rollback = unverified_rollback
        self.connected = False
        self.rollback_calls = []

    def connect(self):
        self.connected = True

    def close(self):
        self.connected = False

    def run_show(self, command):
        if command == "show version":
            output = "Cisco IOS XE Software, Version {}".format(
                self.device["software_version"]
            )
        elif command == "show isis neighbors":
            output = """
peer-a L2 Twe1/0/1 10.255.0.1 UP 24 0A
peer-b L2 Twe1/0/2 10.255.0.3 UP 24 0B
"""
        elif command == "show lisp session":
            output = "Sessions for VRF default, total: 2, established: 2"
        elif command == "show nve peers":
            output = "nve1 8100 L2CP 10.255.1.1 2 8100 UP A/M 00:12:00\n" \
                "nve1 8100 L2CP 10.255.1.2 2 8100 UP A/M 00:12:00"
        elif command.startswith("show bgp"):
            output = "\n".join(
                [
                    "198.51.100.1 4 65100 12 14 3 0 0 00:10:00 8",
                    "198.51.100.3 4 65100 12 14 3 0 0 00:10:00 8",
                    "198.51.100.5 4 65100 12 14 3 0 0 00:10:00 8",
                    "198.51.100.7 4 65100 12 14 3 0 0 00:10:00 8",
                ]
            )
        else:
            output = ""
        return {
            "command": command,
            "output": output,
            "output_hash": hashlib.sha256(output.encode("utf-8")).hexdigest(),
        }

    def create_checkpoint(self, run_id):
        return {"checkpoint": "flash:sda-{}.cfg".format(run_id), "verified": True}

    def apply_block(self, commands):
        if self.fail_apply:
            self.fail_apply = False
            raise RuntimeError("simulated apply failure")
        joined = "\n".join(commands)
        return {
            "command_count": len(commands),
            "command_hash": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
            "output_hash": hashlib.sha256(b"accepted").hexdigest(),
        }

    def rollback(self, checkpoint):
        if self.fail_rollback:
            raise RuntimeError("simulated rollback failure")
        self.rollback_calls.append(checkpoint)
        return {
            "checkpoint": checkpoint,
            "output_hash": hashlib.sha256(b"rollback").hexdigest(),
            "verification_output_hash": hashlib.sha256(b"diff").hexdigest(),
            "verified": not self.unverified_rollback,
        }


class TransactionWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = StateStore(str(Path(self.temp.name) / "worker.sqlite3"))
        self.intent = load_intent(PRODUCTION)
        intent_record, _ = self.store.save_intent(self.intent, "planner")
        self.plan = create_plan(self.intent)
        self.artifact = render_configuration(self.intent, self.plan)
        self.plan_record, _ = self.store.save_plan(
            intent_record["intent_id"],
            self.plan,
            "planner",
            artifact_hash=self.artifact["artifact_hash"],
            intent_version=str(self.intent["schema_version"]),
        )
        self.store.record_approval(
            self.plan_record["plan_id"],
            "approved",
            "approver",
            "CHG-TEST",
            (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )

    def tearDown(self):
        self.temp.cleanup()

    def create_apply_run(self, suffix):
        now = datetime.now(timezone.utc)
        run, _ = self.store.create_run(
            plan_id=self.plan_record["plan_id"],
            mode="apply",
            idempotency_key="transaction-worker-{}".format(suffix),
            requested_by="operator",
            execution_enabled=True,
            maintenance_start=(now - timedelta(minutes=1)).isoformat(),
            maintenance_end=(now + timedelta(minutes=30)).isoformat(),
        )
        return run

    def use_dynamic_plan(self, suffix):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        reservation, _ = self.store.reserve_design(
            requirements,
            policy,
            "worker-dynamic-design-{}".format(suffix),
            "dynamic-planner",
        )
        self.intent = reservation["intent"]
        intent_record, _ = self.store.save_intent(self.intent, "dynamic-planner")
        self.plan = create_plan(self.intent)
        self.artifact = render_configuration(self.intent, self.plan)
        self.plan_record, _ = self.store.save_plan(
            intent_record["intent_id"],
            self.plan,
            "dynamic-planner",
            artifact_hash=self.artifact["artifact_hash"],
            intent_version=str(self.intent["schema_version"]),
            reservation_id=reservation["reservation_id"],
        )
        self.store.record_approval(
            self.plan_record["plan_id"],
            "approved",
            "dynamic-approver",
            "CHG-DYNAMIC",
            (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        return reservation

    def test_successful_transaction_passes_all_gates(self):
        adapters = {}

        def factory(device):
            adapter = FakeAdapter(device)
            adapters[device["id"]] = adapter
            return adapter

        run = self.create_apply_run("success")
        result = TransactionWorker(
            self.store, factory, lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertTrue(result["succeeded"], result)
        self.assertEqual("apply_succeeded", result["run"]["status"])
        self.assertTrue(self.store.verify_audit_chain())
        self.assertTrue(self.store.run_evidence(run["run_id"]))

    def test_failure_after_checkpoint_rolls_back_changed_device(self):
        adapters = {}

        def factory(device):
            adapter = FakeAdapter(device, fail_apply=(device["id"] == "border-cp-01"))
            adapters[device["id"]] = adapter
            return adapter

        run = self.create_apply_run("rollback")
        result = TransactionWorker(
            self.store, factory, lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertFalse(result["succeeded"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual("rolled_back", result["run"]["status"])
        self.assertTrue(adapters["border-cp-01"].rollback_calls)

    def test_dynamic_allocations_commit_only_after_successful_verify(self):
        reservation = self.use_dynamic_plan("success")
        run = self.create_apply_run("dynamic-success")
        result = TransactionWorker(
            self.store, lambda device: FakeAdapter(device), lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertTrue(result["succeeded"], result)
        stored = self.store.get_design_reservation(reservation["reservation_id"])
        self.assertEqual("committed", stored["state"])

    def test_dynamic_allocations_release_after_verified_rollback(self):
        reservation = self.use_dynamic_plan("rollback")

        def factory(device):
            return FakeAdapter(device, fail_apply=(device["id"] == "border-cp-01"))

        run = self.create_apply_run("dynamic-rollback")
        result = TransactionWorker(
            self.store, factory, lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertTrue(result["rolled_back"], result)
        stored = self.store.get_design_reservation(reservation["reservation_id"])
        self.assertEqual("released", stored["state"])

    def test_dynamic_allocations_quarantine_when_rollback_is_unverified(self):
        reservation = self.use_dynamic_plan("quarantine")

        def factory(device):
            return FakeAdapter(
                device,
                fail_apply=(device["id"] == "border-cp-01"),
                fail_rollback=True,
            )

        run = self.create_apply_run("dynamic-quarantine")
        result = TransactionWorker(
            self.store, factory, lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertFalse(result["rolled_back"], result)
        stored = self.store.get_design_reservation(reservation["reservation_id"])
        self.assertEqual("quarantined", stored["state"])

    def test_false_rollback_verification_quarantines_allocations(self):
        reservation = self.use_dynamic_plan("false-verification")

        def factory(device):
            return FakeAdapter(
                device,
                fail_apply=(device["id"] == "border-cp-01"),
                unverified_rollback=True,
            )

        run = self.create_apply_run("dynamic-false-verification")
        result = TransactionWorker(
            self.store, factory, lambda _ref: "resolved-test-secret"
        ).process_apply(run["run_id"], self.intent, self.plan_record["document"], self.artifact)
        self.assertFalse(result["rolled_back"], result)
        self.assertEqual("rollback_failed", result["run"]["status"])
        stored = self.store.get_design_reservation(reservation["reservation_id"])
        self.assertEqual("quarantined", stored["state"])


if __name__ == "__main__":
    unittest.main()
