from __future__ import annotations

import copy
import hashlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration
from orchestrator.store import StateStore, sha256_json
from orchestrator.worker import TransactionWorker


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "examples" / "fabric-requirements.cop29-sanitized.yaml"
GUARDRAILS = ROOT / "policy" / "guardrails.cop29-sanitized.yaml"


class Schema12FakeAdapter:
    def __init__(self, device, intent, fail_shared=False):
        self.device = device
        self.intent = intent
        self.fail_shared = fail_shared
        self.rollback_calls = []

    def connect(self):
        pass

    def close(self):
        pass

    def run_show(self, command):
        if command == "show version":
            output = "Cisco IOS XE Software, Version {}".format(
                self.device["software_version"]
            )
        elif command == "show isis neighbors":
            output = "\n".join(
                "peer-{0} L2 Twe1/0/{0} 10.255.0.{0} UP 24 0A".format(index)
                for index in range(1, 9)
            )
        elif command == "show lisp session":
            output = "Sessions for VRF default, total: 2, established: 2"
        elif command == "show nve peers":
            output = (
                "nve1 8100 L2CP 10.255.255.1 2 8100 UP A/M 00:12:00\n"
                "nve1 8100 L2CP 10.255.255.2 2 8100 UP A/M 00:12:00"
            )
        elif command.startswith("show bgp"):
            device_id = str(self.device["id"])
            neighbors = []
            for peer in self.intent["border_handoff"]["peers"]:
                if peer["device_id"] == device_id:
                    neighbors.append(peer["neighbor_ip"])
                if peer.get("fusion_node_id") == device_id:
                    neighbors.append(peer["local_ip"])
            output = "\n".join(
                "{} 4 65000 12 14 3 0 0 00:10:00 8".format(item)
                for item in sorted(set(neighbors))
            )
        elif command.startswith("show ip route vrf"):
            prefix = command.split()[-1]
            output = "Routing entry for {}\n  Known via BGP".format(prefix)
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
        if self.fail_shared and any(
            command.startswith("ip route vrf ") for command in commands
        ):
            self.fail_shared = False
            raise RuntimeError("simulated shared-services apply failure")
        joined = "\n".join(commands)
        return {
            "command_count": len(commands),
            "command_hash": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
            "output_hash": hashlib.sha256(b"accepted").hexdigest(),
        }

    def rollback(self, checkpoint):
        self.rollback_calls.append(checkpoint)
        return {
            "checkpoint": checkpoint,
            "output_hash": hashlib.sha256(b"rollback").hexdigest(),
            "verification_output_hash": hashlib.sha256(b"clean-diff").hexdigest(),
            "verified": True,
        }


class Schema12WorkerTests(unittest.TestCase):
    def test_shared_service_blocker_refuses_apply_before_device_connection(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-blocker.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-blocker-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = render_configuration(intent, plan)
            blocker_codes = {
                item["code"] for item in artifact["blocking_requirements"]
            }
            self.assertIn(
                "shared_services.hardware_acceptance_pending", blocker_codes
            )
            plan_record, _ = store.save_plan(
                intent_record["intent_id"],
                plan,
                "planner",
                artifact_hash=artifact["artifact_hash"],
                intent_version=str(intent["schema_version"]),
                reservation_id=reservation["reservation_id"],
            )
            store.record_approval(
                plan_record["plan_id"],
                "approved",
                "approver",
                "CHG-SCHEMA12-BLOCKER",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-shared-service-blocker",
                requested_by="operator",
                execution_enabled=True,
                maintenance_start=(now - timedelta(minutes=1)).isoformat(),
                maintenance_end=(now + timedelta(minutes=30)).isoformat(),
            )
            adapter_calls = []

            def factory(device):
                adapter_calls.append(device["id"])
                return Schema12FakeAdapter(device, intent)

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertFalse(result["rolled_back"])
            self.assertEqual("apply_failed", result["run"]["status"])
            self.assertEqual([], adapter_calls)
            self.assertEqual([], store.run_evidence(run["run_id"]))
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("reserved", stored["state"])

    def test_shared_service_failure_rolls_back_fusion_node(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-worker.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-worker-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = copy.deepcopy(render_configuration(intent, plan))

            # Simulate a future hardware-acceptance decision. The test does not
            # weaken production behavior: the real renderer keeps all pending
            # feature blockers until their acceptance gates are complete.
            artifact["blocking_requirements"] = []
            artifact_without_hash = dict(artifact)
            artifact_without_hash.pop("artifact_hash", None)
            artifact["artifact_hash"] = sha256_json(artifact_without_hash)
            plan_record, _ = store.save_plan(
                intent_record["intent_id"],
                plan,
                "planner",
                artifact_hash=artifact["artifact_hash"],
                intent_version=str(intent["schema_version"]),
                reservation_id=reservation["reservation_id"],
            )
            store.record_approval(
                plan_record["plan_id"],
                "approved",
                "approver",
                "CHG-SCHEMA12-TEST",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-shared-service-rollback",
                requested_by="operator",
                execution_enabled=True,
                maintenance_start=(now - timedelta(minutes=1)).isoformat(),
                maintenance_end=(now + timedelta(minutes=30)).isoformat(),
            )

            adapters = {}

            def factory(device):
                adapter = Schema12FakeAdapter(
                    device,
                    intent,
                    fail_shared=(device["id"] == "fusion-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertIn("fusion-01", adapters)
            self.assertTrue(adapters["fusion-01"].rollback_calls)
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("released", stored["state"])


if __name__ == "__main__":
    unittest.main()
