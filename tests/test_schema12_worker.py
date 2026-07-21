from __future__ import annotations

import copy
import hashlib
import ipaddress
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from orchestrator.planner import create_plan
from orchestrator.reconciliation import build_multicast_owned_state
from orchestrator.renderer import render_configuration
from orchestrator.store import StateStore, sha256_json
from orchestrator.worker import TransactionWorker


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "examples" / "fabric-requirements.cop29-sanitized.yaml"
GUARDRAILS = ROOT / "policy" / "guardrails.cop29-sanitized.yaml"


class Schema12FakeAdapter:
    def __init__(
        self,
        device,
        intent,
        fail_shared=False,
        fail_pubsub=False,
        fail_multicast=False,
        fail_fusion_multicast=False,
        fail_policy=False,
        fail_reconciliation=False,
    ):
        self.device = device
        self.intent = intent
        self.fail_shared = fail_shared
        self.fail_pubsub = fail_pubsub
        self.fail_multicast = fail_multicast
        self.fail_fusion_multicast = fail_fusion_multicast
        self.fail_policy = fail_policy
        self.fail_reconciliation = fail_reconciliation
        self.pubsub_failure_injected = False
        self.multicast_failure_injected = False
        self.fusion_multicast_failure_injected = False
        self.policy_failure_injected = False
        self.reconciliation_failure_injected = False
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
        elif command == "show ip msdp peer":
            devices = {item["id"]: item for item in self.intent["devices"]}
            output = "\n".join(
                "MSDP Peer {} (?), AS 0, state: established".format(
                    devices[peer_id]["loopback0_ip"]
                )
                for peer_id in self.intent["multicast"]["rp_device_ids"]
                if peer_id != self.device["id"]
            )
        elif command == "show lisp session":
            output = "Sessions for VRF default, total: 2, established: 2"
        elif (
            command.startswith("show lisp instance-id")
            and command.endswith("publisher config-propagation")
        ):
            devices = {item["id"]: item for item in self.intent["devices"]}
            output = "\n".join(
                "{} Reachable Up Established".format(
                    devices[publisher_id]["loopback0_ip"]
                )
                for publisher_id in self.intent["lisp"]["publishers"]
            )
        elif command == "show running-config | section ^router lisp":
            commands = [
                "router lisp",
                " domain-id {}".format(self.intent["lisp"]["domain_id"]),
            ]
            group = next(
                (
                    item
                    for item in self.intent["lisp"]["multihoming_groups"]
                    if self.device["id"] in item["border_device_ids"]
                ),
                None,
            )
            if group is not None:
                commands.append(
                    " multihoming-id {}".format(group["multihoming_id"])
                )
            commands.append(" service ipv4")
            output = "\n".join(commands)
        elif command == "show nve peers":
            output = (
                "nve1 8100 L2CP 10.255.255.1 2 8100 UP A/M 00:12:00\n"
                "nve1 8100 L2CP 10.255.255.2 2 8100 UP A/M 00:12:00"
            )
        elif command.startswith(
            "show running-config | include ^ip multicast-routing vrf "
        ):
            vrf = command.split("vrf ", 1)[1].split("|", 1)[0]
            policy = next(
                item
                for item in self.intent["multicast"]["overlay_policies"]
                if item["vrf"] == vrf
            )
            lines = ["ip multicast-routing vrf {}".format(vrf)]
            if policy["mode"] == "ssm":
                lines.append(
                    "ip pim vrf {} ssm range {}".format(
                        vrf, policy["access_list"]
                    )
                )
            else:
                if "fusion" not in set(self.device.get("roles", [])):
                    lines.append(
                        "ip pim vrf {} register-source Loopback{}".format(
                            vrf, policy["l3_instance_id"]
                        )
                    )
                lines.append(
                        "ip pim vrf {} rp-address {} {}".format(
                            vrf,
                            policy["rp_address"],
                            policy["access_list"],
                        )
                )
            output = "\n".join(lines)
        elif command.startswith(
            "show running-config | section ^ip access-list standard SDA-MCAST-"
        ):
            access_list = command.rsplit(" ", 1)[1].rstrip("$")
            policy = next(
                item
                for item in self.intent["multicast"]["overlay_policies"]
                if item["access_list"] == access_list
            )
            group_range = ipaddress.ip_network(policy["group_range"])
            output = "\n".join(
                [
                    "ip access-list standard {}".format(access_list),
                    " 10 permit {} {}".format(
                        group_range.network_address, group_range.hostmask
                    ),
                ]
            )
        elif command.startswith(
            "show running-config | section ^interface Vlan"
        ):
            vlan_id = command.split("Vlan", 1)[1].rstrip("$")
            output = "\n".join(
                [
                    "interface Vlan{}".format(vlan_id),
                    " ip pim passive",
                    " ip igmp version 3",
                    " ip igmp explicit-tracking",
                ]
            )
        elif command.startswith("show ip pim vrf ") and command.endswith(" interface"):
            vrf = command.split()[4]
            policy = next(
                item
                for item in self.intent["multicast"]["overlay_policies"]
                if item["vrf"] == vrf
            )
            interfaces = [
                "Loopback{}".format(policy["l3_instance_id"]),
                "LISP0.{}".format(policy["l3_instance_id"]),
            ]
            roles = set(self.device.get("roles", []))
            if "fabric_edge" in roles:
                interfaces.extend(
                    "Vlan{}".format(pool["vlan_id"])
                    for pool in self.intent["endpoint_pools"]
                    if pool["virtual_network"] == policy["virtual_network"]
                )
            if "border" in roles:
                interfaces.extend(
                    peer["interface"]
                    for peer in self.intent["border_handoff"]["peers"]
                    if peer["device_id"] == self.device["id"]
                    and peer["vrf"] == vrf
                )
            if "fusion" in roles:
                interfaces.extend(
                    "Vlan{}".format(peer["vlan_id"])
                    for peer in self.intent["border_handoff"]["peers"]
                    if peer.get("fusion_node_id") == self.device["id"]
                    and peer["vrf"] == vrf
                )
            output = "\n".join(
                "10.0.0.1 {} v2/S 0 30 1".format(interface)
                for interface in sorted(set(interfaces))
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
        if self.fail_reconciliation and any(
            command.lstrip().startswith("no ") for command in commands
        ):
            self.fail_reconciliation = False
            self.reconciliation_failure_injected = True
            raise RuntimeError("simulated owned-state reconciliation failure")
        if self.fail_policy and any(
            command.strip().startswith("cts sxp connection peer ")
            for command in commands
        ):
            self.fail_policy = False
            self.policy_failure_injected = True
            raise RuntimeError("simulated policy-plane apply failure")
        if self.fail_pubsub and any(
            command.strip().startswith("import publication publisher ")
            for command in commands
        ):
            self.fail_pubsub = False
            self.pubsub_failure_injected = True
            raise RuntimeError("simulated LISP Pub/Sub apply failure")
        if self.fail_multicast and any(
            command.strip() == "ip pim lisp transport multicast"
            for command in commands
        ):
            self.fail_multicast = False
            self.multicast_failure_injected = True
            raise RuntimeError("simulated multicast apply failure")
        if self.fail_fusion_multicast and any(
            command.strip().startswith("ip pim vrf ")
            and " rp-address " in command
            for command in commands
        ):
            self.fail_fusion_multicast = False
            self.fusion_multicast_failure_injected = True
            raise RuntimeError("simulated fusion multicast apply failure")
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
            self.assertIn(
                "policy_plane.hardware_api_acceptance_pending", blocker_codes
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

    def test_owned_state_prune_failure_rolls_back_and_preserves_prior_baseline(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-reconcile.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-reconcile-design", "planner"
            )
            previous_intent = reservation["intent"]
            previous_manifest = build_multicast_owned_state(previous_intent)
            prior_baseline = store.record_adopted_owned_state(
                fabric_id=previous_intent["fabric"]["id"],
                manifest=previous_manifest,
                evidence_hash="c" * 64,
                change_reference="CHG-SCHEMA12-BASELINE",
                discovered_by="discovery-operator",
                approver="baseline-approver",
            )
            intent = copy.deepcopy(previous_intent)
            intent["fabric"]["multicast"].update(
                {"enabled": False, "transport": "native"}
            )
            intent["fabric"]["multicast"].pop("rp_address", None)
            intent["fabric"]["multicast"].pop("rp_device_ids", None)
            intent["multicast"] = {
                "enabled": False,
                "transport": "native",
                "rp_mode": "none",
                "asm_virtual_networks": [],
                "ssm_virtual_networks": [],
                "ssm_range": "232.0.0.0/8",
                "overlay_policies": [],
                "l2_bum_groups": [],
            }
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent, prior_baseline)
            artifact = copy.deepcopy(render_configuration(intent, plan))
            self.assertGreater(
                artifact["reconciliation"]["stale_resource_count"], 0
            )

            # Bypass platform-acceptance blockers only inside this rollback
            # harness. Production rendering remains fail-closed.
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
            )
            store.record_approval(
                plan_record["plan_id"],
                "approved",
                "approver",
                "CHG-SCHEMA12-RECONCILE",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-reconcile-rollback",
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
                    fail_reconciliation=(device["id"] == "border-cp-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertTrue(
                adapters["border-cp-01"].reconciliation_failure_injected
            )
            self.assertTrue(adapters["border-cp-01"].rollback_calls)
            self.assertEqual(
                prior_baseline["baseline_hash"],
                store.latest_owned_state(intent["fabric"]["id"])["baseline_hash"],
            )

    def test_pubsub_failure_rolls_back_subscriber_node(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-pubsub.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-pubsub-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = copy.deepcopy(render_configuration(intent, plan))

            # Model an explicit future hardware-acceptance decision only inside
            # this failure-injection harness. Production apply remains blocked.
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
                "CHG-SCHEMA12-PUBSUB",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-pubsub-rollback",
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
                    fail_pubsub=(device["id"] == "border-cp-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertTrue(adapters["border-cp-01"].pubsub_failure_injected)
            self.assertTrue(adapters["border-cp-01"].rollback_calls)
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("released", stored["state"])

    def test_multicast_failure_rolls_back_fabric_edge(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-multicast.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-multicast-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = copy.deepcopy(render_configuration(intent, plan))

            # Simulate a future platform-acceptance decision only inside this
            # failure-injection harness. Production rendering stays blocked.
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
                "CHG-SCHEMA12-MULTICAST",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-multicast-rollback",
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
                    fail_multicast=(device["id"] == "edge-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertTrue(adapters["edge-01"].multicast_failure_injected)
            self.assertTrue(adapters["edge-01"].rollback_calls)
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("released", stored["state"])

    def test_fusion_multicast_failure_rolls_back_fusion_node(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-fusion-multicast.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-fusion-multicast-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = copy.deepcopy(render_configuration(intent, plan))

            # Bypass pending acceptance blockers only in this failure-injection
            # harness. The production renderer remains fail-closed.
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
                "CHG-SCHEMA12-FUSION-MULTICAST",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-fusion-multicast-rollback",
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
                    fail_fusion_multicast=(device["id"] == "fusion-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertTrue(
                adapters["fusion-01"].fusion_multicast_failure_injected
            )
            self.assertTrue(adapters["fusion-01"].rollback_calls)
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("released", stored["state"])

    def test_policy_plane_failure_rolls_back_sxp_speaker(self):
        requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            store = StateStore(str(Path(temp_dir) / "schema12-policy.sqlite3"))
            reservation, _ = store.reserve_design(
                requirements, policy, "schema12-policy-design", "planner"
            )
            intent = reservation["intent"]
            intent_record, _ = store.save_intent(intent, "planner")
            plan = create_plan(intent)
            artifact = copy.deepcopy(render_configuration(intent, plan))

            # Simulate future ISE and platform acceptance only in this
            # failure-injection harness. Production rendering remains blocked.
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
                "CHG-SCHEMA12-POLICY",
                (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )
            now = datetime.now(timezone.utc)
            run, _ = store.create_run(
                plan_id=plan_record["plan_id"],
                mode="apply",
                idempotency_key="schema12-policy-rollback",
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
                    fail_policy=(device["id"] == "border-cp-01"),
                )
                adapters[device["id"]] = adapter
                return adapter

            result = TransactionWorker(
                store, factory, lambda _reference: "resolved-test-secret"
            ).process_apply(run["run_id"], intent, plan_record["document"], artifact)

            self.assertFalse(result["succeeded"])
            self.assertTrue(result["rolled_back"], result)
            self.assertEqual("rolled_back", result["run"]["status"])
            self.assertTrue(adapters["border-cp-01"].policy_failure_injected)
            self.assertTrue(adapters["border-cp-01"].rollback_calls)
            stored = store.get_design_reservation(reservation["reservation_id"])
            self.assertEqual("released", stored["state"])

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
