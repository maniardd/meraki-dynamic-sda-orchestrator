from __future__ import annotations

import unittest
from pathlib import Path

from orchestrator.gates import build_gate_plan, evaluate_gate
from orchestrator.intent import load_intent


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "examples" / "fabric-intent.lab.yaml"
PRODUCTION = ROOT / "examples" / "fabric-intent.production.yaml"


class GatePlanTests(unittest.TestCase):
    def test_production_gates_are_derived_from_topology_and_bgp(self):
        gates = build_gate_plan(load_intent(PRODUCTION))
        by_id = {gate["gate_id"]: gate for gate in gates}
        self.assertEqual(2, by_id["underlay.isis.edge-01"]["expected"]["minimum_up"])
        self.assertEqual(2, by_id["lisp.sessions.edge-01"]["expected"]["minimum_established"])
        self.assertEqual(
            ["198.51.100.1", "198.51.100.3"],
            by_id["border.bgp.border-cp-01"]["expected"]["neighbors"],
        )

    def test_lab_without_handoff_has_no_bgp_gate(self):
        gates = build_gate_plan(load_intent(LAB))
        self.assertFalse(any(gate["evaluator"] == "bgp_neighbors" for gate in gates))

    def test_version_gate_is_exact(self):
        gate = {
            "evaluator": "ios_xe_version",
            "expected": {"version": "17.18.3"},
        }
        self.assertTrue(
            evaluate_gate(gate, "Cisco IOS XE Software, Version 17.18.3").passed
        )
        self.assertFalse(
            evaluate_gate(gate, "Cisco IOS XE Software, Version 17.18.2").passed
        )

    def test_every_fabric_device_has_blocking_advantage_license_gate(self):
        intent = load_intent(PRODUCTION)
        gates = build_gate_plan(intent)
        by_id = {gate["gate_id"]: gate for gate in gates}
        for device in intent["devices"]:
            gate = by_id["precheck.license.{}".format(device["id"])]
            self.assertEqual("precheck", gate["phase_id"])
            self.assertEqual("show version", gate["command"])
            self.assertEqual("ios_xe_license_level", gate["evaluator"])
            self.assertEqual(
                "network-advantage",
                gate["expected"]["network_package"],
            )
            self.assertEqual(
                ["catalyst-advantage", "dna-advantage"],
                gate["expected"]["subscription_packages"],
            )
            self.assertTrue(gate["blocking"])


    def test_underlay_mtu_gate_emitted_for_each_device_and_link(self):
        intent = load_intent(PRODUCTION)
        gates = build_gate_plan(intent)
        mtu_gates = [g for g in gates if g["evaluator"] == "interface_mtu"]
        device_ids = {str(d["id"]) for d in intent["devices"]}
        covered_devices = {g["device_id"] for g in mtu_gates}
        self.assertEqual(device_ids, covered_devices)
        for gate in mtu_gates:
            self.assertEqual("underlay", gate["phase_id"])
            self.assertTrue(gate["gate_id"].startswith("underlay.mtu."))
            self.assertTrue(gate["command"].startswith("show interfaces "))
            self.assertEqual(intent["fabric"]["mtu"], gate["expected"]["expected_mtu"])
            self.assertTrue(gate["blocking"])

    def test_underlay_mtu_gate_evaluates_pass_and_fail(self):
        intent = load_intent(LAB)
        gates = build_gate_plan(intent)
        mtu_gate = next(g for g in gates if g["evaluator"] == "interface_mtu")
        expected_mtu = mtu_gate["expected"]["expected_mtu"]
        passing_output = "GigabitEthernet0/0 is up\n  MTU {} bytes, BW 1000000\n".format(expected_mtu)
        self.assertTrue(evaluate_gate(mtu_gate, passing_output).passed)
        failing_output = "GigabitEthernet0/0 is up\n  MTU 1500 bytes, BW 1000000\n"
        self.assertFalse(evaluate_gate(mtu_gate, failing_output).passed)

    def test_underlay_bfd_gate_emitted_for_each_device_with_links(self):
        intent = load_intent(PRODUCTION)
        gates = build_gate_plan(intent)
        bfd_gates = {g["device_id"]: g for g in gates if g["evaluator"] == "bfd_neighbors"}
        device_ids = {str(d["id"]) for d in intent["devices"]}
        self.assertEqual(device_ids, set(bfd_gates))
        for gate in bfd_gates.values():
            self.assertEqual("underlay", gate["phase_id"])
            self.assertEqual("show bfd neighbors", gate["command"])
            self.assertGreater(gate["expected"]["minimum_up"], 0)
            self.assertTrue(gate["blocking"])

    def test_underlay_bfd_gate_evaluates_pass_and_fail(self):
        intent = load_intent(LAB)
        gates = build_gate_plan(intent)
        bfd_gate = next(g for g in gates if g["evaluator"] == "bfd_neighbors")
        passing = (
            "NeighAddr                              LD/RD         RH/RS     State     Int\n"
            "10.255.0.1                           4097/4097     Up        Up        Gi0/1\n"
        )
        self.assertTrue(evaluate_gate(bfd_gate, passing).passed)
        self.assertFalse(evaluate_gate(bfd_gate, "").passed)


if __name__ == "__main__":
    unittest.main()
