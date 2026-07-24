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


if __name__ == "__main__":
    unittest.main()
