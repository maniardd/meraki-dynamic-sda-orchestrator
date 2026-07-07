from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.intent import load_intent
from orchestrator.planner import PlanValidationError, create_plan
from orchestrator.renderer import RenderError, render_configuration


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"
PRODUCTION_EXAMPLE = ROOT / "examples" / "fabric-intent.production.yaml"
SJC23_REQUIREMENTS = ROOT / "examples" / "fabric-requirements.sjc23-golden.yaml"
SJC23_GUARDRAILS = ROOT / "policy" / "guardrails.sjc23-golden.yaml"


class RendererTests(unittest.TestCase):
    def setUp(self):
        self.intent = load_intent(EXAMPLE)
        self.plan = create_plan(self.intent)

    def test_render_is_deterministic_and_secret_values_are_absent(self):
        first = render_configuration(self.intent, self.plan)
        second = render_configuration(self.intent, self.plan)
        self.assertEqual(first["artifact_hash"], second["artifact_hash"])
        self.assertFalse(first["contains_secret_values"])
        self.assertIn("secret://sda-lab/lisp/site-sjc23", str(first))
        self.assertNotIn("authentication-key 0", str(first))

    def test_render_targets_roles_and_contains_expected_phases(self):
        artifact = render_configuration(self.intent, self.plan)
        border_phases = {
            phase["phase_id"] for phase in artifact["devices"]["border-cp-01"]["phases"]
        }
        edge_phases = {
            phase["phase_id"] for phase in artifact["devices"]["edge-01"]["phases"]
        }
        self.assertIn("lisp_control_plane", border_phases)
        self.assertIn("border_handoff", border_phases)
        self.assertIn("lisp_edges", edge_phases)
        self.assertIn("overlay", edge_phases)

    def test_missing_bgp_handoff_blocks_execution(self):
        artifact = render_configuration(self.intent, self.plan)
        self.assertIn(
            "border_handoff.missing",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        self.assertFalse(artifact["executable"])

    def test_explicit_isolated_lab_has_no_handoff_blocker(self):
        candidate = copy.deepcopy(self.intent)
        candidate["border_handoff"] = {"mode": "isolated", "enabled": False}
        artifact = render_configuration(candidate, create_plan(candidate))
        self.assertEqual([], artifact["blocking_requirements"])

    def test_explicit_multicast_and_bfd_are_rendered(self):
        candidate = copy.deepcopy(self.intent)
        candidate["fabric"]["multicast"] = {
            "enabled": True,
            "rp_address": "10.255.255.100",
            "rp_loopback_id": 60000,
            "ssm_default": True,
        }
        candidate["links"][0]["pim_sparse_mode"] = True
        candidate["links"][0]["bfd"] = {
            "enabled": True,
            "interval_ms": 100,
            "min_rx_ms": 100,
            "multiplier": 3,
        }
        rendered = str(render_configuration(candidate, create_plan(candidate)))
        self.assertIn("interface Loopback60000", rendered)
        self.assertIn("ip pim rp-address 10.255.255.100", rendered)
        self.assertIn("bfd interval 100 min_rx 100 multiplier 3", rendered)

    def test_plan_must_match_intent(self):
        candidate = copy.deepcopy(self.intent)
        candidate["metadata"]["name"] = "different"
        with self.assertRaises(RenderError):
            render_configuration(candidate, self.plan)

    def test_cli_injection_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["devices"][0]["hostname"] = "safe\nend\nreload"
        with self.assertRaises(PlanValidationError):
            create_plan(candidate)

    def test_production_reference_renders_bgp_without_blockers(self):
        intent = load_intent(PRODUCTION_EXAMPLE)
        artifact = render_configuration(intent, create_plan(intent))
        self.assertEqual([], artifact["blocking_requirements"])
        border = str(artifact["devices"]["border-cp-01"])
        self.assertIn("router bgp 65001", border)
        self.assertIn("neighbor 198.51.100.1 remote-as 65100", border)

    def test_sjc23_golden_renderer_preserves_hardware_proven_cli(self):
        requirements = yaml.safe_load(SJC23_REQUIREMENTS.read_text(encoding="utf-8"))
        policy = yaml.safe_load(SJC23_GUARDRAILS.read_text(encoding="utf-8"))
        intent = derive_fabric_intent(requirements, policy)["intent"]
        artifact = render_configuration(intent, create_plan(intent))

        def commands(device_id):
            return [
                command
                for phase in artifact["devices"][device_id]["phases"]
                for block in phase["blocks"]
                for command in block["commands"]
            ]

        border = commands("border-cp-01")
        edge = commands("edge-01")
        for expected in (
            "interface TwentyFiveGigE1/0/2",
            " ip address 10.255.0.0 255.255.255.254",
            " service ipv4",
            "  map-server",
            "  map-resolver",
            "  proxy-etr",
            "  proxy-itr 10.255.255.1",
            "  no map-cache away-eids send-map-request",
        ):
            self.assertIn(expected, border)
        for expected in (
            "interface GigabitEthernet1/0/2",
            " ip address 10.255.0.1 255.255.255.254",
            "  itr map-resolver 10.255.255.1",
            "  use-petr 10.255.255.1",
            " instance-id 4099",
            " instance-id 4100",
        ):
            self.assertIn(expected, edge)
        self.assertTrue(
            any(command.startswith("  etr map-server 10.255.255.1 key <secret:") for command in edge)
        )


if __name__ == "__main__":
    unittest.main()
