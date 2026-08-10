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
        candidate = copy.deepcopy(self.intent)
        candidate.pop("border_handoff")
        artifact = render_configuration(candidate, create_plan(candidate))
        self.assertIn(
            "border_handoff.missing",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        self.assertFalse(artifact["executable"])

    def test_explicit_isolated_lab_has_no_handoff_blocker(self):
        artifact = render_configuration(self.intent, self.plan)
        self.assertEqual([], artifact["blocking_requirements"])

    def test_local_border_dhcp_and_derived_endpoint_ports_are_rendered_but_blocked(self):
        candidate = copy.deepcopy(self.intent)
        for pool in candidate["endpoint_pools"]:
            pool["dhcp_helpers"] = [candidate["devices"][0]["loopback0_ip"]]
            pool["dhcp"] = {
                "mode": "local_border",
                "server_device_id": "border-cp-01",
                "helper_address": candidate["devices"][0]["loopback0_ip"],
                "relay_global": True,
                "lease_minutes": 60,
                "dns_servers": [],
            }
        candidate["endpoint_attachments"] = [
            {
                "id": "corp-laptop-01",
                "device_id": "edge-01",
                "interface": "GigabitEthernet1/0/10",
                "site": "SJC23",
                "virtual_network": "Corporate",
                "endpoint_pool_id": candidate["endpoint_pools"][0]["id"],
                "vlan_id": candidate["endpoint_pools"][0]["vlan_id"],
                "description": "CORP laptop",
            },
            {
                "id": "guest-laptop-01",
                "device_id": "edge-01",
                "interface": "GigabitEthernet1/0/11",
                "site": "SJC23",
                "virtual_network": "Guest",
                "endpoint_pool_id": candidate["endpoint_pools"][1]["id"],
                "vlan_id": candidate["endpoint_pools"][1]["vlan_id"],
                "description": "GUEST laptop",
            },
        ]
        artifact = render_configuration(candidate, create_plan(candidate))
        border = str(artifact["devices"]["border-cp-01"])
        edge = str(artifact["devices"]["edge-01"])
        self.assertIn("ip dhcp pool SDA-DHCP-", border)
        self.assertIn(
            "ip helper-address global {}".format(candidate["devices"][0]["loopback0_ip"]),
            edge,
        )
        self.assertIn("interface GigabitEthernet1/0/10", edge)
        self.assertIn("switchport access vlan 100", edge)
        self.assertIn("interface GigabitEthernet1/0/11", edge)
        self.assertIn("switchport access vlan 200", edge)
        self.assertIn(
            "poc.local_dhcp_and_attachment_hardware_acceptance_pending",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        self.assertFalse(artifact["executable"])

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


    def test_fabric_link_block_has_mtu_and_ip_mtu(self):
        artifact = render_configuration(self.intent, self.plan)
        for device_data in artifact["devices"].values():
            link_commands = [
                command
                for phase in device_data["phases"]
                for block in phase["blocks"]
                if block["block_id"].startswith("link_")
                for command in block["commands"]
            ]
            self.assertTrue(
                any(c == " mtu 9100" for c in link_commands),
                "mtu 9100 missing from fabric-link block",
            )
            # default mtu_headroom=50 → ip mtu 9050
            self.assertTrue(
                any(c == " ip mtu 9050" for c in link_commands),
                "ip mtu 9050 missing from fabric-link block",
            )

    def test_fabric_link_ip_mtu_uses_configured_mtu_headroom(self):
        candidate = copy.deepcopy(self.intent)
        candidate["fabric"]["mtu_headroom"] = 100
        artifact = render_configuration(candidate, create_plan(candidate))
        for device_data in artifact["devices"].values():
            link_commands = [
                command
                for phase in device_data["phases"]
                for block in phase["blocks"]
                if block["block_id"].startswith("link_")
                for command in block["commands"]
            ]
            self.assertIn(" ip mtu 9000", link_commands)
            self.assertNotIn(" ip mtu 9050", link_commands)

    def test_system_mtu_command_is_unchanged(self):
        artifact = render_configuration(self.intent, self.plan)
        all_commands = [
            command
            for device_data in artifact["devices"].values()
            for phase in device_data["phases"]
            for block in phase["blocks"]
            for command in block["commands"]
        ]
        self.assertIn("system mtu 9100", all_commands)


if __name__ == "__main__":
    unittest.main()
