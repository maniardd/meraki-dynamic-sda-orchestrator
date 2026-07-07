from __future__ import annotations

import copy
import ipaddress
import json
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.intent import validate_intent


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS_PATH = ROOT / "examples" / "fabric-requirements.cop29-sanitized.yaml"
POLICY_PATH = ROOT / "policy" / "guardrails.cop29-sanitized.yaml"
API_BODY_LIMIT = 1024 * 1024


class COP29ScaleAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = yaml.safe_load(REQUIREMENTS_PATH.read_text(encoding="utf-8"))
        cls.policy = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))

    def derive(self):
        return derive_fabric_intent(self.requirements, self.policy)

    def test_large_campus_fixture_is_deterministic_and_valid(self):
        first = self.derive()
        second = self.derive()
        self.assertEqual(first, second)
        result = validate_intent(first["intent"])
        self.assertTrue(result.is_valid, result.as_dict())

    def test_large_campus_shape_exercises_ha_scale_and_zones(self):
        intent = self.derive()["intent"]
        role_sets = [set(item["roles"]) for item in intent["devices"]]
        self.assertEqual(
            2, sum({"border", "control_plane"}.issubset(item) for item in role_sets)
        )
        self.assertEqual(4, sum("fabric_edge" in item for item in role_sets))
        self.assertEqual(8, len(intent["links"]))
        self.assertEqual(6, len(intent["virtual_networks"]))
        self.assertEqual(4, len(intent["fabric_zones"]))
        self.assertEqual("large_site", intent["fabric_sites"][0]["profile"])

        uplinks = {"edge-01": 0, "edge-02": 0, "edge-03": 0, "edge-04": 0}
        for link in intent["links"]:
            for endpoint in link["endpoints"]:
                if endpoint["device_id"] in uplinks:
                    uplinks[endpoint["device_id"]] += 1
        self.assertEqual(
            {"edge-01": 2, "edge-02": 2, "edge-03": 2, "edge-04": 2}, uplinks
        )

    def test_bgp_handoff_uses_unique_usable_30_addresses(self):
        handoff = self.derive()["intent"]["border_handoff"]
        self.assertEqual(12, len(handoff["peers"]))
        self.assertEqual(12, len({item["prefix"] for item in handoff["peers"]}))
        self.assertEqual(12, len({item["vlan_id"] for item in handoff["peers"]}))
        for peer in handoff["peers"]:
            prefix = ipaddress.ip_network(peer["prefix"])
            self.assertEqual(30, prefix.prefixlen)
            self.assertEqual(
                {
                    ipaddress.ip_address(peer["local_ip"]),
                    ipaddress.ip_address(peer["neighbor_ip"]),
                },
                set(prefix.hosts()),
            )

    def test_fixture_stays_below_current_api_body_limit(self):
        body = json.dumps(
            {"requirements": self.requirements, "policy": self.policy},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLess(len(body), API_BODY_LIMIT)
        self.assertLess(len(body), API_BODY_LIMIT // 4)

    def test_fixture_uses_only_synthetic_management_planes(self):
        execution = ipaddress.ip_network("192.0.2.0/24")
        dashboard = ipaddress.ip_network("198.51.100.0/24")
        for device in self.requirements["devices"]:
            self.assertIn(ipaddress.ip_address(device["management_ip"]), execution)
            self.assertIn(
                ipaddress.ip_address(device["dashboard_management_ip"]), dashboard
            )
            self.assertTrue(
                device["credential_ref"].startswith("secret://acceptance/")
            )

    def test_cop29_derived_gateway_quality_failure_is_rejected(self):
        candidate = copy.deepcopy(self.derive()["intent"])
        candidate["endpoint_pools"][0]["gateway"] = "203.0.113.254"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn(
            "pool.gateway.outside_prefix", {item.code for item in result.issues}
        )


if __name__ == "__main__":
    unittest.main()
