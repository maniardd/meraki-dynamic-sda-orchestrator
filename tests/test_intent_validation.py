from __future__ import annotations

import copy
import unittest
from pathlib import Path

from orchestrator.intent import load_intent, validate_intent


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"
PRODUCTION_EXAMPLE = ROOT / "examples" / "fabric-intent.production.yaml"


class FabricIntentValidationTests(unittest.TestCase):
    def setUp(self):
        self.intent = load_intent(EXAMPLE)

    def codes(self, result):
        return {issue.code for issue in result.issues}

    def test_sanitized_lab_example_is_valid(self):
        result = validate_intent(self.intent)
        self.assertTrue(result.is_valid, result.as_dict())
        self.assertIn("ha.control_plane.single", self.codes(result))
        self.assertIn("ha.border.single", self.codes(result))

    def test_duplicate_loopback_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["devices"][1]["loopback0_ip"] = candidate["devices"][0]["loopback0_ip"]
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("unique.duplicate", self.codes(result))

    def test_unknown_link_device_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["links"][0]["endpoints"][1]["device_id"] = "missing-device"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("reference.device", self.codes(result))

    def test_overlapping_endpoint_pool_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["endpoint_pools"][1]["prefix"] = "10.30.100.128/25"
        candidate["endpoint_pools"][1]["gateway"] = "10.30.100.129"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("address.overlap", self.codes(result))

    def test_production_requires_redundant_border_and_control_plane(self):
        candidate = copy.deepcopy(self.intent)
        candidate["metadata"]["environment"] = "production"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("ha.control_plane", self.codes(result))
        self.assertIn("ha.border", self.codes(result))

    def test_inline_secret_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["lisp"]["auth_key"] = "not-allowed"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("security.inline_secret", self.codes(result))

    def test_gateway_outside_pool_is_rejected(self):
        candidate = copy.deepcopy(self.intent)
        candidate["endpoint_pools"][0]["gateway"] = "10.31.100.1"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("pool.gateway.outside_prefix", self.codes(result))

    def test_redundant_production_reference_with_bgp_is_valid(self):
        result = validate_intent(load_intent(PRODUCTION_EXAMPLE))
        self.assertTrue(result.is_valid, result.as_dict())

    def test_production_requires_bgp_handoff(self):
        candidate = load_intent(PRODUCTION_EXAMPLE)
        candidate["border_handoff"]["enabled"] = False
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.handoff.required", self.codes(result))

    def test_bgp_neighbor_must_be_inside_handoff_prefix(self):
        candidate = load_intent(PRODUCTION_EXAMPLE)
        candidate["border_handoff"]["peers"][0]["neighbor_ip"] = "203.0.113.1"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.neighbor_ip.outside_prefix", self.codes(result))

    def test_explicit_isolated_mode_is_valid_for_lab(self):
        candidate = copy.deepcopy(self.intent)
        candidate["border_handoff"] = {"mode": "isolated", "enabled": False}
        result = validate_intent(candidate)
        self.assertTrue(result.is_valid, result.as_dict())
        self.assertIn("bgp.handoff.isolated", self.codes(result))

    def test_execution_and_dashboard_management_ips_are_separate(self):
        candidate = copy.deepcopy(self.intent)
        candidate["devices"][0]["management_ip"] = "198.51.100.10"
        candidate["devices"][0]["dashboard_management_ip"] = "192.0.2.10"
        result = validate_intent(candidate)
        self.assertTrue(result.is_valid, result.as_dict())

    def test_unknown_structural_field_is_rejected_by_schema(self):
        candidate = copy.deepcopy(self.intent)
        candidate["devices"][0]["unreviewed_transport"] = "telnet"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("schema.additionalProperties", self.codes(result))


if __name__ == "__main__":
    unittest.main()
