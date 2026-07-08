from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.intent import load_intent, validate_intent


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"
PRODUCTION_EXAMPLE = ROOT / "examples" / "fabric-intent.production.yaml"


class FabricIntentValidationTests(unittest.TestCase):
    def setUp(self):
        self.intent = load_intent(EXAMPLE)
        requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.cvd-small.yaml").read_text(
                encoding="utf-8"
            )
        )
        policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.yaml").read_text(encoding="utf-8")
        )
        self.cvd_intent = derive_fabric_intent(requirements, policy)["intent"]

    def codes(self, result):
        return {issue.code for issue in result.issues}

    def test_sanitized_lab_example_is_valid(self):
        result = validate_intent(self.intent)
        self.assertTrue(result.is_valid, result.as_dict())
        self.assertIn("ha.control_plane.single", self.codes(result))
        self.assertIn("ha.border.single", self.codes(result))

    def test_cvd_schema_1_1_hierarchy_is_valid(self):
        result = validate_intent(self.cvd_intent)
        self.assertTrue(result.is_valid, result.as_dict())

    def test_cvd_schema_1_1_unknown_device_site_is_rejected(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["devices"][0]["site"] = "MISSING-SITE"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("reference.fabric_site", self.codes(result))

    def test_cvd_schema_1_1_hierarchy_cycle_is_rejected(self):
        candidate = copy.deepcopy(self.cvd_intent)
        nodes = {item["id"]: item for item in candidate["site_hierarchy"]}
        nodes["AREA-SJC"]["parent_id"] = "BUILDING-23"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("hierarchy.cycle", self.codes(result))

    def test_cvd_schema_1_1_building_directly_under_global_is_valid(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["site_hierarchy"] = [
            item for item in candidate["site_hierarchy"] if item["id"] != "AREA-SJC"
        ]
        nodes = {item["id"]: item for item in candidate["site_hierarchy"]}
        nodes["BUILDING-23"]["parent_id"] = "GLOBAL"
        candidate["fabric_sites"][0]["hierarchy_node_id"] = "BUILDING-23"
        result = validate_intent(candidate)
        self.assertTrue(result.is_valid, result.as_dict())

    def test_cvd_schema_1_1_global_count_and_parent_types_are_enforced(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["site_hierarchy"][0]["type"] = "area"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("hierarchy.global_count", self.codes(result))

        candidate = copy.deepcopy(self.cvd_intent)
        candidate["site_hierarchy"].append(
            {"id": "GLOBAL-2", "name": "Second Global", "type": "global"}
        )
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("hierarchy.global_count", self.codes(result))

        candidate = copy.deepcopy(self.cvd_intent)
        nodes = {item["id"]: item for item in candidate["site_hierarchy"]}
        nodes["FLOOR-1"]["parent_id"] = "AREA-SJC"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("hierarchy.parent_type", self.codes(result))

    def test_cvd_schema_1_1_fabric_site_node_rules_match_allocator(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["fabric_sites"][0]["hierarchy_node_id"] = "GLOBAL"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("site.global_node", self.codes(result))

        candidate = copy.deepcopy(self.cvd_intent)
        duplicate = copy.deepcopy(candidate["fabric_sites"][0])
        duplicate["id"] = "SITE-002"
        candidate["fabric_sites"].append(duplicate)
        candidate["deployment_model"] = "distributed_campus"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("unique.duplicate", self.codes(result))

    def test_cvd_schema_1_1_zone_must_be_inside_site(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["site_hierarchy"].append(
            {"id": "AREA-OTHER", "name": "Other", "type": "area", "parent_id": "GLOBAL"}
        )
        candidate["fabric_zones"][0]["hierarchy_node_id"] = "AREA-OTHER"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("zone.outside_site", self.codes(result))

    def test_cvd_schema_1_1_hierarchy_depth_is_bounded(self):
        candidate = copy.deepcopy(self.cvd_intent)
        hierarchy = [{"id": "GLOBAL", "name": "Global", "type": "global"}]
        parent = "GLOBAL"
        for index in range(1, 18):
            node_id = "AREA-{:02d}".format(index)
            hierarchy.append(
                {"id": node_id, "name": node_id, "type": "area", "parent_id": parent}
            )
            parent = node_id
        candidate["site_hierarchy"] = hierarchy
        candidate["fabric_sites"][0]["hierarchy_node_id"] = parent
        candidate["fabric_zones"] = []
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("hierarchy.too_deep", self.codes(result))

    def test_schema_1_0_rejects_schema_1_1_context_keys(self):
        candidate = copy.deepcopy(self.intent)
        candidate["deployment_model"] = "single_site"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("schema.not", self.codes(result))

    def test_schema_1_0_and_1_1_reject_lisp_pubsub_identity_fields(self):
        for candidate in (self.intent, self.cvd_intent):
            with self.subTest(schema_version=candidate["schema_version"]):
                candidate = copy.deepcopy(candidate)
                candidate["lisp"]["domain_id"] = 424242
                candidate["lisp"]["multihoming_groups"] = []
                result = validate_intent(candidate)
                self.assertFalse(result.is_valid)
                self.assertIn("lisp.identity.unexpected", self.codes(result))

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

    def test_30_handoff_rejects_network_and_broadcast_addresses(self):
        candidate = load_intent(PRODUCTION_EXAMPLE)
        peer = candidate["border_handoff"]["peers"][0]
        peer["prefix"] = "172.31.10.0/30"
        peer["local_ip"] = "172.31.10.0"
        peer["neighbor_ip"] = "172.31.10.3"
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.local_ip.not_usable", self.codes(result))
        self.assertIn("bgp.neighbor_ip.not_usable", self.codes(result))

    def test_duplicate_route_distinguisher_is_rejected(self):
        candidate = copy.deepcopy(self.cvd_intent)
        candidate["virtual_networks"][1]["rd"] = candidate["virtual_networks"][0]["rd"]
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn("unique.duplicate", self.codes(result))

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
