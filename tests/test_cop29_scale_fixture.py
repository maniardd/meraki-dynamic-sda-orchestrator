from __future__ import annotations

import copy
import ipaddress
import json
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import AllocationError, derive_fabric_intent
from orchestrator.gates import build_gate_plan
from orchestrator.intent import validate_intent
from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration


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
        self.assertEqual(24, len(handoff["peers"]))
        self.assertEqual(24, len({item["prefix"] for item in handoff["peers"]}))
        self.assertEqual(24, len({item["vlan_id"] for item in handoff["peers"]}))
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

    def test_full_border_fusion_matrix_and_pubsub_roles_are_derived(self):
        intent = self.derive()["intent"]
        peers = intent["border_handoff"]["peers"]
        adjacency_pairs = {
            (item["device_id"], item["fusion_node_id"]) for item in peers
        }
        self.assertEqual(
            {
                ("border-cp-01", "fusion-01"),
                ("border-cp-01", "fusion-02"),
                ("border-cp-02", "fusion-01"),
                ("border-cp-02", "fusion-02"),
            },
            adjacency_pairs,
        )
        self.assertEqual(
            ["border-cp-01", "border-cp-02"], intent["lisp"]["subscribers"]
        )
        self.assertEqual(
            ["border-cp-01", "border-cp-02"], intent["lisp"]["publishers"]
        )
        self.assertEqual("lisp_pubsub", intent["lisp"]["control_plane_mode"])

    def test_shared_services_multicast_and_policy_are_fully_derived(self):
        result = self.derive()
        intent = result["intent"]
        shared = intent["shared_services"]
        self.assertEqual("deny", shared["default_action"])
        self.assertEqual(5, len(shared["route_leaks"]))
        self.assertEqual(2, len(shared["attachments"]))
        self.assertEqual(
            [3901, 3902], [item["vlan_id"] for item in shared["attachments"]]
        )
        self.assertTrue(
            all(item["prefix"].endswith("/30") for item in shared["attachments"])
        )
        self.assertTrue(
            all(item["import_prefixes"] == ["203.0.113.0/26"] for item in shared["route_leaks"])
        )

        multicast = intent["multicast"]
        self.assertEqual("native", multicast["transport"])
        self.assertEqual(["Media"], multicast["asm_virtual_networks"])
        self.assertEqual(["IoT"], multicast["ssm_virtual_networks"])
        self.assertEqual("10.242.0.0", multicast["rp_address"])

        policy = intent["policy_plane"]
        self.assertEqual("hybrid", policy["mode"])
        tags = [item["tag"] for item in policy["security_groups"]]
        self.assertEqual([1000, 1001, 1002, 1003], tags)
        self.assertEqual(len(tags), len(set(tags)))
        self.assertEqual(2, len(policy["sxp"]["connections"]))
        sgt_reservations = [
            item
            for item in result["reservations"]["scalar"]
            if item["resource_type"] == "sgt"
        ]
        self.assertEqual(4, len(sgt_reservations))

    def test_missing_fusion_mesh_adjacency_fails_closed(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["border_handoff"]["adjacencies"].pop()
        with self.assertRaisesRegex(AllocationError, "full mesh is missing adjacency"):
            derive_fabric_intent(candidate, self.policy)

    def test_narrowed_vn_list_cannot_single_home_a_production_vrf(self):
        candidate = copy.deepcopy(self.requirements)
        adjacency = next(
            item
            for item in candidate["border_handoff"]["adjacencies"]
            if item["border_device_id"] == "border-cp-01"
            and item["fusion_node_id"] == "fusion-02"
        )
        adjacency["virtual_networks"] = [
            item["name"]
            for item in candidate["virtual_networks"]
            if item["name"] != "Media"
        ]
        with self.assertRaisesRegex(
            AllocationError, "requires 2 nodes for border border-cp-01 virtual network Media"
        ):
            derive_fabric_intent(candidate, self.policy)

    def test_native_multicast_requires_pim_on_every_fabric_link(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["links"][0]["pim_sparse_mode"] = False
        with self.assertRaisesRegex(AllocationError, "requires PIM sparse mode"):
            derive_fabric_intent(candidate, self.policy)

    def test_shared_service_address_must_be_inside_advertised_prefix(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["shared_services"]["services"][0]["addresses"] = ["203.0.113.200"]
        with self.assertRaisesRegex(AllocationError, "outside its advertised prefixes"):
            derive_fabric_intent(candidate, self.policy)

    def test_every_production_fusion_requires_shared_service_attachment(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["shared_services"]["attachments"] = [
            item
            for item in candidate["shared_services"]["attachments"]
            if item["fusion_node_id"] != "fusion-02"
        ]
        with self.assertRaisesRegex(
            AllocationError, "missing attachment for fusion node fusion-02"
        ):
            derive_fabric_intent(candidate, self.policy)

    def test_shared_service_prefix_cannot_overlap_fabric_endpoint_space(self):
        derived = self.derive()["intent"]
        endpoint_pool = derived["endpoint_pools"][0]
        candidate = copy.deepcopy(self.requirements)
        service = candidate["shared_services"]["services"][0]
        service["prefixes"] = [endpoint_pool["prefix"]]
        service["addresses"] = [endpoint_pool["gateway"]]
        with self.assertRaisesRegex(AllocationError, "overlaps fabric endpoint pool"):
            derive_fabric_intent(candidate, self.policy)

    def test_ssm_range_and_hybrid_sxp_listener_fail_closed(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["multicast"]["ssm_range"] = "239.0.0.0/8"
        with self.assertRaisesRegex(AllocationError, "inside 232.0.0.0/8"):
            derive_fabric_intent(candidate, self.policy)

        candidate = copy.deepcopy(self.requirements)
        candidate["policy_plane"]["sxp"]["connections"][0]["listener_ip"] = "203.0.113.22"
        with self.assertRaisesRegex(AllocationError, "not an approved ISE node"):
            derive_fabric_intent(candidate, self.policy)

    def test_sgt_exhaustion_and_duplicate_contract_fail_closed(self):
        policy = copy.deepcopy(self.policy)
        policy["ranges"]["sgt"] = {"min": 1000, "max": 1002}
        with self.assertRaisesRegex(AllocationError, "Scalar pool sgt is exhausted"):
            derive_fabric_intent(self.requirements, policy)

        candidate = copy.deepcopy(self.requirements)
        candidate["policy_plane"]["contracts"].append(
            copy.deepcopy(candidate["policy_plane"]["contracts"][0])
        )
        with self.assertRaisesRegex(AllocationError, "Duplicate policy contract"):
            derive_fabric_intent(candidate, self.policy)

    def test_intent_validation_rejects_fusion_policy_and_multicast_drift(self):
        candidate = copy.deepcopy(self.derive()["intent"])
        candidate["border_handoff"]["peers"][0]["remote_as"] = 65111
        candidate["multicast"]["ssm_virtual_networks"] = ["IoT", "Media"]
        candidate["policy_plane"]["security_groups"][1]["tag"] = candidate[
            "policy_plane"
        ]["security_groups"][0]["tag"]
        result = validate_intent(candidate)
        codes = {item.code for item in result.issues}
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.remote_as.mismatch", codes)
        self.assertIn("multicast.mode_conflict", codes)
        self.assertIn("unique.duplicate", codes)

    def test_intent_validation_rejects_ha_service_ssm_and_sxp_drift(self):
        candidate = copy.deepcopy(self.derive()["intent"])
        candidate["border_handoff"]["peers"] = [
            item
            for item in candidate["border_handoff"]["peers"]
            if not (
                item["device_id"] == "border-cp-01"
                and item["fusion_node_id"] == "fusion-02"
                and item["vrf"] == "MEDIA_VN"
            )
        ]
        service = candidate["shared_services"]["services"][0]
        service["prefixes"] = [candidate["endpoint_pools"][0]["prefix"]]
        service["addresses"] = [candidate["endpoint_pools"][0]["gateway"]]
        candidate["multicast"]["ssm_range"] = "239.0.0.0/8"
        candidate["policy_plane"]["sxp"]["connections"][0]["listener_ip"] = "203.0.113.22"
        result = validate_intent(candidate)
        codes = {item.code for item in result.issues}
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.border_vrf.insufficient_fusion_redundancy", codes)
        self.assertIn("shared_service.prefix.overlap", codes)
        self.assertIn("multicast.ssm_range", codes)
        self.assertIn("reference.sxp_listener", codes)

    def test_intent_validation_rejects_missing_fusion_and_border_vrf_peers(self):
        candidate = copy.deepcopy(self.derive()["intent"])
        candidate["border_handoff"]["peers"] = [
            item
            for item in candidate["border_handoff"]["peers"]
            if item["fusion_node_id"] != "fusion-02"
            and not (item["device_id"] == "border-cp-01" and item["vrf"] == "MEDIA_VN")
        ]
        result = validate_intent(candidate)
        codes = {item.code for item in result.issues}
        self.assertFalse(result.is_valid)
        self.assertIn("bgp.fusion_without_peer", codes)
        self.assertIn("bgp.border_vrf_without_peer", codes)

    def test_intent_validation_rejects_asm_without_rp(self):
        candidate = copy.deepcopy(self.derive()["intent"])
        candidate["multicast"]["rp_mode"] = "none"
        candidate["multicast"].pop("rp_address")
        result = validate_intent(candidate)
        self.assertFalse(result.is_valid)
        self.assertIn(
            "multicast.asm.rp_required", {item.code for item in result.issues}
        )

    def test_plan_targets_fusion_services_multicast_and_policy_phases(self):
        intent = self.derive()["intent"]
        plan = create_plan(intent)
        phases = {item["id"]: item for item in plan["phases"]}
        self.assertEqual(
            ["border-cp-01", "border-cp-02", "fusion-01", "fusion-02"],
            phases["border_handoff"]["targets"],
        )
        self.assertEqual(["fusion-01", "fusion-02"], phases["shared_services"]["targets"])
        self.assertEqual(["multicast"], phases["border_handoff"]["depends_on"])
        self.assertEqual(["policy_plane"], phases["endpoint_assurance"]["depends_on"])
        self.assertIn("fusion-01", plan["targets"])

    def test_renderer_includes_fusion_artifacts_but_blocks_unaccepted_features(self):
        intent = self.derive()["intent"]
        plan = create_plan(intent)
        artifacts = render_configuration(intent, plan)
        self.assertIn("fusion-01", artifacts["devices"])
        fusion_blocks = artifacts["devices"]["fusion-01"]["phases"][0]["blocks"]
        commands = "\n".join(
            command for block in fusion_blocks for command in block["commands"]
        )
        self.assertIn("router bgp 65010", commands)
        self.assertIn("switchport mode trunk", commands)
        blocker_codes = {item["code"] for item in artifacts["blocking_requirements"]}
        self.assertEqual(
            {
                "lisp_pubsub.hardware_acceptance_pending",
                "shared_services.hardware_acceptance_pending",
                "multicast.overlay_renderer_pending",
                "policy_plane.renderer_pending",
            },
            blocker_codes,
        )
        self.assertFalse(artifacts["executable"])
        self.assertEqual("1.0", artifacts["artifact_schema_version"])
        self.assertEqual("1.2", artifacts["intent_schema_version"])

    def test_pubsub_subscriber_renderer_and_gates_cover_every_publisher_and_vn(self):
        intent = self.derive()["intent"]
        artifacts = render_configuration(intent, create_plan(intent))
        devices = {item["id"]: item for item in intent["devices"]}
        publisher_addresses = sorted(
            devices[item]["loopback0_ip"] for item in intent["lisp"]["publishers"]
        )
        for subscriber_id in intent["lisp"]["subscribers"]:
            phase = next(
                item
                for item in artifacts["devices"][subscriber_id]["phases"]
                if item["phase_id"] == "overlay"
            )
            block = next(
                item
                for item in phase["blocks"]
                if item["block_id"] == "lisp_pubsub_subscriber"
            )
            commands = "\n".join(block["commands"])
            self.assertIn("map-cache publications", commands)
            self.assertIn("route-export publications", commands)
            self.assertIn("distance publications 250", commands)
            self.assertIn("no map-cache away-eids send-map-request", commands)
            self.assertIn(
                "proxy-itr {}".format(devices[subscriber_id]["loopback0_ip"]),
                commands,
            )
            for address in publisher_addresses:
                self.assertIn(
                    "import publication publisher {}".format(address), commands
                )
                self.assertIn("itr map-resolver {}".format(address), commands)
                self.assertIn(
                    "etr map-server {} key <secret:{}>".format(
                        address, intent["lisp"]["auth_key_ref"]
                    ),
                    commands,
                )
            self.assertEqual([intent["lisp"]["auth_key_ref"]], block["secret_refs"])

        pubsub_gates = [
            gate
            for gate in build_gate_plan(intent)
            if gate["evaluator"] == "lisp_publishers"
        ]
        self.assertEqual(
            len(intent["lisp"]["subscribers"])
            * len(intent["virtual_networks"]),
            len(pubsub_gates),
        )
        self.assertTrue(
            all(
                gate["expected"]["publishers"] == publisher_addresses
                for gate in pubsub_gates
            )
        )
        self.assertTrue(all(gate["phase_id"] == "overlay" for gate in pubsub_gates))

    def test_shared_service_renderer_is_exact_deny_by_default_and_deterministic(self):
        intent = self.derive()["intent"]
        plan = create_plan(intent)
        first = render_configuration(intent, plan)
        second = render_configuration(intent, plan)
        self.assertEqual(first, second)
        phase = next(
            item
            for item in first["devices"]["fusion-01"]["phases"]
            if item["phase_id"] == "shared_services"
        )
        commands = "\n".join(
            command for block in phase["blocks"] for command in block["commands"]
        )
        self.assertIn("ip route vrf SHARED_VN 203.0.113.0 255.255.255.192", commands)
        self.assertIn("export map SDA-RMAP-", commands)
        self.assertIn("import map SDA-RMAP-", commands)
        self.assertIn("no ip prefix-list SDA-PFX-", commands)
        self.assertIn("no route-map SDA-RMAP-", commands)
        self.assertNotIn("permit 0.0.0.0/0", commands)
        self.assertNotIn("10.116.", commands)

    def test_gate_plan_checks_both_sides_of_every_bgp_handoff(self):
        gates = build_gate_plan(self.derive()["intent"])
        by_id = {item["gate_id"]: item for item in gates}
        self.assertEqual(12, len(by_id["border.bgp.border-cp-01"]["expected"]["neighbors"]))
        self.assertEqual(12, len(by_id["fusion.bgp.fusion-01"]["expected"]["neighbors"]))
        self.assertIn("precheck.version.fusion-02", by_id)

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
