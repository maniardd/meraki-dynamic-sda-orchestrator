from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import AllocationError, derive_fabric_intent
from orchestrator.intent import validate_intent


ROOT = Path(__file__).resolve().parents[1]


class DynamicAllocatorTests(unittest.TestCase):
    def setUp(self):
        self.requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.lab.yaml").read_text(encoding="utf-8")
        )
        self.policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.yaml").read_text(encoding="utf-8")
        )

    def derive(self, requirements=None, policy=None, network=(), scalar=()):
        return derive_fabric_intent(
            requirements or self.requirements,
            policy or self.policy,
            network_ledger=network,
            scalar_ledger=scalar,
        )

    def test_identical_requirements_are_byte_deterministic(self):
        first = self.derive()
        second = self.derive()
        self.assertEqual(first, second)
        self.assertEqual(first["intent_hash"], second["intent_hash"])
        self.assertEqual(first["reservation_hash"], second["reservation_hash"])

    def test_input_order_does_not_change_design(self):
        shuffled = copy.deepcopy(self.requirements)
        shuffled["devices"].reverse()
        shuffled["virtual_networks"].reverse()
        shuffled["virtual_networks"][0]["sites"].reverse()
        first = self.derive()
        second = self.derive(shuffled)
        self.assertEqual(first["intent"], second["intent"])
        self.assertNotEqual(first["requirements_hash"], second["requirements_hash"])

    def test_complete_derived_intent_passes_existing_validator(self):
        result = validate_intent(self.derive()["intent"])
        self.assertTrue(result.is_valid, result.as_dict())

    def test_brownfield_prefixes_are_skipped_without_overlap(self):
        network = [
            {
                "allocation_domain": "example-lab",
                "resource_pool_id": "underlay_p2p",
                "prefix": "10.252.0.0/30",
                "state": "committed",
            },
            {
                "allocation_domain": "example-lab",
                "resource_pool_id": "overlay_hosts",
                "prefix": "10.0.0.0/20",
                "state": "committed",
            },
        ]
        result = self.derive(network=network)
        self.assertEqual("10.252.0.4/31", result["intent"]["links"][0]["subnet"])
        self.assertTrue(
            all(not item["prefix"].startswith("10.0.0.") for item in result["intent"]["endpoint_pools"])
        )

    def test_quarantined_allocation_is_never_reused(self):
        network = [
            {
                "allocation_domain": "example-lab",
                "resource_pool_id": "underlay_p2p",
                "prefix": "10.252.0.0/31",
                "state": "quarantined",
            }
        ]
        self.assertEqual("10.252.0.2/31", self.derive(network=network)["intent"]["links"][0]["subnet"])

    def test_released_allocation_can_be_reused(self):
        network = [
            {
                "allocation_domain": "example-lab",
                "resource_pool_id": "underlay_p2p",
                "prefix": "10.252.0.0/31",
                "state": "released",
            }
        ]
        self.assertEqual("10.252.0.0/31", self.derive(network=network)["intent"]["links"][0]["subnet"])

    def test_scalar_duplicates_are_skipped(self):
        scalar = [
            {
                "allocation_domain": "example-lab",
                "resource_type": "vlan_id",
                "value": "100",
                "state": "committed",
            },
            {
                "allocation_domain": "example-lab",
                "resource_type": "l3_instance_id",
                "value": "4099",
                "state": "reserved",
            },
        ]
        intent = self.derive(scalar=scalar)["intent"]
        self.assertEqual([101, 102], [item["vlan_id"] for item in intent["endpoint_pools"]])
        self.assertEqual([4100, 4101], [item["l3_instance_id"] for item in intent["virtual_networks"]])

    def test_capacity_rounding_includes_headroom(self):
        intent = self.derive()["intent"]
        pools = {item["virtual_network"]: item for item in intent["endpoint_pools"]}
        self.assertEqual("10.0.0.0/22", pools["Corporate"]["prefix"])
        self.assertEqual("10.0.4.0/23", pools["Guest"]["prefix"])

    def test_policy_reserved_prefixes_and_scalar_ranges_are_never_allocated(self):
        policy = copy.deepcopy(self.policy)
        policy["supernets"]["loopbacks"]["reserved"] = ["10.253.0.0/32"]
        policy["ranges"]["vlan_id"]["reserved_ranges"] = [[100, 109]]
        intent = self.derive(policy=policy)["intent"]
        self.assertEqual("10.253.0.1", intent["devices"][0]["loopback0_ip"])
        self.assertEqual([110, 111], [item["vlan_id"] for item in intent["endpoint_pools"]])

    def test_policy_reserved_prefix_must_be_inside_its_pool(self):
        policy = copy.deepcopy(self.policy)
        policy["supernets"]["loopbacks"]["reserved"] = ["192.0.2.1/32"]
        with self.assertRaisesRegex(AllocationError, "outside guardrail pool"):
            self.derive(policy=policy)

    def test_sjc23_golden_profile_regenerates_known_fabric_addressing(self):
        requirements = yaml.safe_load(
            (ROOT / "examples" / "fabric-requirements.sjc23-golden.yaml").read_text(
                encoding="utf-8"
            )
        )
        policy = yaml.safe_load(
            (ROOT / "policy" / "guardrails.sjc23-golden.yaml").read_text(
                encoding="utf-8"
            )
        )
        intent = self.derive(requirements=requirements, policy=policy)["intent"]
        devices = {item["id"]: item for item in intent["devices"]}
        pools = {item["virtual_network"]: item for item in intent["endpoint_pools"]}
        self.assertEqual("10.255.255.1", devices["border-cp-01"]["loopback0_ip"])
        self.assertEqual("10.255.255.2", devices["edge-01"]["loopback0_ip"])
        self.assertEqual("10.255.0.0/31", intent["links"][0]["subnet"])
        self.assertEqual("10.30.100.0/24", pools["Corporate"]["prefix"])
        self.assertEqual("10.30.200.0/24", pools["Guest"]["prefix"])
        self.assertEqual([100, 200], [pools["Corporate"]["vlan_id"], pools["Guest"]["vlan_id"]])

    def test_pool_exhaustion_fails_without_partial_result(self):
        policy = copy.deepcopy(self.policy)
        policy["supernets"]["underlay_p2p"] = {"cidr": "192.0.2.0/31", "prefix_len": 31}
        network = [
            {
                "allocation_domain": "example-lab",
                "resource_pool_id": "underlay_p2p",
                "prefix": "192.0.2.0/31",
                "state": "reserved",
            }
        ]
        with self.assertRaisesRegex(AllocationError, "exhausted"):
            self.derive(policy=policy, network=network)

    def test_unsupported_platform_role_is_rejected(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["devices"][1]["roles"] = ["border"]
        with self.assertRaisesRegex(AllocationError, "does not support"):
            self.derive(candidate)

    def test_unsupported_software_is_rejected(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["devices"][1]["software_version"] = "16.12.9"
        with self.assertRaisesRegex(AllocationError, "requires IOS XE"):
            self.derive(candidate)

    def test_management_planes_are_preserved_separately(self):
        device = self.derive()["intent"]["devices"][0]
        self.assertEqual("192.0.2.10", device["management_ip"])
        self.assertEqual("198.51.100.10", device["dashboard_management_ip"])

    def test_duplicate_device_id_is_rejected(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["devices"][1]["id"] = candidate["devices"][0]["id"]
        with self.assertRaisesRegex(AllocationError, "Duplicate device id"):
            self.derive(candidate)

    def test_production_requires_redundant_roles(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["metadata"]["environment"] = "production"
        with self.assertRaisesRegex(AllocationError, "redundant borders"):
            self.derive(candidate)

    def test_production_bgp_handoffs_are_fully_derived(self):
        candidate = copy.deepcopy(self.requirements)
        candidate["metadata"]["environment"] = "production"
        candidate["devices"].extend(
            [
                {
                    "id": "border-cp-02",
                    "hostname": "BORDER-CP-02",
                    "site": "SITE-001",
                    "platform": "C9500-48Y4C",
                    "software_version": "17.12.4",
                    "management_ip": "192.0.2.11",
                    "dashboard_management_ip": "198.51.100.11",
                    "roles": ["border", "control_plane"],
                    "credential_ref": "secret://example/devices/border-cp-02",
                },
                {
                    "id": "edge-02",
                    "hostname": "EDGE-02",
                    "site": "SITE-001",
                    "platform": "C9300-24P",
                    "software_version": "17.12.4",
                    "management_ip": "192.0.2.21",
                    "dashboard_management_ip": "198.51.100.21",
                    "roles": ["fabric_edge"],
                    "credential_ref": "secret://example/devices/edge-02",
                },
            ]
        )
        candidate["links"].extend(
            [
                {
                    "id": "border-cp-02--edge-01",
                    "endpoints": [
                        {"device_id": "border-cp-02", "interface": "TwentyFiveGigE1/0/1"},
                        {"device_id": "edge-01", "interface": "GigabitEthernet1/0/2"},
                    ],
                },
                {
                    "id": "border-cp-01--edge-02",
                    "endpoints": [
                        {"device_id": "border-cp-01", "interface": "TwentyFiveGigE1/0/2"},
                        {"device_id": "edge-02", "interface": "GigabitEthernet1/0/1"},
                    ],
                },
                {
                    "id": "border-cp-02--edge-02",
                    "endpoints": [
                        {"device_id": "border-cp-02", "interface": "TwentyFiveGigE1/0/2"},
                        {"device_id": "edge-02", "interface": "GigabitEthernet1/0/2"},
                    ],
                },
            ]
        )
        candidate["border_handoff"] = {
            "enabled": True,
            "mode": "bgp",
            "remote_as": 65200,
        }
        result = self.derive(candidate)
        handoff = result["intent"]["border_handoff"]
        self.assertTrue(handoff["enabled"])
        self.assertEqual(4, len(handoff["peers"]))
        self.assertEqual(4, len({item["prefix"] for item in handoff["peers"]}))
        self.assertEqual(4, len({item["vlan_id"] for item in handoff["peers"]}))
        validation = validate_intent(result["intent"])
        self.assertTrue(validation.is_valid, validation.as_dict())


if __name__ == "__main__":
    unittest.main()
