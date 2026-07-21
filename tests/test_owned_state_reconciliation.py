from __future__ import annotations

import copy
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.parsers import verify_config_lines_absent
from orchestrator.planner import create_plan
from orchestrator.reconciliation import (
    ReconciliationError,
    build_multicast_owned_state,
    build_multicast_reconciliation,
    make_baseline,
)
from orchestrator.renderer import render_configuration
from orchestrator.store import sha256_json


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "examples" / "fabric-requirements.cop29-sanitized.yaml"
GUARDRAILS = ROOT / "policy" / "guardrails.cop29-sanitized.yaml"


class OwnedStateReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requirements = yaml.safe_load(REQUIREMENTS.read_text(encoding="utf-8"))
        cls.guardrails = yaml.safe_load(GUARDRAILS.read_text(encoding="utf-8"))
        cls.intent = derive_fabric_intent(cls.requirements, cls.guardrails)["intent"]

    def baseline(self):
        manifest = build_multicast_owned_state(self.intent)
        return make_baseline(
            manifest,
            "successful_apply",
            "run_previous_success",
            "a" * 64,
        )

    def disabled_intent(self):
        disabled = copy.deepcopy(self.intent)
        disabled["fabric"]["multicast"].update(
            {"enabled": False, "transport": "native"}
        )
        disabled["fabric"]["multicast"].pop("rp_address", None)
        disabled["fabric"]["multicast"].pop("rp_device_ids", None)
        disabled["multicast"] = {
            "enabled": False,
            "transport": "native",
            "rp_mode": "none",
            "asm_virtual_networks": [],
            "ssm_virtual_networks": [],
            "ssm_range": "232.0.0.0/8",
            "overlay_policies": [],
            "l2_bum_groups": [],
        }
        return disabled

    def flipped_intent(self):
        requirements = copy.deepcopy(self.requirements)
        multicast = requirements["multicast"]
        multicast["asm_virtual_networks"] = ["IoT"]
        multicast["ssm_virtual_networks"] = ["Media"]
        for policy in multicast["overlay_policies"]:
            if policy["virtual_network"] == "Media":
                policy["mode"] = "ssm"
                policy["group_range"] = "232.64.0.0/10"
                policy.pop("rp_address", None)
                policy.pop("rp_prefix", None)
            elif policy["virtual_network"] == "IoT":
                policy.update(
                    {
                        "mode": "asm",
                        "group_range": "239.129.0.0/16",
                        "rp_address": "203.0.113.30",
                        "rp_prefix": "203.0.113.0/26",
                    }
                )
        return derive_fabric_intent(requirements, self.guardrails)["intent"]

    def test_identical_candidate_has_no_prune_delta(self):
        plan = create_plan(self.intent, self.baseline())
        artifact = render_configuration(self.intent, plan)
        self.assertEqual("ready", artifact["reconciliation"]["status"])
        self.assertEqual(0, artifact["reconciliation"]["stale_resource_count"])
        self.assertNotIn(
            "multicast.reconciliation_baseline_missing",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        self.assertNotIn(
            "multicast.reconciliation_hardware_acceptance_pending",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        self.assertNotIn(
            "multicast_reconciliation", [item["id"] for item in plan["phases"]]
        )

    def test_removal_prunes_only_resources_in_prior_manifest(self):
        disabled = self.disabled_intent()
        plan = create_plan(disabled, self.baseline())
        artifact = render_configuration(disabled, plan)
        reconciliation = artifact["reconciliation"]
        previous_count = sum(
            len(item["resources"])
            for item in self.baseline()["manifest"]["devices"].values()
        )
        self.assertEqual(previous_count, reconciliation["stale_resource_count"])
        self.assertEqual({}, artifact["owned_state"]["devices"])
        phase = next(
            item for item in plan["phases"] if item["id"] == "multicast_reconciliation"
        )
        self.assertEqual(sorted(reconciliation["devices"]), phase["targets"])
        self.assertEqual(
            ["checkpoint"], phase["depends_on"]
        )
        underlay = next(item for item in plan["phases"] if item["id"] == "underlay")
        self.assertEqual(["multicast_reconciliation"], underlay["depends_on"])
        self.assertIn(
            "multicast.reconciliation_hardware_acceptance_pending",
            {item["code"] for item in artifact["blocking_requirements"]},
        )
        all_blocks = [
            block
            for device in reconciliation["devices"].values()
            for block in device["blocks"]
        ]
        self.assertTrue(all(block["owned_resource_key"] for block in all_blocks))
        self.assertTrue(
            all(
                any(command.lstrip().startswith("no ") for command in block["commands"])
                for block in all_blocks
            )
        )

    def test_asm_ssm_flip_removes_old_acl_and_policy_before_new_state(self):
        flipped = self.flipped_intent()
        old_manifest = self.baseline()["manifest"]
        plan = create_plan(flipped, self.baseline())
        artifact = render_configuration(flipped, plan)
        stale_keys = {
            block["owned_resource_key"]
            for device in artifact["reconciliation"]["devices"].values()
            for block in device["blocks"]
        }
        self.assertTrue(any(key.startswith("multicast.overlay.acl:") for key in stale_keys))
        self.assertTrue(
            any(key.startswith("multicast.overlay.policy:") for key in stale_keys)
        )
        old_acl_names = {
            line.split()[-1]
            for device in old_manifest["devices"].values()
            for resource in device["resources"]
            if resource["kind"] == "overlay_acl"
            for line in resource["remove_commands"]
        }
        prune_commands = {
            command
            for device in artifact["reconciliation"]["devices"].values()
            for block in device["blocks"]
            for command in block["commands"]
        }
        self.assertTrue(
            all(
                "no ip access-list standard {}".format(name) in prune_commands
                for name in old_acl_names
            )
        )

    def test_missing_baseline_never_infers_ownership_from_candidate(self):
        plan = create_plan(self.intent)
        artifact = render_configuration(self.intent, plan)
        self.assertEqual("baseline_missing", artifact["reconciliation"]["status"])
        self.assertEqual({}, artifact["reconciliation"]["devices"])
        self.assertIn(
            "multicast.reconciliation_baseline_missing",
            {item["code"] for item in artifact["blocking_requirements"]},
        )

    def test_tampered_baseline_cannot_inject_an_arbitrary_command(self):
        baseline = copy.deepcopy(self.baseline())
        resource = next(
            item
            for device in baseline["manifest"]["devices"].values()
            for item in device["resources"]
        )
        resource["remove_commands"] = ["reload"]
        resource["remove_command_hash"] = sha256_json(["reload"])
        state = {
            "configured_lines": resource["configured_lines"],
            "remove_commands": resource["remove_commands"],
            "gate_command": resource["gate_command"],
            "forbidden_lines": resource["forbidden_lines"],
        }
        resource["state_hash"] = sha256_json(state)
        manifest_body = dict(baseline["manifest"])
        manifest_body.pop("manifest_hash")
        baseline["manifest"]["manifest_hash"] = sha256_json(manifest_body)
        baseline["manifest_hash"] = baseline["manifest"]["manifest_hash"]
        baseline_body = dict(baseline)
        baseline_body.pop("baseline_hash")
        baseline["baseline_hash"] = sha256_json(baseline_body)
        with self.assertRaisesRegex(ReconciliationError, "Unsupported.*reload"):
            build_multicast_reconciliation(
                baseline, build_multicast_owned_state(self.intent)
            )

    def test_retired_device_baseline_requires_every_consumed_descriptor_field(self):
        current = build_multicast_owned_state(self.disabled_intent())
        for missing_field in (
            "hostname",
            "platform",
            "software_version",
            "management_ip",
            "credential_ref",
        ):
            with self.subTest(missing_field=missing_field):
                baseline = copy.deepcopy(self.baseline())
                first_device = next(
                    iter(baseline["manifest"]["devices"].values())
                )
                first_device["device"].pop(missing_field)
                manifest_body = dict(baseline["manifest"])
                manifest_body.pop("manifest_hash")
                baseline["manifest"]["manifest_hash"] = sha256_json(
                    manifest_body
                )
                baseline["manifest_hash"] = baseline["manifest"][
                    "manifest_hash"
                ]
                baseline_body = dict(baseline)
                baseline_body.pop("baseline_hash")
                baseline["baseline_hash"] = sha256_json(baseline_body)
                with self.assertRaisesRegex(
                    ReconciliationError, "missing required fields"
                ):
                    build_multicast_reconciliation(baseline, current)

    def test_absence_parser_fails_on_exact_stale_line_only(self):
        forbidden = ["ip pim vrf MEDIA_VN ssm range SDA-MCAST-OLD"]
        self.assertTrue(verify_config_lines_absent("ip routing", forbidden).passed)
        result = verify_config_lines_absent(
            "ip pim vrf MEDIA_VN ssm range SDA-MCAST-OLD", forbidden
        )
        self.assertFalse(result.passed)
        self.assertEqual(forbidden, result.observations["present_lines"])


if __name__ == "__main__":
    unittest.main()
