from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from orchestrator.poc_intake import PocIntakeError, sjc23_poc_form_options, sjc23_poc_requirements


ROOT = Path(__file__).resolve().parents[1]
POLICY = yaml.safe_load(
    (ROOT / "policy" / "guardrails.sjc23-poc.yaml").read_text(encoding="utf-8")
)
VALID_FORM = {
    "fabric_name": "SJC23 recorded POC",
    "change_reference": "SJC23-POC-001",
    "corporate_users": "150",
    "guest_users": "150",
    "corporate_attachment": "corporate_laptop",
    "guest_attachment": "guest_laptop",
    "dhcp_lease_minutes": "60",
    "dns_profile": "public_google",
}

NATIVE_PROMPT_RESPONSE = {
    "Fabric name": "SJC23 recorded POC",
    "Change reference": "SJC23-POC-001",
    "Corporate users": ["150"],
    "Guest users": ["150"],
    "Corporate attachment": ["corporate_laptop"],
    "Guest attachment": ["guest_laptop"],
    "DHCP lease minutes": ["60"],
    "DNS profile": ["public_google"],
}

NATIVE_PROMPT_TEXT_FALLBACK = {
    "Fabric name": "SJC23 recorded POC",
    "Change reference": "SJC23-POC-001",
    "Corporate users": "150",
    "Guest users": "150",
    "Corporate attachment": "corporate_laptop",
    "Guest attachment": "guest_laptop",
    "DHCP lease minutes": "60",
    "DNS profile": "public_google",
}


class PocIntakeTests(unittest.TestCase):
    def test_native_prompt_options_are_policy_locked_and_demand_only(self):
        options = sjc23_poc_form_options(POLICY)
        self.assertEqual("poc_options_ready", options["status"])
        self.assertEqual(["1", "50", "100", "150", "200"], options["options"]["corporate_users"])
        self.assertEqual(["corporate_laptop"], options["options"]["corporate_attachment"])
        self.assertEqual(["guest_laptop"], options["options"]["guest_attachment"])
        self.assertEqual(["public_google"], options["options"]["dns_profile"])
        self.assertFalse(options["contains_secret_values"])
        self.assertFalse(options["contains_raw_configuration"])
        rendered = str(options)
        self.assertNotIn("10.30.100.0", rendered)
        self.assertNotIn("vlan", rendered.lower())
        with self.assertRaisesRegex(PocIntakeError, "requires the reviewed"):
            sjc23_poc_form_options({"policy_version": "1.0"})

    def test_guided_form_only_changes_approved_demand_fields(self):
        requirements = sjc23_poc_requirements(VALID_FORM, POLICY)
        self.assertEqual("SJC23 recorded POC", requirements["metadata"]["name"])
        self.assertEqual("SJC23-POC-001", requirements["metadata"]["change_reference"])
        virtual_networks = {item["name"]: item for item in requirements["virtual_networks"]}
        self.assertEqual(150, virtual_networks["Corporate"]["sites"][0]["users"])
        self.assertEqual(150, virtual_networks["Guest"]["sites"][0]["users"])
        self.assertEqual(
            ["8.8.8.8", "8.8.4.4"],
            virtual_networks["Corporate"]["sites"][0]["dhcp"]["dns_servers"],
        )
        self.assertEqual(False, requirements["border_handoff"]["enabled"])

    def test_unknown_topology_or_cli_input_fails_closed(self):
        unsafe = dict(VALID_FORM, generated_cli="reload")
        with self.assertRaisesRegex(PocIntakeError, "unsupported fields"):
            sjc23_poc_requirements(unsafe, POLICY)
        with self.assertRaisesRegex(PocIntakeError, "approved Corporate laptop"):
            sjc23_poc_requirements(dict(VALID_FORM, corporate_attachment="Gi1/0/1"), POLICY)
        with self.assertRaisesRegex(PocIntakeError, "requires the reviewed"):
            sjc23_poc_requirements(VALID_FORM, {"policy_version": "1.0"})

    def test_native_meraki_prompt_response_is_normalized_at_the_boundary(self):
        requirements = sjc23_poc_requirements(NATIVE_PROMPT_RESPONSE, POLICY)
        self.assertEqual("SJC23 recorded POC", requirements["fabric"]["name"])
        virtual_networks = {item["name"]: item for item in requirements["virtual_networks"]}
        self.assertEqual(150, virtual_networks["Corporate"]["sites"][0]["users"])

    def test_native_prompt_text_fallback_is_equally_demand_only(self):
        requirements = sjc23_poc_requirements(NATIVE_PROMPT_TEXT_FALLBACK, POLICY)
        self.assertEqual("SJC23 recorded POC", requirements["fabric"]["name"])
        virtual_networks = {item["name"]: item for item in requirements["virtual_networks"]}
        self.assertEqual(150, virtual_networks["Corporate"]["sites"][0]["users"])
        with self.assertRaisesRegex(PocIntakeError, "approved Corporate laptop"):
            sjc23_poc_requirements(
                dict(NATIVE_PROMPT_TEXT_FALLBACK, **{"Corporate attachment": "reload"}), POLICY
            )
        with self.assertRaisesRegex(PocIntakeError, "reviewed text value or one selected value"):
            sjc23_poc_requirements(
                dict(NATIVE_PROMPT_TEXT_FALLBACK, **{"Corporate users": {"value": "150"}}), POLICY
            )

    def test_native_meraki_prompt_response_rejects_multi_select_and_injection(self):
        multi_select = dict(NATIVE_PROMPT_RESPONSE, **{"Corporate users": ["50", "100"]})
        with self.assertRaisesRegex(PocIntakeError, "exactly one selected"):
            sjc23_poc_requirements(multi_select, POLICY)
        unsafe = dict(NATIVE_PROMPT_RESPONSE, generated_cli="reload")
        with self.assertRaisesRegex(PocIntakeError, "unsupported fields"):
            sjc23_poc_requirements(unsafe, POLICY)
