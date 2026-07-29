from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from orchestrator.poc_intake import PocIntakeError, sjc23_poc_requirements


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


class PocIntakeTests(unittest.TestCase):
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
