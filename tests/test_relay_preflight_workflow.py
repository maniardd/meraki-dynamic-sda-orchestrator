from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "relay_preflight.yml"


class RelayPreflightWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")
        self.document = yaml.safe_load(self.text)

    def test_is_manual_and_read_only(self):
        triggers = self.document.get("on", self.document.get(True, {}))
        self.assertEqual({"workflow_dispatch": None}, triggers)
        self.assertEqual({"contents": "read"}, self.document["permissions"])

    def test_cannot_checkout_or_mutate_the_host(self):
        lowered = self.text.lower()
        for forbidden in (
            "actions/checkout",
            "sudo ",
            "rm -",
            "pkill",
            "systemctl start",
            "systemctl restart",
            "systemctl enable",
            "netmiko",
            "send_config",
            "/api/v3/deploy",
        ):
            self.assertNotIn(forbidden, lowered)

    def test_does_not_dump_environment_or_credentials(self):
        lowered = self.text.lower()
        for forbidden in ("printenv", " env ", ".env", "password", "api_key", "token"):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
