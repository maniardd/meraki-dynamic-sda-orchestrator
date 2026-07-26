from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepairPocIngressTests(unittest.TestCase):
    def test_repair_is_local_api_only_and_has_rollback(self):
        source = (ROOT / "tools/repair_poc_ingress.py").read_text(encoding="utf-8")
        self.assertIn('AGENT_API = "http://127.0.0.1:4040/api"', source)
        self.assertIn('LOCAL_HEALTH = "http://127.0.0.1:8080/health"', source)
        self.assertIn('EXPECTED_UPSTREAM = "http://localhost:8080"', source)
        self.assertIn("rollback_attempted = True", source)
        self.assertIn("execution_enabled\": False", source)
        self.assertNotIn("systemctl", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("authtoken", source)

    def test_workflow_requires_exact_confirmation_and_has_no_device_path(self):
        workflow = (ROOT / ".github/workflows/repair_poc_ingress.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("REPOINT_POC_TO_8080", workflow)
        self.assertIn("contents: read", workflow)
        self.assertIn("runs-on: [self-hosted, sda-relay]", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("ssh", workflow.lower())
        self.assertNotIn("systemctl", workflow)


if __name__ == "__main__":
    unittest.main()
