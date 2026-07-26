from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "inspect_meraki_role_identities.py"
WORKFLOW = ROOT / ".github" / "workflows" / "inspect_meraki_role_identities.yml"


class InspectMerakiRoleIdentitiesTests(unittest.TestCase):
    def _identity_file(self, actors: list[str], mode: int = 0o600) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "token-identities.json"
        identities = {
            ("a" * 63) + str(index): {"actor": actor, "roles": ["viewer"]}
            for index, actor in enumerate(actors)
        }
        path.write_text(json.dumps({"version": 1, "identities": identities}), encoding="utf-8")
        os.chmod(path, mode)
        return path

    def test_report_is_structural_only_and_ready_when_all_roles_exist(self):
        path = self._identity_file(
            [
                "meraki-planner",
                "meraki-approver",
                "meraki-operator",
                "meraki-auditor",
            ]
        )
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--identity-file", str(path)],
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(4, report["identity_count"])
        self.assertEqual([], report["missing_meraki_role_actors"])
        self.assertTrue(report["private_file_mode"])
        self.assertTrue(report["ready_for_meraki_targets"])
        self.assertFalse(report["contains_secret_values"])
        self.assertFalse(report["contains_token_digests"])
        self.assertNotIn("a" * 64, completed.stdout)

    def test_missing_role_or_insecure_mode_is_not_ready(self):
        path = self._identity_file(["meraki-planner", "meraki-approver"], 0o640)
        completed = subprocess.run(
            [sys.executable, str(SCRIPT), "--identity-file", str(path)],
            capture_output=True,
            text=True,
        )
        report = json.loads(completed.stdout)
        self.assertEqual(2, completed.returncode)
        self.assertFalse(report["safe"])
        self.assertFalse(report["contains_secret_values"])
        self.assertFalse(report["contains_token_digests"])

    def test_workflow_is_manual_secret_free_and_read_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("runs-on: [self-hosted, sda-relay]", text)
        self.assertIn("inspect_meraki_role_identities.py", text)
        self.assertIn("execution_enabled\"] is False", text)
        self.assertNotIn("create_api_identity.py", text)
        self.assertNotIn("systemctl", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("upload-artifact", text)


if __name__ == "__main__":
    unittest.main()
