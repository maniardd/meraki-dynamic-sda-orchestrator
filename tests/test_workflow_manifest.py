from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "workflows" / "production_workflow_manifest.yaml"


class WorkflowManifestTests(unittest.TestCase):
    def setUp(self):
        self.manifest = yaml.safe_load(MANIFEST.read_text(encoding="utf-8"))

    def test_apply_workflow_is_disabled_during_development(self):
        workflows = {item["name"]: item for item in self.manifest["workflows"]}
        self.assertFalse(workflows["SDA Fabric - Start Apply"]["enabled"])
        self.assertFalse(self.manifest["package"]["exchange_publishable"])

    def test_target_roles_are_separated(self):
        roles = [item["role"] for item in self.manifest["targets"]]
        self.assertEqual(len(roles), len(set(roles)))
        self.assertEqual({"planner", "approver", "operator", "auditor"}, set(roles))

    def test_operations_use_versioned_api_and_known_roles(self):
        roles = {item["role"] for item in self.manifest["targets"]}
        for operation in self.manifest["api_operations"]:
            self.assertTrue(operation["path"].startswith("/v1/"))
            self.assertIn(operation["role"], roles)

    def test_manifest_has_no_inline_transport_or_secret_values(self):
        rendered = MANIFEST.read_text(encoding="utf-8").lower()
        self.assertNotIn("ngrok", rendered)
        self.assertNotIn("verify=false", rendered)
        self.assertNotIn("api_key:", rendered)


if __name__ == "__main__":
    unittest.main()
