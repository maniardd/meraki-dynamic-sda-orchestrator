from __future__ import annotations

import unittest

from orchestrator.workflow_audit import audit_workflow_export


class WorkflowAuditTests(unittest.TestCase):
    def test_unsafe_poc_export_is_not_misclassified_as_production_ready(self):
        document = {
            "workflow": {
                "properties": {
                    "description": "Synthetic unsafe workflow fixture",
                    "target": {"no_target": True},
                },
                "variables": [],
                "actions": [
                    {
                        "type": "python3.script",
                        "properties": {
                            "script": (
                                "requests.post('https://relay.example.invalid/api/v2/apply', "
                                "verify=False)"
                            )
                        },
                    }
                ],
            }
        }
        result = audit_workflow_export(document)
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["production_ready"])
        self.assertIn("transport.tls_verification_disabled", codes)
        self.assertIn("api.legacy_v2", codes)
        self.assertIn("transport.unauthenticated_request", codes)
        self.assertIn("target.missing", codes)
        self.assertIn("control.approval.missing", codes)
        self.assertIn("control.idempotency.missing", codes)


if __name__ == "__main__":
    unittest.main()
