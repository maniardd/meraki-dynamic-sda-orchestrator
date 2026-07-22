from __future__ import annotations

import copy
import unittest

from orchestrator.meraki_native_export import (
    audit_native_export,
    audit_native_export_set,
    inventory_native_export,
)


def native_workflow(name="SDA Fabric - Validate and Plan", actions=None):
    return {
        "workflow": {
            "unique_name": "definition_workflow_02TESTNATIVEWORKFLOW",
            "name": name,
            "title": name,
            "type": "generic.workflow",
            "base_type": "workflow",
            "object_type": "definition_workflow",
            "variables": [],
            "properties": {
                "description": "Synthetic tenant-native export",
                "display_name": name,
                "target": {"no_target": False},
            },
            "actions": actions or [],
        }
    }


def native_action(name, activity_type, properties=None):
    return {
        "unique_name": "definition_activity_02TEST{}".format(
            name.replace(" ", "").upper()
        ),
        "name": name,
        "title": name,
        "type": activity_type,
        "base_type": "activity",
        "object_type": "definition_activity",
        "properties": {
            "description": "Synthetic action",
            "display_name": name,
            **(properties or {}),
        },
    }


class MerakiNativeExportTests(unittest.TestCase):
    def test_inventory_contains_structure_but_never_property_values(self):
        document = native_workflow(
            actions=[
                native_action(
                    "HTTP Request",
                    "web_service.http_request",
                    {"relative_url": "/v1/workflow-actions/plan", "token": "secret://ref"},
                )
            ]
        )
        inventory = inventory_native_export(document)
        rendered = str(inventory)
        self.assertEqual(1, inventory["workflow_count"])
        self.assertIn("relative_url", rendered)
        self.assertNotIn("/v1/workflow-actions/plan", rendered)
        self.assertNotIn("secret://ref", rendered)
        self.assertFalse(inventory["contains_property_values"])

    def test_valid_native_http_export_passes(self):
        document = native_workflow(
            actions=[native_action("HTTP Request", "web_service.http_request")]
        )
        result = audit_native_export(document)
        self.assertTrue(result["native_export_valid"], result["issues"])

    def test_python_and_unsafe_transport_markers_fail_closed(self):
        document = native_workflow(
            actions=[
                native_action(
                    "Execute Python Script",
                    "python3.script",
                    {
                        "script": "requests.post('https://demo.ngrok.io/api/v2/run', verify=False)"
                    },
                )
            ]
        )
        result = audit_native_export(document)
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["native_export_valid"])
        self.assertIn("native.python_forbidden", codes)
        self.assertIn("transport.ngrok", codes)
        self.assertIn("api.legacy_v2", codes)
        self.assertIn("transport.tls_verification_disabled", codes)

    def test_inline_secret_fails_but_references_pass(self):
        base = native_workflow(
            actions=[
                native_action(
                    "HTTP Request",
                    "web_service.http_request",
                    {"token": "secret://meraki-account-key"},
                )
            ]
        )
        self.assertTrue(audit_native_export(base)["native_export_valid"])
        candidate = copy.deepcopy(base)
        candidate["workflow"]["actions"][0]["properties"]["token"] = "cleartext-token"
        result = audit_native_export(candidate)
        self.assertFalse(result["native_export_valid"])
        self.assertIn("secret.inline_value", {item["code"] for item in result["issues"]})

    def test_missing_tenant_identifiers_fail_closed(self):
        document = native_workflow(
            actions=[native_action("HTTP Request", "web_service.http_request")]
        )
        document["workflow"]["unique_name"] = "invented"
        document["workflow"]["actions"][0]["unique_name"] = "invented"
        result = audit_native_export(document)
        codes = {item["code"] for item in result["issues"]}
        self.assertIn("native.workflow_identifier", codes)
        self.assertIn("native.activity_identifier", codes)

    def test_export_set_requires_all_workflows_and_native_activities(self):
        documents = [
            native_workflow(
                "SDA Fabric - Validate and Plan",
                [native_action("HTTP Request", "web_service.http_request")],
            ),
            native_workflow(
                "SDA Fabric - Request Approval",
                [
                    native_action("Create Prompt", "task.create_prompt"),
                    native_action("Request Approval", "task.request_approval"),
                ],
            ),
        ]
        result = audit_native_export_set(
            documents,
            expected_workflow_names=(
                "SDA Fabric - Validate and Plan",
                "SDA Fabric - Request Approval",
            ),
            required_activity_names=("HTTP Request", "Create Prompt", "Request Approval"),
        )
        self.assertTrue(result["native_export_set_valid"], result["issues"])

        result = audit_native_export_set(
            documents[:1],
            expected_workflow_names=(
                "SDA Fabric - Validate and Plan",
                "SDA Fabric - Request Approval",
            ),
            required_activity_names=("HTTP Request", "Request Approval"),
        )
        codes = {item["code"] for item in result["issues"]}
        self.assertFalse(result["native_export_set_valid"])
        self.assertIn("package.workflow_missing", codes)
        self.assertIn("package.activity_missing", codes)


if __name__ == "__main__":
    unittest.main()
