from __future__ import annotations

import copy
import unittest

from orchestrator.meraki_native_export import (
    audit_native_export,
    audit_native_export_set,
    inventory_native_export,
    verify_capture_fingerprint,
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


def structural_fingerprint(document, portable_types, topology):
    inventory = inventory_native_export(document)
    workflow = inventory["workflows"][0]
    variable = workflow["variables"][0]
    actions = {}
    for portable_name, activity_type in portable_types.items():
        action = next(
            item for item in workflow["actions"] if item["type"] == activity_type
        )
        actions[portable_name] = {
            "type": action["type"],
            "base_type": action["base_type"],
            "object_type": action["object_type"],
            "unique_name_prefix": action["unique_name_prefix"],
            "property_keys": action["property_keys"],
        }
    return {
        "source": {
            "export_sha256": inventory["export_sha256"],
            "workflow_name": workflow["name"],
            "raw_export_committed": False,
            "child_workflows_embedded": False,
        },
        "safety": {
            "contains_property_values": False,
            "contains_credentials": False,
            "contains_target_bindings": False,
            "configured_properties_complete": True,
            "workflow_executed": False,
        },
        "export_top_level_keys": inventory["top_level_keys"],
        "workflow": {
            "type": workflow["type"],
            "base_type": workflow["base_type"],
            "object_type": workflow["object_type"],
            "unique_name_prefix": workflow["unique_name_prefix"],
            "top_level_keys": workflow["top_level_keys"],
            "property_keys": workflow["property_keys"],
            "variable": {
                "object_type": variable["object_type"],
                "unique_name_prefix": variable["unique_name_prefix"],
                "wrapper_keys": variable["wrapper_keys"],
                "property_keys": variable["property_keys"],
            },
        },
        "activities": actions,
        "serialization_topology": topology,
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

    def test_inventory_captures_nested_logic_and_child_workflow_structure(self):
        completed = native_action(
            "Completed",
            "logic.completed",
            {"completion_type": "succeeded", "skip_execution": True},
        )
        branch = native_action(
            "Condition Branch",
            "logic.condition_block",
            {"condition": {"operator": "eq"}, "skip_execution": False},
        )
        branch["actions"] = [completed]
        condition = native_action(
            "Condition Block",
            "logic.if_else",
            {"conditions": [], "skip_execution": True},
        )
        condition["blocks"] = [branch]
        child = native_action(
            "Read-only Child",
            "workflow.sub_workflow",
            {
                "input": {"synthetic": "CAPTURE_ONLY"},
                "skip_execution": True,
                "workflow_id": "definition_workflow_02SYNTHETICCHILD",
                "workflow_name": "Read-only Child",
            },
        )
        child["base_type"] = "subworkflow"
        document = native_workflow(actions=[condition, child])

        result = audit_native_export(document)
        self.assertTrue(result["native_export_valid"], result["issues"])
        actions = result["inventory"]["workflows"][0]["actions"]
        self.assertEqual(
            [
                "logic.if_else",
                "logic.condition_block",
                "logic.completed",
                "workflow.sub_workflow",
            ],
            [item["type"] for item in actions],
        )
        rendered = str(result["inventory"])
        self.assertIn("completion_type", rendered)
        self.assertIn("workflow_id", rendered)
        self.assertNotIn("CAPTURE_ONLY", rendered)
        self.assertFalse(result["inventory"]["contains_property_values"])

    def test_configured_capture_fingerprint_verifies_without_exposing_values(self):
        document = native_workflow(
            actions=[
                native_action(
                    "HTTP Request",
                    "web-service.http_request",
                    {
                        "relative_url": "/v1/workflow-actions/plan",
                        "skip_execution": True,
                    },
                )
            ]
        )
        document["dependent_workflows"] = []
        document["workflow"]["variables"] = [
            {
                "unique_name": "variable_workflow_02SYNTHETIC",
                "schema_id": "synthetic",
                "object_type": "variable_workflow",
                "properties": {
                    "description": "Synthetic",
                    "name": "capture",
                    "scope": "local",
                    "type": "string",
                    "value": "must-not-leak",
                },
            }
        ]
        inventory = inventory_native_export(document)
        workflow = inventory["workflows"][0]
        action = workflow["actions"][0]
        variable = workflow["variables"][0]
        fingerprint = {
            "source": {
                "export_sha256": inventory["export_sha256"],
                "workflow_name": workflow["name"],
                "raw_export_committed": False,
                "child_workflows_embedded": False,
            },
            "safety": {
                "contains_property_values": False,
                "contains_credentials": False,
                "contains_target_bindings": False,
                "configured_properties_complete": True,
                "workflow_executed": False,
            },
            "export_top_level_keys": inventory["top_level_keys"],
            "workflow": {
                "type": workflow["type"],
                "base_type": workflow["base_type"],
                "object_type": workflow["object_type"],
                "unique_name_prefix": workflow["unique_name_prefix"],
                "top_level_keys": workflow["top_level_keys"],
                "property_keys": workflow["property_keys"],
                "variable": {
                    "object_type": variable["object_type"],
                    "unique_name_prefix": variable["unique_name_prefix"],
                    "wrapper_keys": variable["wrapper_keys"],
                    "property_keys": variable["property_keys"],
                },
            },
            "activities": {
                "http_request": {
                    "type": action["type"],
                    "base_type": action["base_type"],
                    "object_type": action["object_type"],
                    "unique_name_prefix": action["unique_name_prefix"],
                    "property_keys": action["property_keys"],
                }
            },
            "serialization_topology": {
                "root_action_sequence": ["http_request"]
            },
        }
        result = verify_capture_fingerprint(document, fingerprint)
        self.assertTrue(result["capture_fingerprint_valid"], result["issues"])
        rendered = str(result)
        self.assertNotIn("/v1/workflow-actions/plan", rendered)
        self.assertNotIn("must-not-leak", rendered)

        candidate = copy.deepcopy(fingerprint)
        candidate["activities"]["http_request"]["property_keys"].remove(
            "relative_url"
        )
        result = verify_capture_fingerprint(document, candidate)
        self.assertFalse(result["capture_fingerprint_valid"])
        self.assertIn("capture.activity", {item["code"] for item in result["issues"]})

    def test_capture_fingerprint_rejects_nested_topology_tampering(self):
        completed = native_action("Completed", "logic.completed")
        branch = native_action("Condition Branch", "logic.condition_block")
        branch["actions"] = [completed]
        condition = native_action("Condition Block", "logic.if_else")
        condition["blocks"] = [branch]

        while_branch = native_action("Condition Branch", "logic.condition_block")
        while_loop = native_action("While Loop", "logic.while")
        while_loop["blocks"] = [while_branch]

        child = native_action(
            "Synthetic Child",
            "workflow.sub_workflow",
            {"workflow_id": "definition_workflow_02SYNTHETICCHILD"},
        )
        child["base_type"] = "subworkflow"
        document = native_workflow(actions=[condition, child, while_loop])
        document["dependent_workflows"] = [
            "definition_workflow_02SYNTHETICCHILD"
        ]
        document["workflow"]["variables"] = [
            {
                "unique_name": "variable_workflow_02SYNTHETIC",
                "schema_id": "synthetic",
                "object_type": "variable_workflow",
                "properties": {
                    "name": "capture",
                    "scope": "local",
                    "type": "string",
                    "value": "capture",
                },
            }
        ]
        fingerprint = structural_fingerprint(
            document,
            {
                "condition": "logic.if_else",
                "condition_branch": "logic.condition_block",
                "completed": "logic.completed",
                "child_workflow": "workflow.sub_workflow",
                "while_loop": "logic.while",
            },
            {
                "root_action_sequence": [
                    "condition",
                    "child_workflow",
                    "while_loop",
                ],
                "condition": {
                    "children_key": "blocks",
                    "branch_activity": "condition_branch",
                    "branch_actions_key": "actions",
                    "terminal_activity": "completed",
                },
                "child_workflow": {
                    "dependency_key": "dependent_workflows",
                    "embedded_workflows": False,
                },
                "while_loop": {
                    "children_key": "blocks",
                    "branch_activity": "condition_branch",
                },
            },
        )
        self.assertTrue(
            verify_capture_fingerprint(document, fingerprint)[
                "capture_fingerprint_valid"
            ]
        )

        cases = (
            ("condition", "capture.condition_topology"),
            ("while", "capture.while_topology"),
            ("child", "capture.child_topology"),
        )
        for case, expected_code in cases:
            with self.subTest(case=case):
                candidate = copy.deepcopy(document)
                if case == "condition":
                    candidate["workflow"]["actions"][0]["blocks"] = []
                elif case == "while":
                    candidate["workflow"]["actions"][2]["blocks"][0][
                        "type"
                    ] = "logic.invented"
                else:
                    candidate["dependent_workflows"] = []
                result = verify_capture_fingerprint(candidate, fingerprint)
                self.assertFalse(result["capture_fingerprint_valid"])
                self.assertIn(
                    expected_code,
                    {item["code"] for item in result["issues"]},
                )

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
