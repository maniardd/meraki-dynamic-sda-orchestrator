from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from orchestrator.meraki_workflow_package import (
    compile_workflow_build_plan,
    load_workflow_package,
    validate_workflow_package,
    workflow_operation_matrix,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "workflows" / "production_workflow_manifest.yaml"
NATIVE_FINGERPRINT = ROOT / "workflows" / "native" / "capture" / "activity-fingerprint.v1.json"


class MerakiWorkflowPackageTests(unittest.TestCase):
    def setUp(self):
        self.document = load_workflow_package(MANIFEST)

    def test_manifest_is_safe_to_build_but_not_claimed_production_ready(self):
        result = validate_workflow_package(self.document)
        self.assertTrue(result["safe_to_build"], result["issues"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["importable_exports_present"])
        self.assertFalse(result["apply_enabled"])

    def test_native_approval_acknowledgement_and_expiry_binding_fail_closed(self):
        mutations = (
            ("require_checkbox", "", "approval.acknowledgement"),
            ("require_checkbox", None, "approval.acknowledgement"),
            ("due_at_input", "unreviewed_due", "approval.due_binding"),
            ("due_at_input", None, "approval.due_binding"),
            ("expires_at_input", "unreviewed_expiry", "approval.expiry_binding"),
            ("expires_at_input", None, "approval.expiry_binding"),
        )
        for field, value, expected_code in mutations:
            with self.subTest(field=field, value=value):
                candidate = copy.deepcopy(self.document)
                workflow = next(
                    item
                    for item in candidate["workflows"]
                    if item["id"] == "request_approval"
                )
                native_approval = next(
                    step
                    for step in workflow["steps"]
                    if step["activity"] == "request_approval"
                )
                native_approval[field] = value
                result = validate_workflow_package(candidate)
                self.assertFalse(result["safe_to_build"])
                self.assertIn(
                    expected_code,
                    {issue["code"] for issue in result["issues"]},
                )

    def test_role_separation_and_fixed_relative_operations(self):
        roles = {target["role"] for target in self.document["targets"]}
        self.assertEqual({"planner", "approver", "operator", "auditor"}, roles)
        for operation in self.document["api_operations"].values():
            self.assertEqual("POST", operation["method"])
            self.assertTrue(operation["path"].startswith("/v1/workflow-actions/"))
            self.assertNotIn("://", operation["path"])
            self.assertNotIn("$", operation["path"])
            self.assertIn(operation["role"], roles)

    def test_compilation_is_deterministic_secret_free_and_redirect_safe(self):
        first = compile_workflow_build_plan(self.document)
        second = compile_workflow_build_plan(self.document)
        self.assertEqual(first, second)
        self.assertFalse(first["credentials_included"])
        rendered = json.dumps(first).lower()
        self.assertNotIn("ngrok", rendered)
        self.assertNotIn("bearer_token", rendered)
        for workflow in first["workflows"]:
            for step in workflow["steps"]:
                request = step.get("request")
                if request:
                    self.assertFalse(request["allow_auto_redirect"])
                    self.assertFalse(request["allow_sensitive_headers_redirect"])

    def test_native_assembly_covers_every_portable_step_with_captured_primitives(self):
        compiled = compile_workflow_build_plan(self.document)
        recipes = compiled["native_assembly"]["portable_activity_recipes"]
        portable_activities = {
            step["activity"]
            for workflow in self.document["workflows"]
            for step in workflow["steps"]
        }
        captured_primitives = set(compiled["native_serialization"]["activity_types"])

        self.assertEqual(set(recipes), portable_activities)
        self.assertEqual(
            "tenant_generated_only",
            compiled["native_assembly"]["tenant_identifier_policy"],
        )
        self.assertFalse(compiled["native_assembly"]["compiler_emits_importable_json"])

        expected_expansions = {
            "approval_task_rule": ["condition"],
            "bounded_poll": ["set_variables", "while_loop"],
            "build_json": ["parse_json", "set_variables"],
            "json_path_extract": ["json_path_query"],
            "result_summary": ["create_prompt"],
        }
        for portable_name, sequence in expected_expansions.items():
            self.assertEqual(sequence, recipes[portable_name]["native_sequence"])
        self.assertEqual(
            ["http_request", "condition", "sleep", "set_variables"],
            recipes["bounded_poll"]["loop_body_sequence"],
        )
        self.assertEqual(
            [
                "input_json_parsed_before_use",
                "fixed_request_body_template",
                "no_quoted_user_controlled_interpolation",
                "payload_substitution_acceptance_required",
            ],
            recipes["build_json"]["invariants"],
        )

        for portable_name, recipe in recipes.items():
            referenced = set(recipe["native_sequence"])
            referenced.update(recipe.get("loop_body_sequence", []))
            referenced.update(recipe.get("supporting_activities", []))
            self.assertTrue(referenced, portable_name)
            self.assertLessEqual(referenced, captured_primitives, portable_name)

        for workflow in compiled["workflows"]:
            for step in workflow["steps"]:
                self.assertEqual(
                    recipes[step["activity"]],
                    step["native_implementation"],
                    "{}:{}".format(workflow["id"], step["id"]),
                )

    def test_native_assembly_contract_tampering_fails_closed(self):
        mutations = (
            lambda item: item["native_assembly"].update(
                {"tenant_identifier_policy": "compiler_generated"}
            ),
            lambda item: item["native_assembly"]["portable_activity_recipes"].pop(
                "bounded_poll"
            ),
            lambda item: item["native_assembly"]["portable_activity_recipes"][
                "bounded_poll"
            ]["loop_body_sequence"].append("python"),
            lambda item: item["native_assembly"]["portable_activity_recipes"][
                "http_request"
            ]["native_sequence"].append("sleep"),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = copy.deepcopy(self.document)
                mutation(candidate)
                result = validate_workflow_package(candidate)
                self.assertFalse(result["safe_to_build"])
                self.assertIn(
                    "native.assembly_contract",
                    {item["code"] for item in result["issues"]},
                )
                with self.assertRaisesRegex(
                    ValueError, "Invalid Meraki workflow package"
                ):
                    compile_workflow_build_plan(candidate)

    def test_genuine_native_activity_types_are_pinned_without_property_values(self):
        fingerprint = json.loads(NATIVE_FINGERPRINT.read_text(encoding="utf-8"))
        self.assertEqual(
            "efb6d7806a1ad26447cafbfeb5c3cabd85f2c01ae9ec5b06547eaa3743ba1187",
            fingerprint["source"]["export_sha256"],
        )
        self.assertFalse(fingerprint["safety"]["contains_property_values"])
        self.assertFalse(fingerprint["safety"]["contains_credentials"])
        self.assertFalse(fingerprint["source"]["raw_export_committed"])
        self.assertFalse(fingerprint["source"]["child_workflows_embedded"])
        self.assertTrue(fingerprint["safety"]["configured_properties_complete"])
        rendered_fingerprint = json.dumps(fingerprint)
        self.assertNotIn("CAPTURE_ONLY", rendered_fingerprint)
        self.assertNotIn("@cisco.com", rendered_fingerprint)
        self.assertNotIn("/v1/workflow-actions/plan", rendered_fingerprint)
        self.assertNotIn("started_by", rendered_fingerprint)
        expected = {
            "http_request": "web-service.http_request",
            "create_prompt": "task.prompt_request",
            "condition": "logic.if_else",
            "condition_branch": "logic.condition_block",
            "completed": "logic.completed",
            "request_approval": "task.request_approval",
            "child_workflow": "workflow.sub_workflow",
            "while_loop": "logic.while",
            "set_variables": "core.set_multiple_variables",
            "sleep": "core.sleep",
            "parse_json": "core.parsejson",
            "json_path_query": "corejava.jsonpathquery",
        }
        self.assertEqual(
            expected,
            {
                name: activity["type"]
                for name, activity in fingerprint["activities"].items()
            },
        )
        compiled = compile_workflow_build_plan(self.document)
        self.assertEqual(
            fingerprint["source"]["export_sha256"],
            compiled["native_serialization"]["capture_export_sha256"],
        )
        self.assertEqual(expected, compiled["native_serialization"]["activity_types"])
        self.assertTrue(compiled["native_serialization"]["configured_properties_complete"])
        self.assertEqual(
            fingerprint["serialization_topology"],
            compiled["native_serialization"]["serialization_topology"],
        )
        self.assertEqual(
            sorted(fingerprint["workflow"]["property_keys"]),
            compiled["native_serialization"]["workflow_property_keys"],
        )
        self.assertEqual(
            sorted(fingerprint["export_top_level_keys"]),
            compiled["native_serialization"]["export_top_level_keys"],
        )
        self.assertEqual(
            sorted(fingerprint["workflow"]["top_level_keys"]),
            compiled["native_serialization"]["workflow_top_level_keys"],
        )
        self.assertEqual(
            {
                "object_type": fingerprint["workflow"]["variable"]["object_type"],
                "unique_name_prefix": fingerprint["workflow"]["variable"][
                    "unique_name_prefix"
                ],
                "wrapper_keys": sorted(
                    fingerprint["workflow"]["variable"]["wrapper_keys"]
                ),
                "property_keys": sorted(
                    fingerprint["workflow"]["variable"]["property_keys"]
                ),
            },
            compiled["native_serialization"]["workflow_variable"],
        )
        self.assertEqual(
            {
                name: sorted(activity["property_keys"])
                for name, activity in fingerprint["activities"].items()
            },
            compiled["native_serialization"]["activity_property_keys"],
        )

    def test_native_serialization_metadata_fails_closed_when_tampered(self):
        cases = (
            ("contains_property_values", True, "native.property_values"),
            ("capture_export_sha256", "invented", "native.capture_hash"),
        )
        for field, value, expected_code in cases:
            with self.subTest(field=field):
                candidate = copy.deepcopy(self.document)
                candidate["native_serialization"][field] = value
                result = validate_workflow_package(candidate)
                self.assertFalse(result["safe_to_build"])
                self.assertIn(expected_code, {item["code"] for item in result["issues"]})

        candidate = copy.deepcopy(self.document)
        candidate["native_serialization"]["activities"]["http_request"]["type"] = "invented"
        result = validate_workflow_package(candidate)
        self.assertFalse(result["safe_to_build"])
        self.assertIn("native.activity_type", {item["code"] for item in result["issues"]})

        candidate = copy.deepcopy(self.document)
        candidate["native_serialization"]["configured_properties_complete"] = False
        result = validate_workflow_package(candidate)
        self.assertFalse(result["safe_to_build"])
        self.assertIn(
            "native.configured_properties_incomplete",
            {item["code"] for item in result["issues"]},
        )

        candidate = copy.deepcopy(self.document)
        candidate["native_serialization"]["activities"]["create_prompt"][
            "observed_property_keys"
        ].remove("form_elements")
        result = validate_workflow_package(candidate)
        self.assertFalse(result["safe_to_build"])
        self.assertIn("native.property_keys", {item["code"] for item in result["issues"]})

        candidate = copy.deepcopy(self.document)
        candidate["native_serialization"]["serialization_topology"]["condition"][
            "children_key"
        ] = "invented"
        result = validate_workflow_package(candidate)
        self.assertFalse(result["safe_to_build"])
        self.assertIn(
            "native.serialization_topology",
            {item["code"] for item in result["issues"]},
        )

        tamper_cases = (
            (
                lambda item: item["native_serialization"][
                    "observed_export_top_level_keys"
                ].append("invented"),
                "native.export_top_level_keys",
            ),
            (
                lambda item: item["native_serialization"]["workflow"][
                    "observed_top_level_keys"
                ].remove("variables"),
                "native.workflow_top_level_keys",
            ),
            (
                lambda item: item["native_serialization"]["workflow"]["variable"][
                    "observed_property_keys"
                ].remove("scope"),
                "native.variable_property_keys",
            ),
        )
        for mutation, expected_code in tamper_cases:
            with self.subTest(expected_code=expected_code):
                candidate = copy.deepcopy(self.document)
                mutation(candidate)
                result = validate_workflow_package(candidate)
                self.assertFalse(result["safe_to_build"])
                self.assertIn(
                    expected_code,
                    {item["code"] for item in result["issues"]},
                )

    def test_apply_workflow_and_executable_steps_are_disabled(self):
        workflows = {item["id"]: item for item in self.document["workflows"]}
        apply_workflow = workflows["start_apply"]
        self.assertFalse(apply_workflow["enabled"])
        for step in apply_workflow["steps"]:
            if step["activity"] in {"http_request", "bounded_poll"}:
                self.assertFalse(step["enabled"])

        compiled = {
            item["id"]: item
            for item in compile_workflow_build_plan(self.document)["workflows"]
        }
        compiled_apply = compiled["start_apply"]
        self.assertFalse(compiled_apply["enabled"])
        executable_steps = [
            step
            for step in compiled_apply["steps"]
            if step["activity"] in {"http_request", "bounded_poll"}
        ]
        self.assertTrue(executable_steps)
        self.assertFalse(any(step["enabled"] for step in executable_steps))

    def test_operation_matrix_contains_no_enabled_apply_operation(self):
        matrix = workflow_operation_matrix(self.document)
        self.assertTrue(any(row["operation"] == "plan" for row in matrix))
        apply_rows = [row for row in matrix if row["workflow_id"] == "start_apply"]
        self.assertTrue(apply_rows)
        self.assertFalse(any(row["enabled"] for row in apply_rows))

    def test_variable_or_absolute_operation_path_fails_closed(self):
        for invalid_path in (
            "https://relay.example.test/v1/workflow-actions/plan",
            "/v1/workflow-actions/$workflow.local.path$",
        ):
            with self.subTest(path=invalid_path):
                candidate = copy.deepcopy(self.document)
                candidate["api_operations"]["plan"]["path"] = invalid_path
                result = validate_workflow_package(candidate)
                codes = {issue["code"] for issue in result["issues"]}
                self.assertFalse(result["safe_to_build"])
                self.assertIn("operation.path", codes)

    def test_redirect_or_unbounded_poll_fails_closed(self):
        candidate = copy.deepcopy(self.document)
        candidate["safety"]["allow_redirects"] = True
        dry_run = next(item for item in candidate["workflows"] if item["id"] == "start_dry_run")
        poll = next(item for item in dry_run["steps"] if item["activity"] == "bounded_poll")
        poll["max_attempts"] = 1000
        result = validate_workflow_package(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["safe_to_build"])
        self.assertIn("transport.redirects", codes)
        self.assertIn("poll.bounds", codes)

    def test_production_claim_requires_native_exports(self):
        candidate = copy.deepcopy(self.document)
        candidate["package"]["production_ready"] = True
        result = validate_workflow_package(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["safe_to_build"])
        self.assertIn("release.importable_exports_missing", codes)
        self.assertIn("release.apply_disabled", codes)

    def test_http_request_requires_immediate_status_branch(self):
        candidate = copy.deepcopy(self.document)
        workflow = next(item for item in candidate["workflows"] if item["id"] == "validate_and_plan")
        workflow["steps"].pop(2)
        result = validate_workflow_package(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["safe_to_build"])
        self.assertIn("step.http_status_branch", codes)

    def test_importable_export_claim_requires_inventory(self):
        candidate = copy.deepcopy(self.document)
        candidate["package"]["importable_exports_present"] = True
        result = validate_workflow_package(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["safe_to_build"])
        self.assertIn("release.native_export_inventory", codes)

    def test_runtime_budget_is_required_and_must_be_positive_integer(self):
        cases = (
            ("request_timeout_seconds", "runtime.request_timeout"),
            ("max_parent_runtime_seconds", "runtime.parent_budget"),
        )
        for field, expected_code in cases:
            for invalid_value in (None, 0, -1, True, "60"):
                with self.subTest(field=field, value=invalid_value):
                    candidate = copy.deepcopy(self.document)
                    if invalid_value is None:
                        candidate["runtime"].pop(field)
                    else:
                        candidate["runtime"][field] = invalid_value
                    result = validate_workflow_package(candidate)
                    codes = {issue["code"] for issue in result["issues"]}
                    self.assertFalse(result["safe_to_build"])
                    self.assertIn(expected_code, codes)

    def test_zero_runtime_budget_cannot_bypass_poll_duration_guard(self):
        candidate = copy.deepcopy(self.document)
        candidate["runtime"]["max_parent_runtime_seconds"] = 0
        dry_run = next(item for item in candidate["workflows"] if item["id"] == "start_dry_run")
        poll = next(item for item in dry_run["steps"] if item["activity"] == "bounded_poll")
        poll["max_attempts"] = 100
        poll["interval_seconds"] = 60
        result = validate_workflow_package(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertFalse(result["safe_to_build"])
        self.assertIn("runtime.parent_budget", codes)


if __name__ == "__main__":
    unittest.main()
