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

    def test_genuine_native_activity_types_are_pinned_without_property_values(self):
        fingerprint = json.loads(NATIVE_FINGERPRINT.read_text(encoding="utf-8"))
        self.assertEqual(
            "d88dcb829e1f7a076ba82ba8cdd6d32e5c8b1852ed6dc93c1f95721a324724ee",
            fingerprint["source"]["export_sha256"],
        )
        self.assertFalse(fingerprint["safety"]["contains_property_values"])
        self.assertFalse(fingerprint["safety"]["contains_credentials"])
        self.assertFalse(fingerprint["source"]["raw_export_committed"])
        expected = {
            "http_request": "web-service.http_request",
            "create_prompt": "task.prompt_request",
            "request_approval": "task.request_approval",
        }
        self.assertEqual(
            expected,
            {
                name: activity["type"]
                for name, activity in fingerprint["activities"].items()
            },
        )
        compiled = compile_workflow_build_plan(self.document)
        self.assertEqual(expected, compiled["native_serialization"]["activity_types"])
        self.assertFalse(compiled["native_serialization"]["configured_properties_complete"])

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

    def test_apply_workflow_and_executable_steps_are_disabled(self):
        workflows = {item["id"]: item for item in self.document["workflows"]}
        apply_workflow = workflows["start_apply"]
        self.assertFalse(apply_workflow["enabled"])
        for step in apply_workflow["steps"]:
            if step["activity"] in {"http_request", "bounded_poll"}:
                self.assertFalse(step["enabled"])

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
