from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from orchestrator.acceptance import (
    load_acceptance_registry,
    load_workflow_manifest,
    validate_production_acceptance,
)


ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "acceptance" / "production-acceptance.sjc23.yaml"
WORKFLOW_MANIFEST = ROOT / "workflows" / "production_workflow_manifest.yaml"


class ProductionAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.registry = load_acceptance_registry(REGISTRY)
        self.workflow_manifest = load_workflow_manifest(WORKFLOW_MANIFEST)

    def validate(self, registry=None, workflow_manifest=None):
        return validate_production_acceptance(
            registry or self.registry,
            workflow_manifest=workflow_manifest or self.workflow_manifest,
        )

    def test_shipped_registry_is_valid_but_fail_closed(self):
        result = self.validate()
        self.assertTrue(result["registry_valid"], result["issues"])
        self.assertFalse(result["acceptance_complete"])
        self.assertFalse(result["ready_for_controlled_enablement"])
        self.assertFalse(result["production_ready"])
        self.assertFalse(result["workflow_apply_state"]["apply_enabled"])
        self.assertFalse(result["workflow_apply_state"]["apply_workflow_enabled"])
        self.assertFalse(
            result["workflow_apply_state"]["apply_executable_steps_enabled"]
        )
        self.assertFalse(result["contains_secret_values"])

    def test_passed_gate_requires_passed_evidence(self):
        candidate = copy.deepcopy(self.registry)
        candidate["gates"][0]["status"] = "passed"
        candidate["gates"][0]["evidence"] = []
        result = self.validate(candidate)
        self.assertFalse(result["registry_valid"])
        self.assertIn(
            "gate.passed_without_evidence",
            {issue["code"] for issue in result["issues"]},
        )

    def test_missing_dependency_and_cycle_fail_closed(self):
        candidate = copy.deepcopy(self.registry)
        candidate["gates"][0]["dependencies"] = ["missing.gate"]
        candidate["gates"][1]["dependencies"] = [candidate["gates"][0]["id"]]
        candidate["gates"][0]["dependencies"].append(candidate["gates"][1]["id"])
        result = self.validate(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("gate.dependency_missing", codes)
        self.assertIn("gate.dependency_cycle", codes)

    def test_decided_signoff_requires_identity_time_and_evidence(self):
        candidate = copy.deepcopy(self.registry)
        candidate["signoffs"][0]["status"] = "approved"
        result = self.validate(candidate)
        self.assertFalse(result["registry_valid"])
        self.assertIn(
            "signoff.decision_evidence",
            {issue["code"] for issue in result["issues"]},
        )

    def test_duplicate_gate_evidence_and_signoff_fail_closed(self):
        candidate = copy.deepcopy(self.registry)
        candidate["gates"].append(copy.deepcopy(candidate["gates"][0]))
        candidate["signoffs"].append(copy.deepcopy(candidate["signoffs"][0]))
        result = self.validate(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("gate.duplicate", codes)
        self.assertIn("signoff.duplicate", codes)

    def test_secret_bearing_field_name_is_rejected(self):
        candidate = copy.deepcopy(self.registry)
        candidate["api_token"] = "not-a-real-token"
        result = self.validate(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("registry.schema", codes)
        self.assertIn("registry.secret_key", codes)

    def test_apply_claim_before_acceptance_fails_closed(self):
        candidate = copy.deepcopy(self.registry)
        candidate["controls"]["apply_authorization_requested"] = True
        candidate["controls"]["apply_workflow_present"] = True
        candidate["controls"]["device_writes_permitted"] = True
        result = self.validate(candidate)
        codes = {issue["code"] for issue in result["issues"]}
        self.assertIn("apply.request_before_acceptance", codes)
        self.assertIn("apply.write_before_acceptance", codes)
        self.assertFalse(result["production_ready"])

    def test_fail_open_workflow_manifest_is_detected(self):
        manifest = copy.deepcopy(self.workflow_manifest)
        manifest["safety"]["apply_enabled"] = True
        for workflow in manifest["workflows"]:
            if workflow.get("id") == "start_apply":
                workflow["enabled"] = True
                for step in workflow.get("steps", []):
                    if step.get("activity") in {"http_request", "bounded_poll"}:
                        step["enabled"] = True
        result = self.validate(workflow_manifest=manifest)
        self.assertIn(
            "apply.manifest_fail_open",
            {issue["code"] for issue in result["issues"]},
        )
        self.assertFalse(result["production_ready"])

    def test_registry_hash_is_deterministic_and_content_bound(self):
        first = self.validate()["registry_hash"]
        second = self.validate(copy.deepcopy(self.registry))["registry_hash"]
        self.assertEqual(first, second)
        candidate = copy.deepcopy(self.registry)
        candidate["scope"]["release_candidate"] += "-changed"
        self.assertNotEqual(first, self.validate(candidate)["registry_hash"])

    def test_evidence_file_hashes_match_registry(self):
        for gate in self.registry["gates"]:
            for evidence in gate["evidence"]:
                if not evidence["ref"].startswith("evidence://acceptance/"):
                    continue
                relative = evidence["ref"].removeprefix("evidence://")
                content = (ROOT / relative).read_bytes()
                self.assertEqual(
                    hashlib.sha256(content).hexdigest(),
                    evidence["sha256"],
                    evidence["id"],
                )

    def test_missing_or_tampered_local_evidence_fails_closed(self):
        missing = copy.deepcopy(self.registry)
        missing["gates"][1]["evidence"][0]["ref"] = (
            "evidence://acceptance/evidence/missing.json"
        )
        result = self.validate(missing)
        self.assertIn(
            "evidence.missing",
            {issue["code"] for issue in result["issues"]},
        )

        tampered = copy.deepcopy(self.registry)
        tampered["gates"][1]["evidence"][0]["sha256"] = "0" * 64
        result = self.validate(tampered)
        self.assertIn(
            "evidence.hash_mismatch",
            {issue["code"] for issue in result["issues"]},
        )

    def test_local_evidence_path_escape_fails_closed(self):
        candidate = copy.deepcopy(self.registry)
        candidate["gates"][1]["evidence"][0]["ref"] = (
            "evidence://../outside.json"
        )
        result = self.validate(candidate)
        self.assertIn(
            "evidence.path_escape",
            {issue["code"] for issue in result["issues"]},
        )

    def test_tool_payload_is_structural_and_secret_free(self):
        rendered = json.dumps(self.validate(), sort_keys=True)
        self.assertNotIn("principal://", rendered)
        self.assertNotIn("requirementsJson", rendered)
        self.assertIn('"contains_secret_values": false', rendered)


if __name__ == "__main__":
    unittest.main()
