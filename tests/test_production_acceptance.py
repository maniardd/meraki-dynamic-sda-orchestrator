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

    def test_hash_bound_evidence_is_pinned_to_lf(self):
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        rules = {
            line.strip()
            for line in attributes.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        self.assertIn("/acceptance/evidence/*.json text eol=lf", rules)
        self.assertIn("/acceptance/*.yaml text eol=lf", rules)

    def test_iosxe_read_only_precheck_is_hash_bound_and_write_free(self):
        gate = next(
            gate
            for gate in self.registry["gates"]
            if gate["id"] == "iosxe.read_only_precheck"
        )
        self.assertEqual("passed", gate["status"])
        self.assertEqual(1, len(gate["evidence"]))

        relative = gate["evidence"][0]["ref"].removeprefix("evidence://")
        evidence_path = ROOT / relative
        content = evidence_path.read_bytes()
        self.assertEqual(
            hashlib.sha256(content).hexdigest(),
            gate["evidence"][0]["sha256"],
        )

        evidence = json.loads(content)
        self.assertEqual("passed", evidence["result"])
        self.assertTrue(evidence["safety"]["read_only"])
        self.assertFalse(evidence["safety"]["configuration_mode_used"])
        self.assertFalse(evidence["safety"]["raw_output_persisted"])
        self.assertFalse(evidence["safety"]["device_writes_performed"])
        self.assertFalse(evidence["safety"]["contains_secret_values"])
        self.assertFalse(evidence["safety"]["contains_raw_configuration"])
        self.assertEqual(
            18,
            evidence["targets"]["border_control_plane"]["passed_commands"],
        )
        self.assertEqual(
            19,
            evidence["targets"]["fabric_edge"]["passed_commands"],
        )
        self.assertTrue(
            evidence["licensing_observation"]["requires_resolution_before_apply"]
        )

    def test_iosxe_license_state_is_explicit_and_blocks_underlay_acceptance(self):
        by_id = {gate["id"]: gate for gate in self.registry["gates"]}
        license_gate = by_id["iosxe.license_state"]
        self.assertEqual("passed", license_gate["status"])
        self.assertEqual(
            ["iosxe.read_only_precheck"],
            license_gate["dependencies"],
        )
        self.assertEqual(1, len(license_gate["evidence"]))
        latest = license_gate["evidence"][0]
        self.assertEqual("passed", latest["result"])
        self.assertEqual(
            "evidence://acceptance/evidence/iosxe-license-state-accepted-20260726.json",
            latest["ref"],
        )
        content = (ROOT / latest["ref"].removeprefix("evidence://")).read_bytes()
        self.assertEqual(hashlib.sha256(content).hexdigest(), latest["sha256"])
        fresh_evidence = json.loads(content)
        self.assertTrue(
            fresh_evidence["targets"]["border_control_plane"]["license_policy_passed"]
        )
        self.assertTrue(
            fresh_evidence["targets"]["fabric_edge"]["license_policy_passed"]
        )
        self.assertTrue(fresh_evidence["safety"]["read_only"])
        self.assertFalse(fresh_evidence["safety"]["device_writes_performed"])
        self.assertEqual(
            ["iosxe.license_state"],
            by_id["iosxe.underlay"]["dependencies"],
        )

        result = self.validate()
        self.assertEqual(17, result["required_gate_count"])
        self.assertEqual(5, result["passed_required_gate_count"])
        self.assertNotIn("iosxe.license_state", result["incomplete_gate_ids"])

    def test_unselected_design_capabilities_are_explicitly_optional(self):
        by_id = {gate["id"]: gate for gate in self.registry["gates"]}
        expected_conditions = {
            "fusion.bgp_handoff": "border_handoff.enabled false",
            "multicast.native_overlay": "multicast.enabled is false",
            "policy.ise_sxp_sgt": "policy_plane.mode none",
        }
        for gate_id, condition in expected_conditions.items():
            gate = by_id[gate_id]
            self.assertFalse(gate["required"], gate_id)
            self.assertEqual("not_applicable", gate["status"], gate_id)
            self.assertIn(condition, gate["rationale"], gate_id)

        result = self.validate()
        self.assertEqual(17, result["required_gate_count"])
        for gate_id in expected_conditions:
            self.assertNotIn(gate_id, result["incomplete_gate_ids"])

        candidate = copy.deepcopy(self.registry)
        candidate_gate = next(
            gate
            for gate in candidate["gates"]
            if gate["id"] == "fusion.bgp_handoff"
        )
        candidate_gate["required"] = True
        invalid = self.validate(candidate)
        self.assertFalse(invalid["registry_valid"])
        self.assertIn(
            "gate.not_applicable_required",
            {issue["code"] for issue in invalid["issues"]},
        )

    def test_acceptance_collateral_matches_live_applicable_gate_count(self):
        result = self.validate()
        expected = (
            f'{result["passed_required_gate_count"]} of '
            f'{result["required_gate_count"]} applicable gates'
        )
        collateral = [
            ROOT / "docs" / "engineering-product-vidcast-and-devnet-submission.md",
            ROOT / "docs" / "production-acceptance-registry.md",
            ROOT / "docs" / "vidcast-and-ciscolive-demo-kit.md",
        ]
        for path in collateral:
            rendered = path.read_text(encoding="utf-8")
            self.assertIn(expected, rendered, path.name)
            self.assertNotIn("5/20", rendered, path.name)
            self.assertNotIn("five of twenty", rendered.lower(), path.name)
            self.assertNotIn("twenty required gates", rendered.lower(), path.name)

    def test_sjc23_closure_plan_lists_each_live_pending_gate(self):
        result = self.validate()
        closure_plan = (
            ROOT / "docs" / "sjc23-acceptance-closure-plan.md"
        ).read_text(encoding="utf-8")

        self.assertIn("Required pending-gate evidence", closure_plan)
        self.assertIn("Safe execution order", closure_plan)
        self.assertIn("Explicit no-go conditions", closure_plan)
        self.assertEqual(12, len(result["incomplete_gate_ids"]))
        for gate_id in result["incomplete_gate_ids"]:
            self.assertIn(f"`{gate_id}`", closure_plan, gate_id)

        for not_applicable_gate in (
            "fusion.bgp_handoff",
            "multicast.native_overlay",
            "policy.ise_sxp_sgt",
        ):
            self.assertNotIn(
                f"| `{not_applicable_gate}` |",
                closure_plan,
                not_applicable_gate,
            )

    def test_failed_meraki_native_package_audit_is_hash_bound_and_secret_free(self):
        gate = next(
            gate
            for gate in self.registry["gates"]
            if gate["id"] == "meraki.native_export_import"
        )
        self.assertEqual("pending", gate["status"])
        audit_evidence = [
            item
            for item in gate["evidence"]
            if item["id"].startswith("meraki.native-package-audit")
        ]
        self.assertEqual(3, len(audit_evidence))
        self.assertTrue(
            all(evidence["result"] == "failed" for evidence in audit_evidence)
        )

        latest = audit_evidence[-1]
        relative = latest["ref"].removeprefix("evidence://")
        content = (ROOT / relative).read_bytes()
        self.assertEqual(
            hashlib.sha256(content).hexdigest(),
            latest["sha256"],
        )

        evidence = json.loads(content)
        self.assertEqual("failed", evidence["result"])
        self.assertFalse(evidence["source"]["raw_export_committed"])
        self.assertEqual(8, evidence["audit"]["error_count"])
        self.assertEqual(5, evidence["audit"]["workflow_count"])
        self.assertTrue(evidence["audit"]["final_prompt_activity_present"])
        self.assertTrue(evidence["audit"]["strict_final_prompt_label_match"])
        self.assertEqual(
            {
                "secret.inline_value": 4,
                "transport.ngrok": 4,
            },
            evidence["audit"]["issue_counts"],
        )
        self.assertEqual(
            18,
            evidence["comparison_to_previous_audit"]["previous_error_count"],
        )
        self.assertEqual(
            8,
            evidence["comparison_to_previous_audit"]["current_error_count"],
        )
        self.assertFalse(evidence["audit"]["native_export_set_valid"])
        self.assertFalse(evidence["audit"]["production_package_complete"])
        self.assertFalse(evidence["safety"]["contains_secret_values"])
        self.assertFalse(
            evidence["safety"]["audit_report_contains_property_values"]
        )
        self.assertFalse(evidence["safety"]["workflow_run_performed"])
        self.assertFalse(evidence["safety"]["device_writes_performed"])
        self.assertFalse(evidence["safety"]["apply_enabled"])

    def test_poc_readiness_evidence_is_hash_bound_but_cannot_close_production_gates(self):
        by_id = {gate["id"]: gate for gate in self.registry["gates"]}
        expected = {
            "ingress.stable_tls": (
                "ingress.poc-public-readiness.20260727",
                "ingress-poc-public-readiness-20260727.json",
                {"public_https_health": True, "api_execution_enabled": False},
            ),
            "meraki.native_export_import": (
                "meraki.role-identity-readiness.20260727",
                "meraki-role-identity-readiness-20260727.json",
                {"private_file_mode": True, "ready_for_meraki_targets": True},
            ),
            "runtime.postgres_backup_restore": (
                "runtime.postgres-local-recovery.20260727",
                "runtime-postgres-local-recovery-20260727.json",
                {
                    "private_backup_created": True,
                    "production_database_modified": False,
                    "disposable_restore_passed": True,
                },
            ),
        }
        for gate_id, (evidence_id, filename, expected_checks) in expected.items():
            gate = by_id[gate_id]
            self.assertEqual("pending", gate["status"], gate_id)
            record = next(
                item for item in gate["evidence"] if item["id"] == evidence_id
            )
            content = (ROOT / "acceptance" / "evidence" / filename).read_bytes()
            self.assertEqual(
                hashlib.sha256(content).hexdigest(), record["sha256"], evidence_id
            )
            evidence = json.loads(content)
            self.assertEqual("passed", evidence["result"], evidence_id)
            self.assertFalse(evidence["safety"]["contains_secret_values"])
            self.assertFalse(evidence["safety"]["apply_enabled"])
            source = evidence["checks"] if "checks" in evidence else evidence["identity_readiness"]
            for key, value in expected_checks.items():
                self.assertEqual(value, source[key], f"{evidence_id}:{key}")

        result = self.validate()
        self.assertEqual(5, result["passed_required_gate_count"])
        self.assertIn("ingress.stable_tls", result["incomplete_gate_ids"])
        self.assertIn("meraki.native_export_import", result["incomplete_gate_ids"])

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
