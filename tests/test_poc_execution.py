from __future__ import annotations

import copy
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from orchestrator.api import create_app
from orchestrator.allocator import derive_fabric_intent
from orchestrator.auth import token_sha256
from orchestrator.planner import create_plan
from orchestrator.poc_execution import (
    PocExecutionError,
    authorize_sjc23_poc_execution,
    build_sjc23_poc_deployment_preview,
)
from orchestrator.renderer import RenderError, render_configuration


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = yaml.safe_load(
    (ROOT / "examples" / "fabric-requirements.sjc23-poc.yaml").read_text(encoding="utf-8")
)
POLICY = yaml.safe_load(
    (ROOT / "policy" / "guardrails.sjc23-poc.yaml").read_text(encoding="utf-8")
)
VALID_FORM = {
    "fabric_name": "SJC23 recorded POC",
    "change_reference": "SJC23-POC-001",
    "corporate_users": "150",
    "guest_users": "150",
    "corporate_attachment": "corporate_laptop",
    "guest_attachment": "guest_laptop",
    "dhcp_lease_minutes": "60",
    "dns_profile": "public_google",
}


def _candidate():
    intent = derive_fabric_intent(copy.deepcopy(REQUIREMENTS), POLICY)["intent"]
    plan = create_plan(intent)
    artifact = render_configuration(intent, plan)
    return intent, plan, artifact


class PocExecutionPreviewTests(unittest.TestCase):
    def test_execution_authorization_allows_only_the_hash_bound_poc_blocker(self):
        intent, plan, artifact = _candidate()
        authorization = authorize_sjc23_poc_execution(
            intent,
            plan,
            artifact,
            POLICY,
            {
                "change_reference": "SJC23-POC-001",
                "plan_hash": plan["plan_hash"],
                "artifact_hash": artifact["artifact_hash"],
            },
        )

        self.assertEqual("sjc23_isolated_two_node", authorization["scope"])
        self.assertEqual(
            ["poc.local_dhcp_and_attachment_hardware_acceptance_pending"],
            authorization["allowed_blocker_codes"],
        )
        self.assertFalse(authorization["deployment_authorized"])

    def test_execution_authorization_fails_closed_for_hash_or_blocker_drift(self):
        intent, plan, artifact = _candidate()
        valid = {
            "change_reference": "SJC23-POC-001",
            "plan_hash": plan["plan_hash"],
            "artifact_hash": artifact["artifact_hash"],
        }
        wrong_hash = dict(valid, artifact_hash="0" * 64)
        with self.assertRaisesRegex(PocExecutionError, "artifact hash"):
            authorize_sjc23_poc_execution(intent, plan, artifact, POLICY, wrong_hash)

        extra_blocker = copy.deepcopy(artifact)
        extra_blocker["blocking_requirements"].append({"code": "unexpected.blocker"})
        extra_blocker["artifact_hash"] = artifact["artifact_hash"]
        with self.assertRaisesRegex(PocExecutionError, "only the local-DHCP"):
            authorize_sjc23_poc_execution(intent, plan, extra_blocker, POLICY, valid)

    def test_preview_is_poc_scoped_secret_free_and_non_executable(self):
        intent, plan, artifact = _candidate()
        preview = build_sjc23_poc_deployment_preview(intent, plan, artifact, POLICY)

        self.assertEqual("poc_deployment_preview_ready", preview["status"])
        self.assertFalse(preview["deployment_authorized"])
        self.assertFalse(preview["contains_secret_values"])
        self.assertFalse(preview["contains_raw_configuration"])
        self.assertEqual("10.255.0.0/31", preview["underlay"]["subnet"])
        self.assertEqual(
            ["10.30.100.0/24", "10.30.200.0/24"],
            [item["endpoint_prefix"] for item in preview["virtual_networks"]],
        )
        self.assertEqual(
            ["GigabitEthernet1/0/10", "GigabitEthernet1/0/11"],
            [item["interface"] for item in preview["endpoint_attachments"]],
        )
        self.assertIn(
            "poc.local_dhcp_and_attachment_hardware_acceptance_pending",
            preview["blocking_requirements"],
        )
        rendered = str(preview).lower()
        self.assertNotIn("secret://", rendered)
        self.assertNotIn("router lisp", rendered)
        self.assertNotIn("ip dhcp pool", rendered)

    def test_preview_rejects_out_of_scope_pool_attachment_or_policy(self):
        intent, plan, artifact = _candidate()
        changed_pool = copy.deepcopy(intent)
        changed_pool["endpoint_pools"][0]["prefix"] = "10.30.110.0/24"
        with self.assertRaisesRegex(PocExecutionError, "endpoint pool prefix"):
            build_sjc23_poc_deployment_preview(changed_pool, plan, artifact, POLICY)

        changed_attachment = copy.deepcopy(intent)
        changed_attachment["endpoint_attachments"][0]["interface"] = "GigabitEthernet1/0/12"
        with self.assertRaisesRegex(PocExecutionError, "attachment interface"):
            build_sjc23_poc_deployment_preview(changed_attachment, plan, artifact, POLICY)

        changed_policy = dict(POLICY, policy_version="1.0")
        with self.assertRaisesRegex(PocExecutionError, "policy version"):
            build_sjc23_poc_deployment_preview(intent, plan, artifact, changed_policy)

    def test_preview_refuses_to_turn_a_hardware_blocker_into_apply_authorization(self):
        intent, plan, artifact = _candidate()
        changed_artifact = copy.deepcopy(artifact)
        changed_artifact["blocking_requirements"] = []
        with self.assertRaisesRegex(PocExecutionError, "hardware-acceptance blocker"):
            build_sjc23_poc_deployment_preview(intent, plan, changed_artifact, POLICY)

    def test_guided_plan_api_returns_the_redacted_review_preview(self):
        token = "poc-execution-preview-planner-token-0001"
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(token): {
                        "actor": "poc-planner",
                        "roles": ["planner"],
                    }
                },
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
                "ORCHESTRATOR_GUARDRAILS_PATH": str(
                    ROOT / "policy" / "guardrails.sjc23-poc.yaml"
                ),
            }
        )
        response = app.test_client().post(
            "/v1/workflow-actions/poc-guided-plan",
            headers={"Authorization": "Bearer " + token},
            json={
                "form_values": VALID_FORM,
                "idempotency_key": "poc-deployment-preview-0001",
            },
        )

        self.assertEqual(200, response.status_code, response.get_json())
        preview = response.get_json()["poc_deployment_preview"]
        self.assertEqual("poc_deployment_preview_ready", preview["status"])
        self.assertFalse(preview["deployment_authorized"])
        self.assertEqual("10.255.0.0/31", preview["underlay"]["subnet"])
        self.assertIn(
            "poc.local_dhcp_and_attachment_hardware_acceptance_pending",
            preview["blocking_requirements"],
        )
        rendered = str(preview).lower()
        self.assertNotIn("secret://", rendered)
        self.assertNotIn("router lisp", rendered)

    def test_guided_plan_fails_closed_with_a_typed_preview_error(self):
        token = "poc-preview-render-error-planner-token-0001"
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(token): {"actor": "poc-planner", "roles": ["planner"]}
                },
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
                "ORCHESTRATOR_GUARDRAILS_PATH": str(
                    ROOT / "policy" / "guardrails.sjc23-poc.yaml"
                ),
            }
        )
        real_render = render_configuration
        render_count = 0

        def render_once_then_fail(intent, plan):
            nonlocal render_count
            render_count += 1
            if render_count == 1:
                return real_render(intent, plan)
            raise RenderError("preview rendering deliberately unavailable")

        with patch("orchestrator.api.render_configuration", side_effect=render_once_then_fail):
            response = app.test_client().post(
                "/v1/workflow-actions/poc-guided-plan",
                headers={"Authorization": "Bearer " + token},
                json={
                    "form_values": VALID_FORM,
                    "idempotency_key": "poc-deployment-preview-0002",
                },
            )

        self.assertEqual(422, response.status_code, response.get_json())
        self.assertEqual("poc_deployment_preview", response.get_json()["error"])


    def test_preview_includes_loopback_ip_for_each_device(self):
        intent, plan, artifact = _candidate()
        preview = build_sjc23_poc_deployment_preview(intent, plan, artifact, POLICY)
        for device_entry in preview["devices"]:
            self.assertIn("loopback_ip", device_entry)
            self.assertTrue(
                device_entry["loopback_ip"],
                "loopback_ip is empty for {}".format(device_entry["device_id"]),
            )

    def test_preview_includes_l2_and_l3_vni_per_virtual_network(self):
        intent, plan, artifact = _candidate()
        preview = build_sjc23_poc_deployment_preview(intent, plan, artifact, POLICY)
        for vn_entry in preview["virtual_networks"]:
            self.assertIn("l2_vni", vn_entry, vn_entry["virtual_network"])
            self.assertIn("l3_vni", vn_entry, vn_entry["virtual_network"])
            self.assertGreater(vn_entry["l2_vni"], 0, vn_entry["virtual_network"])
            self.assertGreater(vn_entry["l3_vni"], 0, vn_entry["virtual_network"])

    def test_preview_includes_vni_vlan_map(self):
        intent, plan, artifact = _candidate()
        preview = build_sjc23_poc_deployment_preview(intent, plan, artifact, POLICY)
        self.assertIn("vni_vlan_map", preview)
        self.assertTrue(preview["vni_vlan_map"])
        for entry in preview["vni_vlan_map"]:
            self.assertIn("virtual_network", entry)
            self.assertIn("vlan_id", entry)
            self.assertIn("l2_vni", entry)
            self.assertIn("l3_vni", entry)
            self.assertGreater(entry["l2_vni"], 0)
            self.assertGreater(entry["l3_vni"], 0)


if __name__ == "__main__":
    unittest.main()
