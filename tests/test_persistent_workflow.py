from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orchestrator.api import create_app
from orchestrator.auth import token_sha256
from orchestrator.intent import load_intent
import yaml


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"
REQUIREMENTS_EXAMPLE = ROOT / "examples" / "fabric-requirements.lab.yaml"
TOKENS = {
    "planner-token": "planner-token-value-with-required-length",
    "approver-token": "approver-token-value-with-required-length",
    "operator-token": "operator-token-value-with-required-length",
    "auditor-token": "auditor-token-value-with-required-length",
}


class PersistentWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        database_path = str(Path(self.temporary_directory.name) / "state.sqlite3")
        self.intent = load_intent(EXAMPLE)
        self.requirements = yaml.safe_load(
            REQUIREMENTS_EXAMPLE.read_text(encoding="utf-8")
        )
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_DATABASE_PATH": database_path,
                "ORCHESTRATOR_EXECUTION_ENABLED": False,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(TOKENS["planner-token"]): {
                        "actor": "meraki-planner",
                        "roles": ["planner"],
                    },
                    token_sha256(TOKENS["approver-token"]): {
                        "actor": "change-approver",
                        "roles": ["approver"],
                    },
                    token_sha256(TOKENS["operator-token"]): {
                        "actor": "fabric-operator",
                        "roles": ["operator"],
                    },
                    token_sha256(TOKENS["auditor-token"]): {
                        "actor": "audit-reader",
                        "roles": ["auditor"],
                    },
                },
            }
        )
        self.client = app.test_client()

    def tearDown(self):
        self.temporary_directory.cleanup()

    @staticmethod
    def headers(token):
        return {
            "Authorization": "Bearer " + TOKENS.get(token, token),
            "Content-Type": "application/json",
        }

    def create_intent_and_plan(self):
        intent_response = self.client.post(
            "/v1/intents", json=self.intent, headers=self.headers("planner-token")
        )
        self.assertEqual(201, intent_response.status_code, intent_response.get_json())
        intent_id = intent_response.get_json()["intent_id"]
        plan_response = self.client.post(
            "/v1/intents/{}/plans".format(intent_id),
            json={},
            headers=self.headers("planner-token"),
        )
        self.assertEqual(201, plan_response.status_code, plan_response.get_json())
        return intent_response.get_json(), plan_response.get_json()

    def approve(self, plan_id):
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        response = self.client.post(
            "/v1/plans/{}/approvals".format(plan_id),
            json={
                "decision": "approved",
                "change_reference": "CHG-LAB-001",
                "expires_at": expires_at,
            },
            headers=self.headers("approver-token"),
        )
        self.assertEqual(201, response.status_code, response.get_json())
        return response.get_json()

    def test_intent_and_plan_are_immutable_and_idempotent(self):
        first_intent, first_plan = self.create_intent_and_plan()
        second_intent = self.client.post(
            "/v1/intents", json=self.intent, headers=self.headers("planner-token")
        )
        self.assertEqual(200, second_intent.status_code)
        self.assertEqual(first_intent["intent_id"], second_intent.get_json()["intent_id"])
        second_plan = self.client.post(
            "/v1/intents/{}/plans".format(first_intent["intent_id"]),
            json={},
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, second_plan.status_code)
        self.assertEqual(first_plan["plan_id"], second_plan.get_json()["plan_id"])

    def test_role_separation_blocks_planner_approval(self):
        _intent, plan = self.create_intent_and_plan()
        response = self.client.post(
            "/v1/plans/{}/approvals".format(plan["plan_id"]),
            json={},
            headers=self.headers("planner-token"),
        )
        self.assertEqual(403, response.status_code)

    def test_dynamic_requirements_are_allocated_planned_and_idempotent(self):
        payload = {
            "requirements": self.requirements,
            "idempotency_key": "meraki-design-request-0001",
        }
        first = self.client.post(
            "/v1/workflow-actions/plan",
            json=payload,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, first.status_code, first.get_json())
        body = first.get_json()
        self.assertEqual("plan_ready", body["status"])
        self.assertEqual("reserved", body["reservation_state"])
        self.assertGreater(body["allocation_summary"]["network"], 0)
        self.assertGreater(body["allocation_summary"]["scalar"], 0)

        second = self.client.post(
            "/v1/workflow-actions/plan",
            json=payload,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, second.status_code, second.get_json())
        self.assertEqual(body["reservation_id"], second.get_json()["reservation_id"])
        self.assertEqual(body["plan_id"], second.get_json()["plan_id"])

    def test_meraki_string_encoded_plan_body_is_decoded_once(self):
        payload = {
            "requirements": self.requirements,
            "idempotency_key": "meraki-native-http-json-string-001",
        }
        response = self.client.post(
            "/v1/workflow-actions/plan",
            data=json.dumps(json.dumps(payload)),
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, response.status_code, response.get_json())
        self.assertEqual("plan_ready", response.get_json()["status"])

    def test_meraki_unquoted_idempotency_token_is_repaired_with_strict_grammar(self):
        idempotency_key = "meraki-native-http-unquoted-001"
        payload = {
            "requirements": self.requirements,
            "idempotency_key": idempotency_key,
        }
        valid_json = json.dumps(payload, separators=(",", ":"))
        meraki_body = valid_json.replace(
            json.dumps(idempotency_key), idempotency_key, 1
        )
        response = self.client.post(
            "/v1/workflow-actions/plan",
            data=meraki_body,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, response.status_code, response.get_json())
        self.assertEqual("plan_ready", response.get_json()["status"])

        invalid_body = meraki_body.replace(idempotency_key, "unsafe key", 1)
        rejected = self.client.post(
            "/v1/workflow-actions/plan",
            data=invalid_body,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(400, rejected.status_code)
        self.assertEqual("body", rejected.get_json()["error"])

    def test_meraki_string_compatibility_remains_object_only_and_endpoint_scoped(self):
        non_object = self.client.post(
            "/v1/workflow-actions/plan",
            data=json.dumps(json.dumps(["not", "an", "object"])),
            headers=self.headers("planner-token"),
        )
        self.assertEqual(400, non_object.status_code)
        self.assertEqual("body", non_object.get_json()["error"])

        strict_route = self.client.post(
            "/v1/intents/validate",
            data=json.dumps(json.dumps(self.intent)),
            headers=self.headers("planner-token"),
        )
        self.assertEqual(400, strict_route.status_code)
        self.assertEqual("body", strict_route.get_json()["error"])

    def test_dynamic_idempotency_key_rebinding_is_rejected(self):
        payload = {
            "requirements": self.requirements,
            "idempotency_key": "meraki-design-request-0002",
        }
        first = self.client.post(
            "/v1/workflow-actions/plan",
            json=payload,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, first.status_code, first.get_json())
        changed = copy.deepcopy(payload)
        changed["requirements"]["virtual_networks"][0]["sites"][0]["users"] += 50
        second = self.client.post(
            "/v1/workflow-actions/plan",
            json=changed,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(409, second.status_code, second.get_json())

    def test_unsatisfied_dynamic_requirements_fail_closed(self):
        payload = {
            "requirements": copy.deepcopy(self.requirements),
            "idempotency_key": "meraki-design-request-0003",
        }
        payload["requirements"]["devices"][1]["roles"] = ["border"]
        response = self.client.post(
            "/v1/workflow-actions/plan",
            json=payload,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(422, response.status_code, response.get_json())
        self.assertEqual("allocation_failed", response.get_json()["status"])

    def test_run_requires_approval(self):
        _intent, plan = self.create_intent_and_plan()
        response = self.client.post(
            "/v1/runs",
            json={
                "plan_id": plan["plan_id"],
                "mode": "dry_run",
                "idempotency_key": "workflow-run-without-approval",
            },
            headers=self.headers("operator-token"),
        )
        self.assertEqual(409, response.status_code)
        self.assertEqual("approval_required", response.get_json()["error"])

    def test_approved_dry_run_is_idempotent_and_audited(self):
        _intent, plan = self.create_intent_and_plan()
        self.approve(plan["plan_id"])
        payload = {
            "plan_id": plan["plan_id"],
            "mode": "dry_run",
            "idempotency_key": "meraki-workflow-instance-0001",
        }
        first = self.client.post(
            "/v1/runs", json=payload, headers=self.headers("operator-token")
        )
        second = self.client.post(
            "/v1/runs", json=payload, headers=self.headers("operator-token")
        )
        self.assertEqual(201, first.status_code, first.get_json())
        self.assertEqual(200, second.status_code, second.get_json())
        self.assertEqual(first.get_json()["run_id"], second.get_json()["run_id"])
        self.assertEqual(plan["plan_hash"], first.get_json()["plan_hash"])
        self.assertEqual(plan["artifact_hash"], first.get_json()["artifact_hash"])
        self.assertEqual(plan["intent_version"], first.get_json()["intent_version"])
        self.assertNotIn(payload["idempotency_key"], str(first.get_json()))

        audit = self.client.get(
            "/v1/audit/run/{}".format(first.get_json()["run_id"]),
            headers=self.headers("auditor-token"),
        )
        self.assertEqual(200, audit.status_code)
        self.assertTrue(audit.get_json()["chain_valid"])
        self.assertEqual("run.created", audit.get_json()["events"][0]["event_type"])

        processed = self.client.post(
            "/v1/runs/{}/process-dry-run".format(first.get_json()["run_id"]),
            json={},
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, processed.status_code, processed.get_json())
        self.assertEqual("dry_run_blocked", processed.get_json()["run"]["status"])
        self.assertGreater(processed.get_json()["summary"]["command_count"], 0)
        self.assertGreater(len(processed.get_json()["evidence"]), 1)

        repeated = self.client.post(
            "/v1/runs/{}/process-dry-run".format(first.get_json()["run_id"]),
            json={},
            headers=self.headers("operator-token"),
        )
        self.assertEqual(409, repeated.status_code)

    def test_apply_fails_closed_when_execution_is_disabled(self):
        _intent, plan = self.create_intent_and_plan()
        self.approve(plan["plan_id"])
        now = datetime.now(timezone.utc)
        response = self.client.post(
            "/v1/runs",
            json={
                "plan_id": plan["plan_id"],
                "mode": "apply",
                "idempotency_key": "meraki-workflow-apply-0001",
                "maintenance_window": {
                    "start": (now - timedelta(minutes=5)).isoformat(),
                    "end": (now + timedelta(minutes=30)).isoformat(),
                },
            },
            headers=self.headers("operator-token"),
        )
        self.assertEqual(409, response.status_code)
        self.assertEqual("execution_disabled", response.get_json()["error"])

    def test_fixed_path_meraki_action_contract(self):
        planned = self.client.post(
            "/v1/workflow-actions/plan",
            json={"intent": self.intent},
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, planned.status_code, planned.get_json())
        self.assertEqual("plan_ready", planned.get_json()["status"])
        plan_id = planned.get_json()["plan_id"]

        approved = self.client.post(
            "/v1/workflow-actions/approve",
            json={
                "plan_id": plan_id,
                "decision": "approved",
                "change_reference": "CHG-FIXED-001",
                "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            },
            headers=self.headers("approver-token"),
        )
        self.assertEqual(200, approved.status_code, approved.get_json())

        started = self.client.post(
            "/v1/workflow-actions/run",
            json={
                "plan_id": plan_id,
                "mode": "dry_run",
                "idempotency_key": "fixed-meraki-action-0001",
            },
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, started.status_code, started.get_json())
        run_id = started.get_json()["run"]["run_id"]

        processed = self.client.post(
            "/v1/workflow-actions/process-dry-run",
            json={"run_id": run_id},
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, processed.status_code, processed.get_json())

        status = self.client.post(
            "/v1/workflow-actions/status",
            json={"run_id": run_id},
            headers=self.headers("operator-token"),
        )
        self.assertEqual("dry_run_blocked", status.get_json()["status"])

        evidence = self.client.post(
            "/v1/workflow-actions/evidence",
            json={"run_id": run_id},
            headers=self.headers("auditor-token"),
        )
        self.assertEqual(200, evidence.status_code, evidence.get_json())
        self.assertTrue(evidence.get_json()["chain_valid"])


if __name__ == "__main__":
    unittest.main()
