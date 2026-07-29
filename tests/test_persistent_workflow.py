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
SJC23_POC_GUARDRAILS = ROOT / "policy" / "guardrails.sjc23-poc.yaml"
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

    def test_meraki_workflow_action_role_matrix_fails_closed(self):
        """Every fixed workflow action has one mutating owner role.

        The read-only status action is intentionally available to all four
        service identities; it is the only exception and is asserted below.
        """
        _intent, plan = self.create_intent_and_plan()
        plan_id = plan["plan_id"]
        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

        denied_actions = (
            (
                "/v1/workflow-actions/plan",
                {"intent": self.intent},
                ("approver-token", "operator-token", "auditor-token"),
            ),
            (
                "/v1/workflow-actions/approve",
                {
                    "plan_id": plan_id,
                    "decision": "approved",
                    "change_reference": "CHG-ROLE-MATRIX-DENIED",
                    "expires_at": expires_at,
                },
                ("planner-token", "operator-token", "auditor-token"),
            ),
            (
                "/v1/workflow-actions/run",
                {
                    "plan_id": plan_id,
                    "mode": "dry_run",
                    "idempotency_key": "role-matrix-denied-run-001",
                },
                ("planner-token", "approver-token", "auditor-token"),
            ),
        )
        for path, payload, denied_tokens in denied_actions:
            for token in denied_tokens:
                with self.subTest(path=path, token=token):
                    response = self.client.post(path, json=payload, headers=self.headers(token))
                    self.assertEqual(403, response.status_code, response.get_json())
                    self.assertEqual("forbidden", response.get_json()["error"])

        approved = self.client.post(
            "/v1/workflow-actions/approve",
            json={
                "plan_id": plan_id,
                "decision": "approved",
                "change_reference": "CHG-ROLE-MATRIX-001",
                "expires_at": expires_at,
            },
            headers=self.headers("approver-token"),
        )
        self.assertEqual(200, approved.status_code, approved.get_json())
        started = self.client.post(
            "/v1/workflow-actions/run",
            json={
                "plan_id": plan_id,
                "mode": "dry_run",
                "idempotency_key": "role-matrix-run-001",
            },
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, started.status_code, started.get_json())
        run_id = started.get_json()["run"]["run_id"]

        for path in (
            "/v1/workflow-actions/process-dry-run",
            "/v1/workflow-actions/evidence",
        ):
            owner = "operator-token" if path.endswith("process-dry-run") else "auditor-token"
            for token in set(TOKENS) - {owner}:
                with self.subTest(path=path, token=token):
                    response = self.client.post(
                        path,
                        json={"run_id": run_id},
                        headers=self.headers(token),
                    )
                    self.assertEqual(403, response.status_code, response.get_json())
                    self.assertEqual("forbidden", response.get_json()["error"])

        completed = self.client.post(
            "/v1/workflow-actions/process-dry-run",
            json={"run_id": run_id},
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, completed.status_code, completed.get_json())
        for token in TOKENS:
            with self.subTest(path="/v1/workflow-actions/status", token=token):
                response = self.client.post(
                    "/v1/workflow-actions/status",
                    json={"run_id": run_id},
                    headers=self.headers(token),
                )
                self.assertEqual(200, response.status_code, response.get_json())

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

    def test_meraki_plan_accepts_the_native_requirements_json_prompt_value(self):
        response = self.client.post(
            "/v1/workflow-actions/plan",
            json={
                "requirements_json": json.dumps(self.requirements),
                "idempotency_key": "meraki-native-prompt-value-001",
            },
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, response.status_code, response.get_json())
        self.assertEqual("plan_ready", response.get_json()["status"])

    def test_meraki_plan_rejects_non_object_requirements_json(self):
        response = self.client.post(
            "/v1/workflow-actions/plan",
            json={
                "requirements_json": "[\"not\", \"a\", \"requirements object\"]",
                "idempotency_key": "meraki-native-prompt-value-002",
            },
            headers=self.headers("planner-token"),
        )
        self.assertEqual(422, response.status_code, response.get_json())
        self.assertEqual("intent_or_requirements_required", response.get_json()["error"])

    def test_sjc23_guided_poc_form_derives_the_reviewed_profile(self):
        database_path = str(Path(self.temporary_directory.name) / "poc-state.sqlite3")
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_DATABASE_PATH": database_path,
                "ORCHESTRATOR_GUARDRAILS_PATH": str(SJC23_POC_GUARDRAILS),
                "ORCHESTRATOR_EXECUTION_ENABLED": False,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(TOKENS["planner-token"]): {
                        "actor": "meraki-planner", "roles": ["planner"]
                    }
                },
            }
        )
        response = app.test_client().post(
            "/v1/workflow-actions/poc-guided-plan",
            json={
                "form_values": {
                    "fabric_name": "SJC23 recorded POC",
                    "change_reference": "SJC23-POC-001",
                    "corporate_users": "150",
                    "guest_users": "150",
                    "corporate_attachment": "corporate_laptop",
                    "guest_attachment": "guest_laptop",
                    "dhcp_lease_minutes": "60",
                    "dns_profile": "public_google",
                },
                "idempotency_key": "sjc23-guided-poc-plan-0001",
            },
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, response.status_code, response.get_json())
        body = response.get_json()
        self.assertEqual("plan_ready", body["status"])
        self.assertEqual("reserved", body["reservation_state"])
        self.assertGreater(body["allocation_summary"]["network"], 0)

    def test_sjc23_guided_poc_form_rejects_unsafe_or_wrong_policy_input(self):
        payload = {
            "form_values": {
                "fabric_name": "SJC23 recorded POC",
                "change_reference": "SJC23-POC-001",
                "corporate_users": "150",
                "guest_users": "150",
                "corporate_attachment": "corporate_laptop",
                "guest_attachment": "guest_laptop",
                "dhcp_lease_minutes": "60",
                "dns_profile": "public_google",
                "generated_cli": "reload",
            },
            "idempotency_key": "sjc23-guided-poc-plan-0002",
        }
        unsafe = self.client.post(
            "/v1/workflow-actions/poc-guided-plan",
            json=payload,
            headers=self.headers("planner-token"),
        )
        self.assertEqual(422, unsafe.status_code, unsafe.get_json())
        self.assertEqual("poc_guided_intake", unsafe.get_json()["error"])
        self.assertIn("SJC23 POC guardrail", unsafe.get_json()["message"])

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

    def test_meraki_unquoted_fixed_action_tokens_use_field_specific_grammars(self):
        planned = self.client.post(
            "/v1/workflow-actions/plan",
            json={"intent": self.intent},
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, planned.status_code, planned.get_json())
        plan_id = planned.get_json()["plan_id"]

        expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        approval = {
            "plan_id": plan_id,
            "decision": "approved",
            "change_reference": "CHG-MERAKI-UNQUOTED-001",
            "expires_at": expires_at,
        }
        approval_body = json.dumps(approval, separators=(",", ":"))
        for value in approval.values():
            approval_body = approval_body.replace(json.dumps(value), value, 1)
        approved = self.client.post(
            "/v1/workflow-actions/approve",
            data=approval_body,
            headers=self.headers("approver-token"),
        )
        self.assertEqual(200, approved.status_code, approved.get_json())

        run_payload = {
            "plan_id": plan_id,
            "mode": "dry_run",
            "idempotency_key": "meraki-native-unquoted-run-001",
        }
        run_body = json.dumps(run_payload, separators=(",", ":"))
        for value in run_payload.values():
            run_body = run_body.replace(json.dumps(value), value, 1)
        started = self.client.post(
            "/v1/workflow-actions/run",
            data=run_body,
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, started.status_code, started.get_json())
        run_id = started.get_json()["run"]["run_id"]

        for path, token in (
            ("/v1/workflow-actions/process-dry-run", "operator-token"),
            ("/v1/workflow-actions/status", "operator-token"),
            ("/v1/workflow-actions/evidence", "auditor-token"),
        ):
            with self.subTest(path=path):
                response = self.client.post(
                    path,
                    data='{"run_id":' + run_id + "}",
                    headers=self.headers(token),
                )
                self.assertEqual(200, response.status_code, response.get_json())

        unsafe = self.client.post(
            "/v1/workflow-actions/run",
            data=(
                '{"plan_id":plan_../../etc/passwd,"mode":dry_run,'
                '"idempotency_key":meraki-native-unquoted-run-002}'
            ),
            headers=self.headers("operator-token"),
        )
        self.assertEqual(400, unsafe.status_code)
        self.assertEqual("body", unsafe.get_json()["error"])

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

        decoded_twice = self.client.post(
            "/v1/workflow-actions/plan",
            data=json.dumps(json.dumps(json.dumps({"intent": self.intent}))),
            headers=self.headers("planner-token"),
        )
        self.assertEqual(400, decoded_twice.status_code)
        self.assertEqual("body", decoded_twice.get_json()["error"])

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
        self.assertEqual("dry_run_succeeded", processed.get_json()["run"]["status"])
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
        self.assertEqual("dry_run_succeeded", status.get_json()["status"])

        evidence = self.client.post(
            "/v1/workflow-actions/evidence",
            json={"run_id": run_id},
            headers=self.headers("auditor-token"),
        )
        self.assertEqual(200, evidence.status_code, evidence.get_json())
        body = evidence.get_json()
        self.assertTrue(body["chain_valid"])
        self.assertFalse(body["contains_secret_values"])
        self.assertFalse(body["contains_raw_configuration"])
        self.assertTrue(body["evidence"])
        self.assertTrue(body["audit"])
        self.assertEqual(
            {"evidence_id", "phase_id", "evidence_type", "payload_hash", "created_at"},
            set(body["evidence"][0]),
        )
        self.assertEqual(
            {"sequence", "event_type", "event_hash", "previous_hash", "created_at"},
            set(body["audit"][0]),
        )
        self.assertNotIn('"payload":', json.dumps(body, sort_keys=True))
        self.assertNotIn("command_count", json.dumps(body, sort_keys=True))

    def test_string_encoded_meraki_action_contract(self):
        def encoded(document):
            return json.dumps(json.dumps(document))

        planned = self.client.post(
            "/v1/workflow-actions/plan",
            data=encoded({"intent": self.intent}),
            headers=self.headers("planner-token"),
        )
        self.assertEqual(200, planned.status_code, planned.get_json())
        plan_id = planned.get_json()["plan_id"]

        approved = self.client.post(
            "/v1/workflow-actions/approve",
            data=encoded(
                {
                    "plan_id": plan_id,
                    "decision": "approved",
                    "change_reference": "CHG-MERAKI-STRING-001",
                    "expires_at": (
                        datetime.now(timezone.utc) + timedelta(hours=1)
                    ).isoformat(),
                }
            ),
            headers=self.headers("approver-token"),
        )
        self.assertEqual(200, approved.status_code, approved.get_json())

        started = self.client.post(
            "/v1/workflow-actions/run",
            data=encoded(
                {
                    "plan_id": plan_id,
                    "mode": "dry_run",
                    "idempotency_key": "fixed-meraki-string-action-0001",
                }
            ),
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, started.status_code, started.get_json())
        run_id = started.get_json()["run"]["run_id"]

        processed = self.client.post(
            "/v1/workflow-actions/process-dry-run",
            data=encoded({"run_id": run_id}),
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, processed.status_code, processed.get_json())

        status = self.client.post(
            "/v1/workflow-actions/status",
            data=encoded({"run_id": run_id}),
            headers=self.headers("operator-token"),
        )
        self.assertEqual(200, status.status_code, status.get_json())
        self.assertEqual("dry_run_succeeded", status.get_json()["status"])

        evidence = self.client.post(
            "/v1/workflow-actions/evidence",
            data=encoded({"run_id": run_id}),
            headers=self.headers("auditor-token"),
        )
        self.assertEqual(200, evidence.status_code, evidence.get_json())
        self.assertTrue(evidence.get_json()["chain_valid"])


if __name__ == "__main__":
    unittest.main()
