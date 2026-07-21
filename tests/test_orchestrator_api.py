from __future__ import annotations

import copy
import unittest
from pathlib import Path

from orchestrator.api import create_app
from orchestrator.auth import token_sha256
from orchestrator.intent import load_intent
from orchestrator.reconciliation import build_multicast_owned_state


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"


class OrchestratorApiTests(unittest.TestCase):
    def setUp(self):
        self.intent = load_intent(EXAMPLE)
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256("test-token-value-with-required-length"): {
                        "actor": "test-planner",
                        "roles": ["viewer", "planner"],
                    }
                },
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        self.client = app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token-value-with-required-length",
            "Content-Type": "application/json",
        }

    def test_health_is_public_and_execution_is_disabled(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        self.assertFalse(response.get_json()["execution_enabled"])

    def test_readiness_proves_auth_guardrails_database_and_audit(self):
        response = self.client.get("/ready", headers=self.headers)
        self.assertEqual(200, response.status_code, response.get_json())
        body = response.get_json()
        self.assertEqual("ready", body["status"])
        self.assertTrue(body["checks"]["authentication"])
        self.assertTrue(body["checks"]["guardrails"])
        self.assertTrue(body["checks"]["database"])
        self.assertTrue(body["checks"]["audit_chain"])
        self.assertEqual("sqlite", body["checks"]["backend"])

    def test_readiness_requires_authentication(self):
        response = self.client.get("/ready")
        self.assertEqual(401, response.status_code)
        self.assertEqual("no-store", response.headers["Cache-Control"])

    def test_readiness_fails_closed_without_authentication_configuration(self):
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {},
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        response = app.test_client().get(
            "/ready",
            headers={"Authorization": "Bearer " + ("x" * 32)},
        )
        self.assertEqual(503, response.status_code)
        self.assertEqual("service_not_configured", response.get_json()["error"])

    def test_v1_requires_authentication(self):
        response = self.client.post("/v1/intents/validate", json=self.intent)
        self.assertEqual(401, response.status_code)
        self.assertEqual("no-store", response.headers["Cache-Control"])
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
        self.assertTrue(response.headers["X-Request-ID"].startswith("req_"))

    def test_valid_caller_request_id_is_preserved(self):
        response = self.client.post(
            "/v1/intents/validate",
            json=self.intent,
            headers={**self.headers, "X-Request-ID": "meraki-workflow-0001"},
        )
        self.assertEqual("meraki-workflow-0001", response.headers["X-Request-ID"])

    def test_valid_intent_returns_success(self):
        response = self.client.post(
            "/v1/intents/validate",
            json=self.intent,
            headers=self.headers,
        )
        self.assertEqual(200, response.status_code)
        self.assertTrue(response.get_json()["valid"])

    def test_hashed_production_identity_authenticates_readiness(self):
        token = "phase3-api-integration-token-value-0001"
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(token): {
                        "actor": "runtime-auditor",
                        "roles": ["auditor"],
                    }
                },
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        client = app.test_client()
        response = client.get(
            "/ready", headers={"Authorization": "Bearer " + token}
        )
        self.assertEqual(200, response.status_code, response.get_json())
        rejected = client.get(
            "/ready",
            headers={"Authorization": "Bearer phase3-api-integration-token-value-9999"},
        )
        self.assertEqual(401, rejected.status_code)

    def test_invalid_intent_returns_422(self):
        candidate = copy.deepcopy(self.intent)
        candidate["devices"][1]["loopback0_ip"] = candidate["devices"][0]["loopback0_ip"]
        response = self.client.post(
            "/v1/intents/validate",
            json=candidate,
            headers=self.headers,
        )
        self.assertEqual(422, response.status_code)
        self.assertFalse(response.get_json()["valid"])

    def test_plan_is_deterministic_and_non_executable(self):
        first = self.client.post("/v1/plans", json=self.intent, headers=self.headers)
        second = self.client.post("/v1/plans", json=self.intent, headers=self.headers)
        self.assertEqual(201, first.status_code)
        self.assertEqual(201, second.status_code)
        first_plan = first.get_json()
        second_plan = second.get_json()
        self.assertEqual(first_plan["plan_id"], second_plan["plan_id"])
        self.assertEqual(first_plan["plan_hash"], second_plan["plan_hash"])
        self.assertFalse(first_plan["safety"]["executable"])
        self.assertTrue(first_plan["safety"]["requires_approval"])

    def test_approver_can_adopt_a_dual_control_owned_state_baseline(self):
        token = "owned-state-approver-token-value-0001"
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_TOKEN_HASH_IDENTITIES": {
                    token_sha256(token): {
                        "actor": "baseline-approver",
                        "roles": ["approver", "planner", "viewer"],
                    }
                },
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        client = app.test_client()
        headers = {
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
        }
        manifest = build_multicast_owned_state(self.intent)
        response = client.post(
            "/v1/fabrics/{}/owned-state-baselines".format(
                self.intent["fabric"]["id"]
            ),
            headers=headers,
            json={
                "manifest": manifest,
                "evidence_hash": "d" * 64,
                "change_reference": "CHG-BASELINE-API",
                "discovered_by": "discovery-operator",
            },
        )
        self.assertEqual(201, response.status_code, response.get_json())
        self.assertEqual("adopted_discovery", response.get_json()["source_type"])
        fetched = client.get(
            "/v1/fabrics/{}/owned-state-baseline".format(
                self.intent["fabric"]["id"]
            ),
            headers=headers,
        )
        self.assertEqual(200, fetched.status_code, fetched.get_json())
        self.assertEqual(
            manifest["manifest_hash"], fetched.get_json()["manifest_hash"]
        )
        workflow_fetched = client.post(
            "/v1/workflow-actions/owned-state-baseline",
            headers=headers,
            json={"fabric_id": self.intent["fabric"]["id"]},
        )
        self.assertEqual(200, workflow_fetched.status_code)
        self.assertEqual("available", workflow_fetched.get_json()["status"])
        planned = client.post("/v1/plans", headers=headers, json=self.intent)
        self.assertEqual(201, planned.status_code, planned.get_json())
        self.assertEqual(
            response.get_json()["baseline_hash"],
            planned.get_json()["reconciliation_baseline"]["baseline_hash"],
        )


if __name__ == "__main__":
    unittest.main()
