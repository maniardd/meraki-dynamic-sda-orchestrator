from __future__ import annotations

import copy
import unittest
from pathlib import Path

from orchestrator.api import create_app
from orchestrator.intent import load_intent


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "fabric-intent.lab.yaml"


class OrchestratorApiTests(unittest.TestCase):
    def setUp(self):
        self.intent = load_intent(EXAMPLE)
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_API_TOKEN": "test-token",
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        self.client = app.test_client()
        self.headers = {
            "Authorization": "Bearer test-token",
            "Content-Type": "application/json",
        }

    def test_health_is_public_and_execution_is_disabled(self):
        response = self.client.get("/health")
        self.assertEqual(200, response.status_code)
        self.assertFalse(response.get_json()["execution_enabled"])

    def test_readiness_proves_auth_guardrails_database_and_audit(self):
        response = self.client.get("/ready")
        self.assertEqual(200, response.status_code, response.get_json())
        body = response.get_json()
        self.assertEqual("ready", body["status"])
        self.assertTrue(body["checks"]["authentication"])
        self.assertTrue(body["checks"]["guardrails"])
        self.assertTrue(body["checks"]["database"])
        self.assertTrue(body["checks"]["audit_chain"])
        self.assertEqual("sqlite", body["checks"]["backend"])

    def test_readiness_fails_closed_without_authentication_configuration(self):
        app = create_app(
            {
                "TESTING": True,
                "ORCHESTRATOR_API_TOKEN": "",
                "ORCHESTRATOR_TOKEN_IDENTITIES": {},
                "ORCHESTRATOR_DATABASE_PATH": ":memory:",
            }
        )
        response = app.test_client().get("/ready")
        self.assertEqual(503, response.status_code)
        self.assertFalse(response.get_json()["checks"]["authentication"])

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


if __name__ == "__main__":
    unittest.main()
