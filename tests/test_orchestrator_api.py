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

    def test_v1_requires_authentication(self):
        response = self.client.post("/v1/intents/validate", json=self.intent)
        self.assertEqual(401, response.status_code)

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
