from __future__ import annotations

import copy
import hashlib
import unittest
from pathlib import Path

import yaml

from orchestrator.allocator import derive_fabric_intent
from orchestrator.planner import create_plan
from orchestrator.renderer import render_configuration
from orchestrator.worker_runtime import (
    WorkerRuntimeError,
    _sjc23_poc_authorization,
    process_run,
)


ROOT = Path(__file__).resolve().parents[1]
POC_POLICY_PATH = ROOT / "policy" / "guardrails.sjc23-poc.yaml"
POC_POLICY = yaml.safe_load(POC_POLICY_PATH.read_text(encoding="utf-8"))
POC_REQUIREMENTS = yaml.safe_load(
    (ROOT / "examples" / "fabric-requirements.sjc23-poc.yaml").read_text(encoding="utf-8")
)


def _poc_candidate():
    intent = derive_fabric_intent(copy.deepcopy(POC_REQUIREMENTS), POC_POLICY)["intent"]
    plan = create_plan(intent)
    return intent, plan, render_configuration(intent, plan)


class WorkerRuntimeTests(unittest.TestCase):
    def test_worker_refuses_when_api_execution_is_disabled(self):
        with self.assertRaisesRegex(WorkerRuntimeError, "API execution"):
            process_run(
                "run-example",
                {
                    "ORCHESTRATOR_EXECUTION_ENABLED": "false",
                    "ORCHESTRATOR_WORKER_ENABLED": "true",
                },
            )

    def test_worker_requires_independent_enablement(self):
        with self.assertRaisesRegex(WorkerRuntimeError, "Worker enablement"):
            process_run(
                "run-example",
                {
                    "ORCHESTRATOR_EXECUTION_ENABLED": "true",
                    "ORCHESTRATOR_WORKER_ENABLED": "false",
                },
            )

    def test_worker_requires_an_explicit_database(self):
        with self.assertRaisesRegex(WorkerRuntimeError, "database location"):
            process_run(
                "run-example",
                {
                    "ORCHESTRATOR_EXECUTION_ENABLED": "true",
                    "ORCHESTRATOR_WORKER_ENABLED": "true",
                },
            )

    def test_sjc23_poc_authorization_is_disabled_without_its_third_flag(self):
        intent, plan, artifact = _poc_candidate()
        self.assertEqual(
            {"allowed_blocker_codes": []},
            _sjc23_poc_authorization({}, intent, plan, artifact),
        )

    def test_sjc23_poc_authorization_requires_hash_bound_policy_and_artifact(self):
        intent, plan, artifact = _poc_candidate()
        environment = {
            "ORCHESTRATOR_SJC23_POC_EXECUTION_ENABLED": "true",
            "ORCHESTRATOR_GUARDRAILS_PATH": str(POC_POLICY_PATH),
            "ORCHESTRATOR_SJC23_POC_GUARDRAILS_SHA256": hashlib.sha256(
                POC_POLICY_PATH.read_bytes()
            ).hexdigest(),
            "ORCHESTRATOR_SJC23_POC_CHANGE_REFERENCE": "SJC23-POC-001",
            "ORCHESTRATOR_SJC23_POC_PLAN_HASH": plan["plan_hash"],
            "ORCHESTRATOR_SJC23_POC_ARTIFACT_HASH": artifact["artifact_hash"],
        }
        authorization = _sjc23_poc_authorization(environment, intent, plan, artifact)
        self.assertEqual(
            ["poc.local_dhcp_and_attachment_hardware_acceptance_pending"],
            authorization["allowed_blocker_codes"],
        )

        wrong_policy = dict(environment, ORCHESTRATOR_SJC23_POC_GUARDRAILS_SHA256="0" * 64)
        with self.assertRaisesRegex(WorkerRuntimeError, "guardrails hash"):
            _sjc23_poc_authorization(wrong_policy, intent, plan, artifact)

        wrong_artifact = dict(environment, ORCHESTRATOR_SJC23_POC_ARTIFACT_HASH="0" * 64)
        with self.assertRaisesRegex(WorkerRuntimeError, "authorization was rejected"):
            _sjc23_poc_authorization(wrong_artifact, intent, plan, artifact)


if __name__ == "__main__":
    unittest.main()
