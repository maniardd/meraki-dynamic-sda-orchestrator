from __future__ import annotations

import unittest

from orchestrator.worker_runtime import WorkerRuntimeError, process_run


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


if __name__ == "__main__":
    unittest.main()
