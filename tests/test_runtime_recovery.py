from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from orchestrator.runtime_recovery import (
    RuntimeRecoveryInspectionError,
    build_recovery_report,
)


class RuntimeRecoveryInspectionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 7, 23, 18, 30, tzinfo=timezone.utc)
        self.lock = {
            "fabric_id": "fabric-private",
            "run_id": "run-private",
            "status": "apply_running",
            "acquired_at": self.now - timedelta(minutes=5),
            "expires_at": self.now + timedelta(minutes=25),
            "updated_at": self.now - timedelta(seconds=20),
        }

    def test_clean_report_hashes_identifiers_and_never_allows_takeover(self):
        report = build_recovery_report(
            [self.lock],
            [{"mode": "apply", "status": "apply_running", "count": 1}],
            self.now,
        )
        rendered = str(report)
        self.assertTrue(report["safe"])
        self.assertFalse(report["unattended_takeover_allowed"])
        self.assertFalse(report["automatic_lock_release_allowed"])
        self.assertNotIn("fabric-private", rendered)
        self.assertNotIn("run-private", rendered)
        self.assertEqual(64, len(report["locks"][0]["run_id_hash"]))

    def test_expired_lock_fails_closed_for_manual_recovery(self):
        candidate = copy.deepcopy(self.lock)
        candidate["expires_at"] = self.now - timedelta(seconds=1)
        report = build_recovery_report([candidate], [], self.now)
        self.assertFalse(report["safe"])
        self.assertEqual(1, report["expired_lock_count"])
        self.assertIn(
            "fabric_lock.expired_manual_recovery_required",
            {item["code"] for item in report["issues"]},
        )

    def test_terminal_status_and_invalid_window_fail_closed(self):
        candidate = copy.deepcopy(self.lock)
        candidate["status"] = "apply_succeeded"
        candidate["expires_at"] = candidate["acquired_at"]
        report = build_recovery_report([candidate], [], self.now)
        self.assertFalse(report["safe"])
        self.assertEqual(
            {
                "fabric_lock.expired_manual_recovery_required",
                "fabric_lock.invalid_lease_window",
                "fabric_lock.invalid_run_status",
            },
            {item["code"] for item in report["issues"]},
        )

    def test_naive_timestamp_and_invalid_count_are_rejected(self):
        candidate = copy.deepcopy(self.lock)
        candidate["updated_at"] = datetime(2026, 7, 23, 18, 30)
        with self.assertRaisesRegex(
            RuntimeRecoveryInspectionError, "timezone-aware"
        ):
            build_recovery_report([candidate], [], self.now)
        with self.assertRaisesRegex(RuntimeRecoveryInspectionError, "count"):
            build_recovery_report(
                [],
                [{"mode": "apply", "status": "apply_running", "count": True}],
                self.now,
            )

    def test_direct_tool_invocation_loads_package_and_fails_structurally(self):
        root = Path(__file__).resolve().parents[1]
        environment = dict(os.environ)
        environment["ORCHESTRATOR_DATABASE_URL"] = "unsupported://database"
        result = subprocess.run(
            [sys.executable, str(root / "tools" / "inspect_runtime_recovery.py")],
            cwd=str(root.parent),
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(2, result.returncode)
        payload = json.loads(result.stdout)
        self.assertEqual("RuntimeRecoveryInspectionError", payload["error_type"])
        self.assertFalse(payload["safe"])
        self.assertNotIn("ModuleNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main()
