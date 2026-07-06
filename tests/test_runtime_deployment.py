from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / "deploy" / "systemd" / "sda-orchestrator-api.service"
GUNICORN = ROOT / "deploy" / "gunicorn.conf.py"
ENVIRONMENT = ROOT / "deploy" / "api.env.example"
WORKER_UNIT = ROOT / "deploy" / "systemd" / "sda-orchestrator-worker@.service"
WORKER_ENVIRONMENT = ROOT / "deploy" / "worker.env.example"


class RuntimeDeploymentContractTests(unittest.TestCase):
    def test_service_uses_gunicorn_user_paths_and_hardening(self):
        rendered = UNIT.read_text(encoding="utf-8")
        self.assertIn("/.venv/bin/gunicorn", rendered)
        self.assertIn("EnvironmentFile=%h/.config/sda-orchestrator/api.env", rendered)
        self.assertIn("NoNewPrivileges=true", rendered)
        self.assertIn("ProtectSystem=strict", rendered)
        self.assertIn("UMask=0077", rendered)
        self.assertNotIn("User=root", rendered)
        self.assertNotIn("sudo", rendered)

    def test_wsgi_defaults_are_loopback_bounded(self):
        rendered = GUNICORN.read_text(encoding="utf-8")
        self.assertIn('"127.0.0.1:8080"', rendered)
        self.assertIn('worker_class = "gthread"', rendered)
        self.assertIn('forwarded_allow_ips = ""', rendered)

    def test_runtime_example_keeps_apply_disabled_and_has_no_secret_values(self):
        rendered = ENVIRONMENT.read_text(encoding="utf-8")
        self.assertIn("ORCHESTRATOR_EXECUTION_ENABLED=false", rendered)
        self.assertIn("PGPASSFILE=", rendered)
        self.assertNotIn("password=", rendered.lower())
        self.assertNotIn("inline-private-marker", rendered)

    def test_worker_is_a_separate_oneshot_with_double_enablement_off(self):
        unit = WORKER_UNIT.read_text(encoding="utf-8")
        environment = WORKER_ENVIRONMENT.read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("orchestrator.worker_runtime --run-id %i", unit)
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("ORCHESTRATOR_EXECUTION_ENABLED=false", environment)
        self.assertIn("ORCHESTRATOR_WORKER_ENABLED=false", environment)
        self.assertNotIn("password=", environment.lower())


if __name__ == "__main__":
    unittest.main()
