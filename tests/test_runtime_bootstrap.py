from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "admin" / "stage_api_release.sh"
INSTALL = ROOT / "admin" / "install_api_service.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "deploy_orchestrator_api.yml"
VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "validate_foundation.yml"


class RuntimeBootstrapTests(unittest.TestCase):
    def test_release_staging_is_immutable_tested_and_atomic(self):
        rendered = STAGE.read_text(encoding="utf-8")
        self.assertIn("release_id_must_be_full_commit_sha", rendered)
        self.assertIn("python3 -m venv", rendered)
        self.assertIn("-m unittest discover -s tests -q", rendered)
        self.assertIn(".release-commit", rendered)
        self.assertIn('mv -Tf -- "${temporary_link}" "${current_link}"', rendered)
        self.assertIn("previous_release", rendered)
        self.assertIn("rollback_link", rendered)
        self.assertIn("service_health_not_200", rendered)
        self.assertIn("for _ in $(seq 1 30); do", rendered)
        self.assertIn("--max-time 3 http://127.0.0.1:8080/health", rendered)
        self.assertNotIn("--max-time 10 http://127.0.0.1:8080/health", rendered)
        self.assertNotIn("git reset", rendered)
        self.assertNotIn("git clean", rendered)

    def test_install_is_loopback_only_hashed_and_apply_disabled(self):
        rendered = INSTALL.read_text(encoding="utf-8")
        self.assertIn("ORCHESTRATOR_BIND=127.0.0.1:8080", rendered)
        self.assertIn("ORCHESTRATOR_EXECUTION_ENABLED=false", rendered)
        self.assertIn("tools/create_api_identity.py", rendered)
        self.assertIn("token-identities.json", rendered)
        self.assertIn("ProtectSystem=strict", rendered)
        self.assertIn("ProtectHome=read-only", rendered)
        self.assertIn("NoNewPrivileges=true", rendered)
        self.assertIn("postgresql_peer_readiness_failed", rendered)
        self.assertIn("require_single_setting", rendered)
        self.assertIn("duplicate_or_missing_", rendered)
        self.assertNotIn("ORCHESTRATOR_EXECUTION_ENABLED=true", rendered)
        self.assertNotIn("password=", rendered.lower())

    def test_installer_never_prints_the_bootstrap_token(self):
        rendered = INSTALL.read_text(encoding="utf-8")
        self.assertIn('unset planner_token', rendered)
        self.assertIn("planner_token_file=%s", rendered)
        self.assertNotIn("planner_token=%s", rendered)
        self.assertNotIn('printf \'%s\\n\' "${planner_token}" >&2', rendered)

    def test_deployment_workflow_has_no_secrets_or_artifact_upload(self):
        workflow_text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("permissions:\n  contents: read", workflow_text)
        self.assertIn("runs-on: [self-hosted, sda-relay]", workflow_text)
        self.assertIn("admin/stage_api_release.sh", workflow_text)
        self.assertNotIn("secrets.", workflow_text)
        self.assertNotIn("upload-artifact", workflow_text)
        self.assertNotIn("SDA_BORDER_HOST", workflow_text)
        self.assertNotIn("SDA_EDGE_HOST", workflow_text)

    def test_ci_validates_runtime_shell_syntax(self):
        workflow_text = VALIDATION_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("bash -n admin/*.sh", workflow_text)


if __name__ == "__main__":
    unittest.main()
