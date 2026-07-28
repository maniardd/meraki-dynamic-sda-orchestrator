from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGE = ROOT / "admin" / "stage_api_release.sh"
INSTALL = ROOT / "admin" / "install_api_service.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "deploy_orchestrator_api.yml"
VALIDATION_WORKFLOW = ROOT / ".github" / "workflows" / "validate_foundation.yml"
ROLE_WORKFLOW = (
    ROOT / ".github" / "workflows" / "provision_meraki_role_identities.yml"
)
ACCOUNT_KEY_WORKFLOW = (
    ROOT / ".github" / "workflows" / "generate_meraki_account_key_tokens.yml"
)


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
        self.assertIn(
            "ExecStart=${current_path}/.venv/bin/python -m gunicorn",
            rendered,
        )
        self.assertNotIn(
            "ExecStart=${current_path}/.venv/bin/gunicorn",
            rendered,
        )
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

    def test_role_provisioning_uses_the_installed_runtime_environment(self):
        workflow_text = ROLE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(
            "RUNTIME_PYTHON: /home/sdaadmin/sda-orchestrator/current/.venv/bin/python",
            workflow_text,
        )
        self.assertIn('test -x "${RUNTIME_PYTHON}"', workflow_text)
        self.assertIn(
            '"${RUNTIME_PYTHON}" admin/provision_meraki_role_identities.py',
            workflow_text,
        )
        self.assertNotIn(
            "\n          python3 admin/provision_meraki_role_identities.py",
            workflow_text,
        )

    def test_one_time_account_key_bootstrap_never_logs_or_uploads_tokens(self):
        workflow_text = ACCOUNT_KEY_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("GENERATE_FRESH_MERAKI_ACCOUNT_KEYS", workflow_text)
        self.assertIn("test ! -e \"${ONE_TIME_FILE}\"", workflow_text)
        self.assertIn("/home/sdaadmin/.local/share/sda-orchestrator/meraki-account-keys.once.json", workflow_text)
        self.assertIn("admin/generate_meraki_account_key_tokens.py", workflow_text)
        self.assertIn("rollback_identity_store", workflow_text)
        self.assertIn("--restore-from \"${IDENTITY_BACKUP}\"", workflow_text)
        self.assertIn("handoff_verification_failed=restoring_previous_hashed_identities", workflow_text)
        self.assertIn("sleep 5", workflow_text)
        self.assertGreaterEqual(workflow_text.count("test -f \"${ONE_TIME_FILE}\""), 2)
        self.assertIn("stat -c '%a' \"${ONE_TIME_FILE}\"", workflow_text)
        self.assertIn("sudo systemctl restart sda-orchestrator-api.service", workflow_text)
        self.assertIn("execution_enabled\"] is False", workflow_text)
        self.assertNotIn("secrets.", workflow_text)
        self.assertNotIn("upload-artifact", workflow_text)


if __name__ == "__main__":
    unittest.main()
