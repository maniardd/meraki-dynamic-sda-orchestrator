from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BACKUP = ROOT / "admin" / "backup_postgresql.sh"
RESTORE = ROOT / "admin" / "verify_postgresql_restore.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "postgres_backup_restore_acceptance.yml"
DEPLOY_WORKFLOW = ROOT / ".github" / "workflows" / "deploy_orchestrator_api.yml"


class PostgreSqlBackupRestoreTests(unittest.TestCase):
    def test_backup_is_private_bounded_and_catalog_verified(self):
        rendered = BACKUP.read_text(encoding="utf-8")
        self.assertIn("run_as_runtime_user_not_root", rendered)
        self.assertIn("unsupported_database_url", rendered)
        self.assertIn("runtime_home_mismatch", rendered)
        self.assertIn("backup_root_symlinked", rendered)
        self.assertIn("SDA_BACKUP_RETENTION_COUNT:-14", rendered)
        self.assertIn("invalid_retention_count", rendered)
        self.assertIn("install -d -m 0700", rendered)
        self.assertIn("chmod 0600", rendered)
        self.assertIn("--format=custom", rendered)
        self.assertIn("--no-owner", rendered)
        self.assertIn("--no-privileges", rendered)
        self.assertIn("archive_missing_required_table", rendered)
        self.assertIn("sha256sum", rendered)
        self.assertIn("unsafe_retention_candidate", rendered)
        self.assertNotIn("pg_dumpall", rendered)
        self.assertNotIn("ORCHESTRATOR_EXECUTION_ENABLED=true", rendered)

    def test_restore_is_checksum_bound_and_disposable_only(self):
        rendered = RESTORE.read_text(encoding="utf-8")
        self.assertIn("backup_outside_managed_root", rendered)
        self.assertIn("backup_symlink_forbidden", rendered)
        self.assertIn("checksum_symlink_forbidden", rendered)
        self.assertIn("checksum_name_mismatch", rendered)
        self.assertIn("checksum_mismatch", rendered)
        self.assertIn('[ "${checksum_name}" = "${archive_name}" ]', rendered)
        self.assertIn('scratch_database="sda_restore_verify"', rendered)
        self.assertIn("listen_addresses=''", rendered)
        self.assertIn("--auth-host=reject", rendered)
        self.assertIn("scratch_cluster_initialize_failed", rendered)
        self.assertIn("scratch_cluster_stop_failed", rendered)
        self.assertIn("--exit-on-error", rendered)
        self.assertIn("restored_schema_incomplete", rendered)
        self.assertIn("restored_audit_hash_invalid", rendered)
        self.assertIn("pg_ctl", rendered)
        self.assertNotIn("ALTER ROLE", rendered)
        self.assertNotIn("CREATEDB", rendered)
        self.assertNotIn('dropdb -- "sda_orchestrator"', rendered)
        self.assertNotIn('--dbname="sda_orchestrator"', rendered)

    def test_acceptance_workflow_is_manual_private_and_device_free(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        triggers = document.get("on", document.get(True, {}))
        self.assertEqual({"workflow_dispatch": None}, triggers)
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertIn("runs-on: [self-hosted, sda-relay]", text)
        self.assertIn("backup_postgresql.sh", text)
        self.assertIn("verify_postgresql_restore.sh", text)
        for forbidden in (
            "actions/checkout",
            "upload-artifact",
            "secrets.",
            "netmiko",
            "SDA_BORDER_HOST",
            "SDA_EDGE_HOST",
            "send_config",
            "systemctl restart",
        ):
            self.assertNotIn(forbidden, text)

    def test_existing_deploy_workflow_has_explicit_default_off_recovery_gate(self):
        text = DEPLOY_WORKFLOW.read_text(encoding="utf-8")
        document = yaml.safe_load(text)
        triggers = document.get("on", document.get(True, {}))
        dispatch = triggers["workflow_dispatch"]
        recovery_input = dispatch["inputs"]["verify_postgres_recovery"]
        self.assertEqual(False, recovery_input["default"])
        self.assertEqual("boolean", recovery_input["type"])
        inspection_input = dispatch["inputs"]["inspect_runtime_recovery"]
        self.assertEqual(False, inspection_input["default"])
        self.assertEqual("boolean", inspection_input["type"])
        self.assertIn("if: ${{ inputs.verify_postgres_recovery }}", text)
        self.assertIn("if: ${{ inputs.inspect_runtime_recovery }}", text)
        self.assertIn("backup_postgresql.sh", text)
        self.assertIn("verify_postgresql_restore.sh", text)
        self.assertIn("tools/inspect_runtime_recovery.py", text)
        self.assertNotIn("ORCHESTRATOR_EXECUTION_ENABLED=true", text)


if __name__ == "__main__":
    unittest.main()
