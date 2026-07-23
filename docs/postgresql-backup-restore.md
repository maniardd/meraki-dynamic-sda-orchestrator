# PostgreSQL backup and restore verification

The SDA orchestrator stores intent, allocations, approvals, runs, evidence,
audit events, and owned-state manifests in PostgreSQL. A production recovery
claim therefore requires a verified database backup, not only a copied
configuration directory.

## Backup contract

`admin/backup_postgresql.sh` runs as the unprivileged orchestrator runtime
user and supports only the locally peer-authenticated `sda_orchestrator`
database. It:

- refuses root execution and alternate database URLs;
- writes only beneath
  `~/.local/share/sda-orchestrator/backups`;
- enforces mode `0700` on the backup directory and mode `0600` on files;
- uses PostgreSQL custom format without ownership or privilege statements;
- checks the archive catalog and all eleven required application tables;
- writes a SHA-256 checksum and secret-free metadata; and
- retains 14 backup sets by default, with a bounded range of 1-365.

The backup contains sensitive network intent and operational evidence. Do not
upload it to GitHub Actions, commit it, paste it into chat, or copy it to an
unapproved destination. Production still requires an approved encrypted
off-host repository and separately tested retention policy.

## Restore verification contract

`admin/verify_postgresql_restore.sh` accepts only a managed backup filename
under the private backup root. It verifies the checksum and archive catalog,
creates a uniquely named disposable database, restores into that database,
checks all required tables and basic audit-hash integrity, records the elapsed
restore time, and drops the disposable database on success or failure.

It never targets or drops `sda_orchestrator`. The production database remains
read-only throughout backup and verification. The peer-authenticated runtime
database role must be permitted to create and drop the disposable verification
database. If it is not, verification fails before restore; do not grant a broad
role change merely to bypass that failure. Provision the narrow recovery
operator control through the reviewed platform baseline.

## Controlled acceptance

After a reviewed release containing both scripts is deployed, manually run
the `SDA PostgreSQL Backup Restore Acceptance` workflow. The workflow uses the
installed immutable release on the private Ubuntu runner. It receives no
credentials, checks out no repository content, uploads no database artifact,
and contacts no network device.

Passing the workflow proves local backup and disposable restore for that host.
It does not by itself close the production gate: encrypted off-host copy,
retention enforcement, recovery objectives, operator access, alerting, and a
second-host recovery exercise remain required.
