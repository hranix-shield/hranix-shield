"""A-12: backups — restic-backed snapshot/restore for the Phase 0 SQLite file.

Public surface re-exported here for callers (router, app_factory, tests):
  - restic_client: thin async wrapper over the `restic` CLI (init/backup/
    snapshots/restore), parameterized — no Settings/global state inside it.
  - integrity: SQLite-file structural soundness check (PRAGMA integrity_check),
    independent of restic's own `restic check`.
  - service: orchestration — resolves Settings into concrete paths, persists
    `BackupJob` rows, publishes `Topic.BACKUP_STATUS`.
  - scheduler: the daily-04:00 automatic-run background task.
"""

from app.services.backup.integrity import check_integrity
from app.services.backup.restic_client import ResticError
from app.services.backup.scheduler import BackupScheduler
from app.services.backup.service import (
    BACKUP_MODULE_ID,
    resolve_backup_password_file,
    run_backup,
    run_restore,
)
from app.services.backup.wiring import (
    backup_connector_status,
    backup_console_metrics,
    create_default_scheduler,
    run_manual_backup,
    run_manual_restore,
    run_startup_integrity_check,
)

__all__ = [
    "BACKUP_MODULE_ID",
    "BackupScheduler",
    "ResticError",
    "backup_connector_status",
    "backup_console_metrics",
    "check_integrity",
    "create_default_scheduler",
    "resolve_backup_password_file",
    "run_backup",
    "run_manual_backup",
    "run_manual_restore",
    "run_restore",
    "run_startup_integrity_check",
]
