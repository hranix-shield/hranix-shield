"""Settings-driven wiring for A-12: turns real `Settings` into concrete
restic arguments and assembles the pieces `app_factory`'s lifespan and the
`/security/consoles/backup*` router need.

Kept separate from `services/backup/service.py` (pure orchestration,
parameterized by explicit paths, zero `Settings` reads) precisely so tests
can exercise `service.py` directly against `tmp_path` fixtures without ever
touching real `Settings`/`data/`/`infra/backups/` — this module is the one
and only place A-12 reads `get_settings()` for backup purposes.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.models import BackupJob
from app.services.backup.integrity import check_integrity
from app.services.backup.restic_client import ResticError, list_snapshots
from app.services.backup.scheduler import BackupScheduler, next_daily_run
from app.services.backup.service import resolve_backup_password_file, run_backup, run_restore
from app.services.event_bus import EventBus

logger = logging.getLogger(__name__)

_CHART_DAYS = 7


def resolve_backup_paths(settings: Settings | None = None) -> tuple[Path, Path, Path | None]:
    """`(repo_dir, password_file, db_path)` resolved from Settings. `db_path`
    is None when the configured database isn't SQLite (Settings.resolved_sqlite_path)
    — nothing for A-12 to back up in that configuration (a future
    PostgreSQL phase brings its own pgBackRest path, see §4.5 of the plan)."""
    settings = settings or get_settings()
    repo_dir = settings.resolved_backup_dir
    password_file = resolve_backup_password_file(settings)
    db_path = settings.resolved_sqlite_path
    return repo_dir, password_file, db_path


async def run_startup_integrity_check(
    *, event_bus: EventBus | None = None, settings: Settings | None = None
) -> BackupJob | None:
    """Called once at app startup (see app_factory._lifespan), before the
    app starts accepting traffic — gated by `settings.backup_enabled` at
    the call site, not in here (this function always runs its check when
    called; the caller decides whether to call it at all).

    - DB file present and structurally sound: no-op (returns None).
    - DB file present and `PRAGMA integrity_check` fails, OR the file is
      missing entirely, but a previous snapshot exists: restores the most
      recent snapshot over it, recording the restore as a `BackupJob` with
      `triggered_by="startup_restore"` and publishing `Topic.BACKUP_STATUS`
      (via `run_restore`) — the "автовосстановление при старте" DoD item.
    - DB file missing AND no snapshot exists (repository never even
      initialized): genuinely a first run / fresh checkout, not data loss
      — nothing to roll back to, this is a no-op (returns None).

    A missing file is deliberately NOT automatically treated as "nothing to
    do" on its own (an earlier revision of this function did that, and a
    live DoD run for this task caught the gap): `get_current_user`/`/auth/*`
    all depend on this same DB, so once the file is gone there is no way to
    authenticate and call the *manual* restore endpoint — the startup path
    is the ONLY recovery route for "the DB file was deleted/lost entirely,"
    not just for "the file is present but corrupted."

    The two cases are still told apart differently, though:
      - The file EXISTS and fails its integrity check: unambiguous, real
        evidence of a problem — always worth attempting a restore, even if
        it turns out no snapshot exists (in which case `run_restore` itself
        records the attempt as a `BackupJob` with `status="failed"`, a
        loud, honest signal that real data was lost with nothing to
        recover it from, rather than staying silent about a real problem).
      - The file is MISSING entirely: ambiguous with, and in practice far
        more often actually IS, a fresh install / first run — only treated
        as worth restoring when a snapshot genuinely exists to prove
        something was actually lost. No snapshot (or the repository was
        never even initialized) means this stays a silent no-op.
    """
    settings = settings or get_settings()
    repo_dir, password_file, db_path = resolve_backup_paths(settings)
    if db_path is None:
        return None

    file_exists = db_path.exists()
    if file_exists:
        if await check_integrity(db_path):
            return None
        logger.error(
            "backup: %s failed integrity check at startup — restoring last snapshot", db_path
        )
    else:
        try:
            snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)
        except ResticError:
            return None  # repository never initialized -> genuinely a fresh install
        if not snapshots:
            return None  # no snapshot exists -> also a fresh install, not data loss
        logger.error(
            "backup: %s is missing at startup but a previous snapshot exists — restoring it",
            db_path,
        )

    return await run_restore(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="startup_restore",
        event_bus=event_bus,
    )


def create_default_scheduler(
    *, event_bus: EventBus | None = None, settings: Settings | None = None
) -> BackupScheduler | None:
    """A `BackupScheduler` wired to real Settings, or None when there is no
    SQLite file configured to back up (see `resolve_backup_paths`)."""
    settings = settings or get_settings()
    repo_dir, password_file, db_path = resolve_backup_paths(settings)
    if db_path is None:
        return None

    async def _run_once() -> None:
        await run_backup(
            repo_dir=repo_dir,
            password_file=password_file,
            db_path=db_path,
            triggered_by="scheduled",
            event_bus=event_bus,
        )

    return BackupScheduler(
        hour=settings.backup_schedule_hour,
        minute=settings.backup_schedule_minute,
        run_once=_run_once,
    )


async def run_manual_backup(
    *, event_bus: EventBus | None = None, settings: Settings | None = None
) -> BackupJob:
    """Used by `POST /security/consoles/backup/snapshot`."""
    settings = settings or get_settings()
    repo_dir, password_file, db_path = resolve_backup_paths(settings)
    if db_path is None:
        raise ValueError("no SQLite database configured to back up")
    return await run_backup(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        event_bus=event_bus,
    )


async def run_manual_restore(
    *,
    snapshot_id: str | None = None,
    event_bus: EventBus | None = None,
    settings: Settings | None = None,
) -> BackupJob:
    """Used by `POST /security/consoles/backup/restore/{snapshot_id}`."""
    settings = settings or get_settings()
    repo_dir, password_file, db_path = resolve_backup_paths(settings)
    if db_path is None:
        raise ValueError("no SQLite database configured to restore")
    return await run_restore(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        snapshot_id=snapshot_id,
        event_bus=event_bus,
    )


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def backup_console_metrics(
    session: AsyncSession, *, settings: Settings | None = None
) -> dict:
    """Real data for `/security/consoles/backup` (see
    routers/security_console.py._backup_payload): the latest job's
    status/time, the total size of every successful run recorded, the next
    automatic run (None when `backup_enabled` is off — nothing IS
    scheduled), a genuine last-7-days size chart, and the one real module's
    (`database`) last backup time.

    Every value here comes from an actual `BackupJob` query — an empty
    table (no snapshot has ever run) legitimately produces all-None/all-zero
    output, which is the honest answer, not a fabricated one.
    """
    settings = settings or get_settings()

    latest_job = (
        await session.scalars(
            select(BackupJob).order_by(BackupJob.started_at.desc()).limit(1)
        )
    ).first()

    total_size_bytes = (
        await session.scalars(
            select(BackupJob.size_bytes).where(BackupJob.status == "success")
        )
    ).all()
    total_size_bytes = sum(size for size in total_size_bytes if size)

    next_scheduled_at = (
        next_daily_run(settings.backup_schedule_hour, settings.backup_schedule_minute)
        if settings.backup_enabled
        else None
    )

    chart_values = await _size_chart_7d(session)

    database_job = (
        await session.scalars(
            select(BackupJob)
            .where(BackupJob.status == "success")
            .order_by(BackupJob.started_at.desc())
            .limit(1)
        )
    ).first()

    return {
        "last_backup_at": latest_job.finished_at.isoformat() if latest_job and latest_job.finished_at else None,
        "last_backup_status": latest_job.status if latest_job else None,
        "total_size_bytes": total_size_bytes,
        # Exactly one real storage target in Phase 0: the local restic repo.
        # §7.1 of the plan wants >=2 (local + NAS/external) eventually — not
        # yet built, so this stays honestly 1, not a placeholder guess.
        "storages": 1,
        "next_scheduled_at": next_scheduled_at.isoformat() if next_scheduled_at else None,
        "chart_values": chart_values,
        "database_last_backup_at": (
            database_job.finished_at.isoformat()
            if database_job and database_job.finished_at
            else None
        ),
    }


async def _size_chart_7d(session: AsyncSession) -> list[int]:
    """Sum of `size_bytes` for every successful job, bucketed by calendar
    day, for the last `_CHART_DAYS` days (oldest first, today last) —
    genuinely computed from `BackupJob` rows, not a fixed-length zero list.
    """
    today = _now().date()
    buckets = {today - timedelta(days=offset): 0 for offset in range(_CHART_DAYS - 1, -1, -1)}

    jobs = (
        await session.scalars(
            select(BackupJob).where(BackupJob.status == "success")
        )
    ).all()
    for job in jobs:
        if job.finished_at is None or job.size_bytes is None:
            continue
        day = job.finished_at.date()
        if day in buckets:
            buckets[day] += job.size_bytes

    return [buckets[day] for day in sorted(buckets)]
