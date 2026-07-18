"""Orchestration layer: resolves `Settings` into concrete restic
arguments, persists a `BackupJob` row for every run (manual, scheduled, or
startup-restore), and publishes `Topic.BACKUP_STATUS` on the event bus.

Reads `async_session_maker`/`engine` from this module's own namespace at
call time (imported here, referenced by bare name below) — not through
`app.db.session` at call time — so a test can monkeypatch
`app.services.backup.service.async_session_maker` (and `.engine`, for the
post-restore pool-disposal step below) to point at an isolated tmp DB,
exactly the same pattern already used for
`app.services.event_bus.async_session_maker` and
`app.services.health.checks.async_session_maker` (see tests/conftest.py).
"""

from __future__ import annotations

import logging
import secrets
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.config import restic_password_file as _default_restic_password_file
from app.db.models import BackupJob
from app.db.session import async_session_maker, engine
from app.services.backup.restic_client import (
    ResticError,
    create_snapshot,
    init_repo,
    list_snapshots,
    restore_snapshot,
)
from app.services.event_bus import EventBus, Topic

logger = logging.getLogger(__name__)

# Sentinel distinguishing "caller didn't pass dispose_engine" (resolve the
# module-global `engine` at CALL time, so a test's
# `monkeypatch.setattr(service_module, "engine", tmp_engine)` is honored)
# from "caller explicitly passed dispose_engine=None" (skip disposal
# entirely) — a plain `None` default could not distinguish the two, since
# Python evaluates default argument values once, at function-definition
# time, not per call.
_USE_MODULE_ENGINE = object()

# Phase 0 backs up exactly one real "module" — the whole SQLite file (see
# A-12 spec §2: Documents/CRM/etc. don't exist yet to have their own
# backup unit). This tag is what distinguishes this module's snapshots in
# `restic snapshots` from anything a later phase's own backup unit tags.
BACKUP_MODULE_ID = "database"

# A-19: kept as a plain module-level Path (NOT re-exported as a function
# call at each use site) specifically so tests/conftest.py's autouse
# `monkeypatch.setattr(backup_service_module, "RESTIC_PASSWORD_FILE",
# tmp_path / "...")` fixture keeps working completely unchanged —
# `resolve_backup_password_file` below still does a bare-name lookup of
# `RESTIC_PASSWORD_FILE` (a module global, read at CALL time), same as
# before A-19, and monkeypatch.setattr replaces that global with a plain
# Path, not a function, so the function body must keep treating it as one.
#
# Evaluating `_default_restic_password_file()` here ONCE, at this module's
# import time, is still correct in a real packaged (PyInstaller) process:
# the bootloader sets `sys.frozen`/`sys._MEIPASS` (see
# `app.config.is_packaged()`) before ANY of this project's own code,
# including this very import, ever runs — so "resolved once here" and
# "resolved fresh on every call" agree for every real process this code
# executes in. This is a different failure mode than the *bound default
# parameter* bug this function's own docstring documents below (a default
# captured at function-DEFINITION time, invisible to
# `monkeypatch.setattr` on the module): this is a *module attribute*,
# still read via bare-name lookup inside the function body, which IS
# correctly observed by monkeypatch.setattr, exactly as it always was.
RESTIC_PASSWORD_FILE = _default_restic_password_file()


def _now() -> datetime:
    """Naive UTC now — matches the non-timezone-aware DateTime columns in
    db/models.py and the same helper's reasoning in services/auth.py."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def resolve_backup_password_file(
    settings: Settings | None = None, *, secret_file: Path | None = None
) -> Path:
    """Ensures a restic password FILE exists at `secret_file` and returns
    its path. restic is always invoked with `--password-file` (see
    restic_client._run_restic) — so this returns a *path*, unlike
    `services.auth.resolve_jwt_secret` which returns the secret value
    itself (JWT signing needs the value in-process; restic instead wants a
    file it reads on its own).

    An explicit `RESTIC_PASSWORD` (env var/.env) is written into
    `secret_file` (permissions 600) so every restic invocation still goes
    through one real file; otherwise a random password is generated on
    first use and persisted — same fallback shape as resolve_jwt_secret,
    same reasoning: this is AGPL-licensed source, so no fixed in-code
    constant can ever be the default.

    `secret_file` defaults to None here, resolved to this module's own
    `RESTIC_PASSWORD_FILE` name *inside the function body* rather than as
    the signature's default value — the same reasoning as `run_restore`'s
    `_USE_MODULE_ENGINE` sentinel above: a bound default is captured once,
    at function-definition time, so `monkeypatch.setattr(service,
    "RESTIC_PASSWORD_FILE", tmp_path / "...")` would silently NOT be
    honored by callers that never pass `secret_file` themselves — exactly
    what `services/backup/wiring.py.resolve_backup_paths()` does on every
    call. This is not a hypothetical: an earlier revision used a bound
    default here, and it wrote a real password file into this repo's own
    `data/.restic_password` while this task's own test suite was being
    developed (caught during a routine check of `git status`/`data/`
    before the live DoD run — see the task report). Resolving the name at
    call time is what makes wiring.py's tests actually test-isolated.

    A-19: `RESTIC_PASSWORD_FILE`'s own default value (see this module's
    top level) is now sourced from `app.config.restic_password_file()`,
    which resolves under a platformdirs directory instead of `REPO_ROOT`
    when running as a packaged (PyInstaller) binary — see that function's
    docstring. This function's own `secret_file`-is-None fallback
    behavior, and this docstring's reasoning about bare-name lookups vs.
    bound defaults, are unchanged either way.
    """
    settings = settings or get_settings()
    if secret_file is None:
        secret_file = RESTIC_PASSWORD_FILE

    if settings.restic_password:
        if not secret_file.exists() or secret_file.read_text().strip() != settings.restic_password:
            secret_file.parent.mkdir(parents=True, exist_ok=True)
            secret_file.write_text(settings.restic_password)
            secret_file.chmod(0o600)
        return secret_file

    if secret_file.exists() and secret_file.read_text().strip():
        return secret_file

    secret_file.parent.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_hex(32)
    secret_file.write_text(generated)
    secret_file.chmod(0o600)
    return secret_file


async def _record_job(
    maker: async_sessionmaker[AsyncSession],
    *,
    target_path: Path,
    triggered_by: str,
    started_at: datetime,
) -> int | None:
    """Best-effort: records the initial "running" row, returns its id — or
    None if the write itself fails.

    This matters specifically for `run_restore` when triggered by DB
    corruption: `BackupJob` lives in the very SQLite file that may
    currently be unreadable/unwritable (verified live — inserting into a
    garbled SQLite file raises immediately, see A-12 task report). A
    failure here must never crash the restore attempt itself; it only
    means there is no durable "this was running" row until the file is
    fixed — `_finish_job` below writes one full row after the run in that
    case, and if even THAT fails, the run still completes and returns a
    usable (if unpersisted) result rather than raising out of `run_backup`/
    `run_restore` — which, for a restore triggered by startup corruption,
    would otherwise crash the app before it ever finished starting.
    """
    try:
        async with maker() as session:
            job = BackupJob(
                status="running",
                started_at=started_at,
                target_path=str(target_path),
                triggered_by=triggered_by,
            )
            session.add(job)
            await session.commit()
            await session.refresh(job)
            return job.id
    except Exception:
        logger.warning(
            "backup: could not record the initial BackupJob row (triggered_by=%r) — "
            "target DB may currently be unwritable; will attempt one full row after the run",
            triggered_by,
            exc_info=True,
        )
        return None


async def _finish_job(
    maker: async_sessionmaker[AsyncSession],
    job_id: int | None,
    *,
    status: str,
    size_bytes: int | None,
    target_path: Path,
    triggered_by: str,
    started_at: datetime,
) -> BackupJob:
    """Updates the "running" row `_record_job` created — or, if that
    initial write failed (`job_id` is None) or the row can no longer be
    found, inserts one full row right now instead. If EVEN THAT fails (the
    target DB is still unwritable — e.g. a restore that itself failed with
    no valid snapshot to fall back to), returns an in-memory, unpersisted
    `BackupJob` so the caller still gets a usable object rather than an
    exception: that situation is already the worst case Phase 0 can be in
    (nothing could be restored AND nothing could be recorded) — the
    `logger.error` call already reports it loudly; this function's job is
    only to not also crash the caller.
    """
    finished_at = _now()
    try:
        async with maker() as session:
            job = await session.get(BackupJob, job_id) if job_id is not None else None
            if job is None:
                job = BackupJob(
                    status=status,
                    started_at=started_at,
                    finished_at=finished_at,
                    size_bytes=size_bytes,
                    target_path=str(target_path),
                    triggered_by=triggered_by,
                )
                session.add(job)
            else:
                job.status = status
                job.finished_at = finished_at
                job.size_bytes = size_bytes
            await session.commit()
            await session.refresh(job)
            return job
    except Exception:
        logger.error(
            "backup: could not persist the BackupJob row at all (status=%r, triggered_by=%r) "
            "— target DB is still unwritable",
            status,
            triggered_by,
            exc_info=True,
        )
        return BackupJob(
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            size_bytes=size_bytes,
            target_path=str(target_path),
            triggered_by=triggered_by,
        )


async def run_backup(
    *,
    repo_dir: Path,
    password_file: Path,
    db_path: Path,
    triggered_by: str,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    event_bus: EventBus | None = None,
) -> BackupJob:
    """Runs one restic snapshot of `db_path`, recording a `BackupJob` row
    (running -> success/failed) and publishing `Topic.BACKUP_STATUS`.
    `triggered_by` is `"manual"` | `"scheduled"` (both are real callers
    below); `"startup_restore"` never calls this — that trigger records a
    *restore* job, see `run_restore`.
    """
    maker = session_maker or async_session_maker
    started_at = _now()
    job_id = await _record_job(
        maker, target_path=db_path, triggered_by=triggered_by, started_at=started_at
    )

    status_value = "failed"
    size_bytes: int | None = None
    error: str | None = None
    try:
        await init_repo(repo_dir=repo_dir, password_file=password_file)
        summary = await create_snapshot(
            repo_dir=repo_dir,
            password_file=password_file,
            target_paths=[db_path],
            tags=[BACKUP_MODULE_ID],
        )
        status_value = "success"
        size_bytes = summary.total_bytes_processed
    except Exception as exc:
        logger.error(
            "backup: snapshot failed (triggered_by=%r): %s", triggered_by, exc, exc_info=True
        )
        error = str(exc)

    job = await _finish_job(
        maker,
        job_id,
        status=status_value,
        size_bytes=size_bytes,
        target_path=db_path,
        triggered_by=triggered_by,
        started_at=started_at,
    )

    if event_bus is not None:
        payload: dict = {
            "job_id": job_id,
            "status": status_value,
            "triggered_by": triggered_by,
        }
        if size_bytes is not None:
            payload["size_bytes"] = size_bytes
        if error is not None:
            payload["error"] = error
        await event_bus.publish(Topic.BACKUP_STATUS, payload)

    return job


async def run_restore(
    *,
    repo_dir: Path,
    password_file: Path,
    db_path: Path,
    triggered_by: str,
    snapshot_id: str | None = None,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    event_bus: EventBus | None = None,
    dispose_engine: AsyncEngine | None | object = _USE_MODULE_ENGINE,
) -> BackupJob:
    """Restores `db_path` from a restic snapshot (`snapshot_id`, or the
    most recent one when None) and records a `BackupJob` row.

    Restic always reconstructs the full absolute source path under a
    restore's `--target` directory (verified live against restic 0.19.0,
    see A-12 task report) — this restores into a private tmp staging dir
    first, then copies just the one restored file over `db_path`. That
    means a restic restore never writes directly onto a live absolute
    system path (`--target /`), and the exact same staging-then-copy shape
    works identically against a tmp repo in tests.

    `dispose_engine` is disposed after a successful file swap: SQLAlchemy's
    async engine keeps a connection pool, and an open pooled connection's
    file handle keeps pointing at the *old* file's inode after this
    function replaces it on disk — disposing forces the next session to
    open a fresh handle onto the restored file. Left unset, this resolves
    to the real app-wide engine from app.db.session (read from this
    module's own namespace at CALL time, so a test's
    `monkeypatch.setattr(service, "engine", tmp_engine)` is honored — a
    plain `engine` default in the signature would instead freeze in
    whatever `engine` was at import time, since Python only evaluates
    default argument values once). Pass `dispose_engine=None` explicitly to
    skip disposal.
    """
    maker = session_maker or async_session_maker
    if dispose_engine is _USE_MODULE_ENGINE:
        dispose_engine = engine
    started_at = _now()
    job_id = await _record_job(
        maker, target_path=db_path, triggered_by=triggered_by, started_at=started_at
    )

    status_value = "failed"
    size_bytes: int | None = None
    error: str | None = None
    resolved_snapshot_id = snapshot_id
    staging_dir = Path(tempfile.mkdtemp(prefix="hranix-restore-"))
    try:
        if resolved_snapshot_id is None:
            snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)
            if not snapshots:
                raise ResticError(["snapshots"], 0, "no snapshots available to restore from")
            resolved_snapshot_id = snapshots[-1]["short_id"]  # restic lists oldest -> newest

        await restore_snapshot(
            repo_dir=repo_dir,
            password_file=password_file,
            snapshot_id=resolved_snapshot_id,
            target_dir=staging_dir,
        )

        restored_file = staging_dir / db_path.relative_to(db_path.anchor)
        if not restored_file.is_file():
            raise ResticError(
                ["restore", resolved_snapshot_id],
                0,
                f"restored snapshot did not contain {db_path}",
            )

        db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(restored_file, db_path)
        size_bytes = restored_file.stat().st_size
        status_value = "success"  # the data-safety-critical step is done here

        if dispose_engine is not None:
            try:
                await dispose_engine.dispose()
            except Exception:
                # The file swap already succeeded — a failure to dispose the
                # connection pool (e.g. a test double without a real pool)
                # must not turn an otherwise-successful restore into a
                # reported failure.
                logger.warning("backup: engine.dispose() after restore raised", exc_info=True)
    except Exception as exc:
        logger.error(
            "backup: restore failed (triggered_by=%r): %s", triggered_by, exc, exc_info=True
        )
        error = str(exc)
    finally:
        shutil.rmtree(staging_dir, ignore_errors=True)

    job = await _finish_job(
        maker,
        job_id,
        status=status_value,
        size_bytes=size_bytes,
        target_path=db_path,
        triggered_by=triggered_by,
        started_at=started_at,
    )

    if event_bus is not None:
        payload: dict = {
            "job_id": job_id,
            "status": status_value,
            "triggered_by": triggered_by,
            "snapshot_id": resolved_snapshot_id,
        }
        if error is not None:
            payload["error"] = error
        await event_bus.publish(Topic.BACKUP_STATUS, payload)

    return job
