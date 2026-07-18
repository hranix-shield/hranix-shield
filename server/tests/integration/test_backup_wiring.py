"""A-12: services/backup/wiring.py — the layer that reads real `Settings`
and assembles startup-integrity-check / scheduler / manual-action /
console-metrics behavior. Real restic subprocess + a real migrated tmp
SQLite DB throughout (skips cleanly if restic isn't installed); `Settings`
here always points `backup_dir` at `tmp_path` and `restic_password` at an
explicit test value — never the developer's real data/.restic_password or
infra/backups/.

`app.services.backup.service.async_session_maker`/`.engine` are
monkeypatched the same way `app.services.event_bus.async_session_maker`
and `app.services.health.checks.async_session_maker` already are in
tests/conftest.py's `client` fixture — wiring.py's convenience functions
never take a `session_maker` parameter themselves (that's the whole point:
they mirror what app_factory/the router will call), so redirecting the
module-global is the only way to keep them off the real DB in tests.
"""

import shutil
from datetime import datetime
from pathlib import Path

import aiosqlite
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.backup.service as backup_service_module
from app.config import Settings
from app.services.backup import wiring
from app.services.backup.service import run_backup
from app.services.event_bus import EventBus, Topic

pytestmark = pytest.mark.skipif(
    shutil.which("restic") is None, reason="restic CLI is not installed on PATH"
)


@pytest.fixture
def wired_settings(tmp_path, migrated_session_maker, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """Redirects service.py's module-global session maker/engine to this
    test's isolated tmp DB, and returns a Settings pointed at a tmp_path
    backup_dir + an explicit (not auto-generated) restic password — so
    nothing in this file ever touches the developer's real data/ or
    infra/backups/."""
    monkeypatch.setattr(backup_service_module, "async_session_maker", migrated_session_maker)
    fake_engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'unrelated.db'}")
    monkeypatch.setattr(backup_service_module, "engine", fake_engine)

    return Settings(
        _env_file=None,
        backup_dir=str(tmp_path / "backups"),
        restic_password="test-password-for-wiring-tests",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'assistant.db'}",
    )


def _db_path(settings: Settings) -> Path:
    return settings.resolved_sqlite_path


@pytest.mark.integration
async def test_run_startup_integrity_check_is_a_noop_when_db_file_is_missing(
    wired_settings: Settings,
):
    assert not _db_path(wired_settings).exists()

    result = await wiring.run_startup_integrity_check(settings=wired_settings)

    assert result is None


@pytest.mark.integration
async def test_run_startup_integrity_check_is_a_noop_for_a_healthy_db(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        await conn.commit()

    result = await wiring.run_startup_integrity_check(settings=wired_settings)

    assert result is None


@pytest.mark.integration
async def test_run_startup_integrity_check_restores_last_snapshot_when_db_is_corrupted(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo_dir, password_file, _ = wiring.resolve_backup_paths(wired_settings)

    # A real, good snapshot exists from before the "corruption".
    db_path.write_bytes(b"the last known-good backed-up content")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )

    # Now the live file gets corrupted (a crash, disk error, ...).
    db_path.write_bytes(b"\x00\x01\x02 not a valid sqlite file anymore")

    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.BACKUP_STATUS, record)

    result = await wiring.run_startup_integrity_check(event_bus=bus, settings=wired_settings)

    assert result is not None
    assert result.status == "success"
    assert result.triggered_by == "startup_restore"
    assert db_path.read_bytes() == b"the last known-good backed-up content"
    assert len(received) == 1
    assert received[0][0] == Topic.BACKUP_STATUS
    assert received[0][1]["triggered_by"] == "startup_restore"
    assert received[0][1]["status"] == "success"


@pytest.fixture
def single_file_db(tmp_path: Path):
    """A real, Alembic-migrated SQLite file at a KNOWN path (unlike
    conftest's `migrated_session_maker`, which picks its own tmp filename) —
    needed here so `Settings.database_url` can be pointed at the exact same
    file used for BackupJob bookkeeping, reproducing Phase 0's real
    single-DB topology. Alembic's `command.upgrade` calls `asyncio.run()`
    internally, which cannot run inside an already-running event loop —
    this is a plain (non-async) fixture so its setup runs before
    pytest-asyncio starts the test's own event loop, exactly like
    conftest.py's `migrated_session_maker`.
    """
    from alembic import command

    from tests.conftest import _alembic_config_for

    db_path = tmp_path / "assistant.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield db_path, maker, engine
    finally:
        import asyncio

        asyncio.run(engine.dispose())


@pytest.mark.integration
async def test_run_startup_integrity_check_survives_when_the_backup_jobs_table_itself_is_unreadable(
    single_file_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The realistic Phase 0 topology (unlike `wired_settings` above, which
    deliberately points BackupJob bookkeeping at a SEPARATE tmp DB for test
    isolation): `backup_jobs`/`events`/`users` and the file being backed up
    /restored are the SAME single SQLite file (one DB for the whole app,
    see A-2/A-12 spec). That means the very first write `run_restore`
    attempts — recording its own "running" row — targets a file that, at
    that exact moment, is still corrupted. Confirms service.py's
    `_record_job`/`_finish_job` resilience (see their docstrings) makes the
    whole flow survive that instead of crashing app startup.
    """
    from sqlalchemy import select

    from app.db.models import BackupJob

    db_path, real_maker, real_engine = single_file_db
    monkeypatch.setattr(backup_service_module, "async_session_maker", real_maker)
    monkeypatch.setattr(backup_service_module, "engine", real_engine)

    settings = Settings(
        _env_file=None,
        backup_dir=str(tmp_path / "backups"),
        restic_password="test-password-for-single-file-topology",
        database_url=f"sqlite+aiosqlite:///{db_path}",
    )
    repo_dir, password_file, resolved_db_path = wiring.resolve_backup_paths(settings)
    assert resolved_db_path == db_path

    # A real, good snapshot exists from before corruption (this snapshot
    # captures the file as it looked mid this very backup's own bookkeeping
    # write — an inherent quirk of "the backup source and the backup
    # bookkeeping share one file," not something this test needs to solve).
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=real_maker,
    )

    # Close the pool before corrupting the live file on disk, then corrupt it.
    await real_engine.dispose()
    db_path.write_bytes(b"\x00 corrupted bytes, not a valid sqlite file at all " * 5)

    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.BACKUP_STATUS, record)

    result = await wiring.run_startup_integrity_check(event_bus=bus, settings=settings)

    assert result is not None
    assert result.status == "success"
    assert result.triggered_by == "startup_restore"
    assert len(received) == 1
    assert received[0][1]["status"] == "success"

    # Prove the file is genuinely restored and queryable again — actually
    # query backup_jobs through it, rather than only trusting the returned
    # object — confirming the post-restore finish-job write really landed.
    async with real_maker() as session:
        jobs = (await session.scalars(select(BackupJob).order_by(BackupJob.id))).all()
    assert any(j.triggered_by == "startup_restore" and j.status == "success" for j in jobs)
    # engine.dispose() happens in the single_file_db fixture's teardown.


@pytest.mark.integration
async def test_run_startup_integrity_check_with_corruption_but_no_snapshot_reports_failed(
    wired_settings: Settings,
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"garbage, and there is no snapshot to fall back to")

    result = await wiring.run_startup_integrity_check(settings=wired_settings)

    assert result is not None
    assert result.status == "failed"
    assert result.triggered_by == "startup_restore"


@pytest.mark.integration
async def test_run_startup_integrity_check_restores_when_the_file_is_missing_but_a_snapshot_exists(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """The gap this fixes (found during this task's own live DoD run): a
    file that is fully DELETED (not merely corrupted) is just as much real
    data loss as a corrupted one, whenever a snapshot actually exists to
    prove something was lost — and it's the ONLY case /auth/* can't help
    recover from manually (there is no DB left to authenticate against),
    so the startup path has to be the one that handles it."""
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    repo_dir, password_file, _ = wiring.resolve_backup_paths(wired_settings)

    db_path.write_bytes(b"the last known-good backed-up content, pre-deletion")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )

    db_path.unlink()  # total loss, not corruption
    assert not db_path.exists()

    result = await wiring.run_startup_integrity_check(settings=wired_settings)

    assert result is not None
    assert result.status == "success"
    assert result.triggered_by == "startup_restore"
    assert db_path.read_bytes() == b"the last known-good backed-up content, pre-deletion"


@pytest.mark.integration
async def test_run_startup_integrity_check_stays_a_noop_when_file_is_missing_and_repo_never_initialized(
    wired_settings: Settings,
):
    """The other half of the same fix: a missing file with NO snapshot at
    all (repository never initialized) is indistinguishable from, and in
    practice almost always actually IS, a fresh install — stays silent."""
    db_path = _db_path(wired_settings)
    assert not db_path.exists()

    result = await wiring.run_startup_integrity_check(settings=wired_settings)

    assert result is None


@pytest.mark.integration
def test_create_default_scheduler_uses_the_configured_schedule(wired_settings: Settings):
    scheduler = wiring.create_default_scheduler(settings=wired_settings)

    assert scheduler is not None
    now = datetime(2026, 7, 14, 1, 0, 0)
    assert scheduler.next_run_at(now=now) == datetime(
        2026, 7, 14, wired_settings.backup_schedule_hour, wired_settings.backup_schedule_minute
    )


@pytest.mark.integration
def test_create_default_scheduler_is_none_without_a_sqlite_database():
    non_sqlite_settings = Settings(
        _env_file=None, database_url="postgresql+asyncpg://user:pw@localhost/db"
    )

    assert wiring.create_default_scheduler(settings=non_sqlite_settings) is None


@pytest.mark.integration
async def test_create_default_schedulers_run_once_performs_a_real_backup(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"data to be backed up by the scheduler's run_once")

    scheduler = wiring.create_default_scheduler(settings=wired_settings)
    assert scheduler is not None

    await scheduler._run_once()

    metrics = await _fresh_metrics(migrated_session_maker, wired_settings)
    assert metrics["last_backup_status"] == "success"


@pytest.mark.integration
async def test_run_manual_backup_and_restore_round_trip(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"manual backup content")

    backup_job = await wiring.run_manual_backup(settings=wired_settings)
    assert backup_job.status == "success"
    assert backup_job.triggered_by == "manual"

    db_path.write_bytes(b"corrupted after the fact")
    restore_job = await wiring.run_manual_restore(settings=wired_settings)

    assert restore_job.status == "success"
    assert restore_job.triggered_by == "manual"
    assert db_path.read_bytes() == b"manual backup content"


@pytest.mark.integration
async def test_run_manual_backup_raises_without_a_sqlite_database():
    non_sqlite_settings = Settings(
        _env_file=None, database_url="postgresql+asyncpg://user:pw@localhost/db"
    )

    with pytest.raises(ValueError):
        await wiring.run_manual_backup(settings=non_sqlite_settings)


async def _fresh_metrics(maker: async_sessionmaker[AsyncSession], settings: Settings) -> dict:
    async with maker() as session:
        return await wiring.backup_console_metrics(session, settings=settings)


@pytest.mark.integration
async def test_backup_console_metrics_on_an_empty_table_is_honestly_empty(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    metrics = await _fresh_metrics(migrated_session_maker, wired_settings)

    assert metrics["last_backup_at"] is None
    assert metrics["last_backup_status"] is None
    assert metrics["total_size_bytes"] == 0
    assert metrics["chart_values"] == [0] * 7
    assert metrics["database_last_backup_at"] is None
    assert metrics["next_scheduled_at"] is None  # backup_enabled defaults to False


@pytest.mark.integration
async def test_backup_console_metrics_next_scheduled_at_reflects_backup_enabled(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    enabled_settings = wired_settings.model_copy(update={"backup_enabled": True})

    metrics = await _fresh_metrics(migrated_session_maker, enabled_settings)

    assert metrics["next_scheduled_at"] is not None


@pytest.mark.integration
async def test_backup_console_metrics_reflects_a_real_successful_snapshot(
    wired_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    db_path = _db_path(wired_settings)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.write_bytes(b"twenty six bytes of data!!")  # 26 bytes

    job = await wiring.run_manual_backup(settings=wired_settings)
    assert job.status == "success"

    metrics = await _fresh_metrics(migrated_session_maker, wired_settings)

    assert metrics["last_backup_status"] == "success"
    assert metrics["last_backup_at"] is not None
    assert metrics["total_size_bytes"] == 26
    assert metrics["database_last_backup_at"] is not None
    assert sum(metrics["chart_values"]) == 26  # today's bucket carries the whole snapshot
    assert metrics["chart_values"][-1] == 26  # today is the last (rightmost) bucket
