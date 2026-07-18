"""A-12: run_backup/run_restore — real restic subprocess against a
tmp_path repository + the real `migrated_session_maker` fixture (a fresh,
Alembic-migrated SQLite DB per test, see tests/conftest.py) for BackupJob
persistence. Never touches the developer's real data/assistant.db or
infra/backups/. Skips cleanly if restic isn't installed.
"""

import shutil
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import BackupJob
from app.services.backup.service import run_backup, run_restore
from app.services.event_bus import EventBus, Topic

pytestmark = pytest.mark.skipif(
    shutil.which("restic") is None, reason="restic CLI is not installed on PATH"
)


def _password_file(tmp_path: Path) -> Path:
    path = tmp_path / ".restic_password"
    path.write_text("test-password-for-backup-service-tests")
    path.chmod(0o600)
    return path


async def _all_jobs(maker: async_sessionmaker[AsyncSession]) -> list[BackupJob]:
    async with maker() as session:
        return list((await session.scalars(select(BackupJob).order_by(BackupJob.id))).all())


@pytest.mark.integration
async def test_run_backup_success_records_a_success_job_and_publishes_backup_status(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "assistant.db"
    db_path.write_bytes(b"pretend sqlite bytes")

    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.BACKUP_STATUS, record)

    job = await run_backup(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        session_maker=migrated_session_maker,
        event_bus=bus,
    )

    assert job.status == "success"
    assert job.triggered_by == "manual"
    assert job.size_bytes == len(b"pretend sqlite bytes")
    assert job.target_path == str(db_path)
    assert job.finished_at is not None
    assert job.finished_at >= job.started_at

    jobs = await _all_jobs(migrated_session_maker)
    assert len(jobs) == 1
    assert jobs[0].status == "success"

    assert len(received) == 1
    topic, payload = received[0]
    assert topic == Topic.BACKUP_STATUS
    assert payload["status"] == "success"
    assert payload["triggered_by"] == "manual"
    assert payload["size_bytes"] == len(b"pretend sqlite bytes")


@pytest.mark.integration
async def test_run_backup_twice_reuses_the_same_repo_idempotent_init(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "assistant.db"
    db_path.write_bytes(b"version one")

    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )
    db_path.write_bytes(b"version two, a bit longer")
    second_job = await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="scheduled", session_maker=migrated_session_maker,
    )

    assert second_job.status == "success"
    jobs = await _all_jobs(migrated_session_maker)
    assert [j.status for j in jobs] == ["success", "success"]
    assert [j.triggered_by for j in jobs] == ["manual", "scheduled"]


@pytest.mark.integration
async def test_run_backup_against_a_missing_source_file_records_a_failed_job(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "does-not-exist.db"  # never created

    bus = EventBus()
    received: list[dict] = []

    async def record(_topic: str, payload: dict) -> None:
        received.append(payload)

    bus.subscribe(Topic.BACKUP_STATUS, record)

    job = await run_backup(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        session_maker=migrated_session_maker,
        event_bus=bus,
    )

    assert job.status == "failed"
    assert job.size_bytes is None
    assert job.finished_at is not None
    assert len(received) == 1
    assert received[0]["status"] == "failed"
    assert "error" in received[0]


@pytest.mark.integration
async def test_run_restore_with_no_snapshot_id_restores_the_latest_and_disposes_engine(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "assistant.db"

    db_path.write_bytes(b"first version")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )
    db_path.write_bytes(b"second and latest version")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )

    # Simulate corruption/loss of the live file entirely.
    db_path.unlink()

    disposed = {"called": False}

    class _DisposeTrackingEngine:
        """Duck-typed stand-in for AsyncEngine — run_restore only ever calls
        `await dispose_engine.dispose()` on whatever it's given, so a real
        engine isn't needed to prove that call happens after a successful
        restore."""

        async def dispose(self) -> None:
            disposed["called"] = True

    job = await run_restore(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        session_maker=migrated_session_maker,
        dispose_engine=_DisposeTrackingEngine(),
    )

    assert job.status == "success"
    assert db_path.read_bytes() == b"second and latest version"  # the LATEST snapshot, not the first
    assert disposed["called"] is True


@pytest.mark.integration
async def test_run_restore_with_an_explicit_snapshot_id_restores_that_one(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    from app.services.backup.restic_client import list_snapshots

    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "assistant.db"

    db_path.write_bytes(b"first version to restore explicitly")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )
    snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)
    first_snapshot_id = snapshots[0]["short_id"]

    db_path.write_bytes(b"second version")
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=migrated_session_maker,
    )

    job = await run_restore(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        snapshot_id=first_snapshot_id,
        session_maker=migrated_session_maker,
        dispose_engine=None,
    )

    assert job.status == "success"
    assert db_path.read_bytes() == b"first version to restore explicitly"


@pytest.mark.integration
async def test_run_restore_with_no_snapshots_available_records_a_failed_job(
    tmp_path: Path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    db_path = tmp_path / "assistant.db"
    db_path.write_bytes(b"whatever is there now stays untouched")

    job = await run_restore(
        repo_dir=repo_dir,
        password_file=password_file,
        db_path=db_path,
        triggered_by="manual",
        session_maker=migrated_session_maker,
        dispose_engine=None,
    )

    assert job.status == "failed"
    # The file that was there before the (failed) restore attempt is untouched.
    assert db_path.read_bytes() == b"whatever is there now stays untouched"
