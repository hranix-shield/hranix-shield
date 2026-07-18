"""A-12: exercises the REAL app_factory lifespan (`create_app()` ->
`with TestClient(app):` -> `_lifespan`), not just
`run_startup_integrity_check`/`run_restore` in isolation the way
test_backup_wiring.py does.

This is the only test shape that would have caught a real bug found live
while developing this task (see the A-12 task report): `_lifespan` used to
call `ensure_bootstrap_admin()` *before* the backup integrity check.
`ensure_bootstrap_admin`'s very first action is `SELECT count(*) FROM
users`, which raises immediately against a missing or corrupted DB file —
crashing the whole lifespan (uvicorn's "Application startup failed.
Exiting.") before the restore logic ever got a chance to fix the file.
None of `test_backup_wiring.py`'s tests exercise `ensure_bootstrap_admin`
at all (they call `run_startup_integrity_check` directly), and
`test_auth_startup.py`'s lifespan tests never combine `backup_enabled=True`
with a broken DB (it predates A-12) — so this genuinely was an
untested combination until a live run against a real server caught it.

Fixed by moving the backup integrity-check/auto-restore call before
`ensure_bootstrap_admin()` in `app_factory._lifespan` — a restic restore
brings back the full previously-migrated file (schema and all), so
`ensure_bootstrap_admin` sees a normal, already-populated `users` table
afterward. These tests pin that fix directly.
"""

import asyncio
import shutil
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.app_factory as app_factory_module
import app.services.auth as auth_service
import app.services.backup.service as backup_service_module
import app.services.event_bus as event_bus_module
import app.services.health.checks as health_checks_module
import app.services.notifications.service as notifications_service_module
from app.app_factory import create_app
from app.config import Settings
from app.db.models import User
from app.services.backup.service import run_backup
from app.services.backup.wiring import resolve_backup_paths
from tests.common.factories import create_user
from tests.conftest import _alembic_config_for

pytestmark = pytest.mark.skipif(
    shutil.which("restic") is None, reason="restic CLI is not installed on PATH"
)


@pytest.fixture
def single_file_db(tmp_path: Path):
    """Same shape as test_backup_wiring.py's fixture of the same name: a
    real, Alembic-migrated SQLite file at a KNOWN path, so `database_url`
    can point at exactly the file used for BackupJob/users bookkeeping —
    the real Phase 0 single-DB topology."""
    db_path = tmp_path / "assistant.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield db_path, maker, engine
    finally:
        asyncio.run(engine.dispose())


def _isolate_module_globals(
    maker: async_sessionmaker[AsyncSession], engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Redirects every module-global `async_session_maker`/`engine` this
    lifespan run could reach to the isolated single-file DB — the same set
    conftest.py's `client` fixture redirects, PLUS `auth_service`'s and
    `backup_service_module`'s (that fixture never runs the real lifespan,
    so it never needed to). Missing any one of these would leak a write
    into the real data/assistant.db the moment the lifespan actually
    publishes an event or queries the DB — exactly the class of bug this
    task already found once with the restic password file (see
    tests/conftest.py's autouse fixture).

    `notifications_service_module` (A-13) needs the same redirect:
    `NotificationService` subscribes to `Topic.BACKUP_STATUS` too (wired
    unconditionally in `create_app()`), so every `run_backup`/`run_restore`
    call this lifespan makes would otherwise have that subscriber try to
    write into the real data/assistant.db as well — found live the same way
    as the restic-password-file bug above (see A-13 task report).
    """
    monkeypatch.setattr(event_bus_module, "async_session_maker", maker)
    monkeypatch.setattr(health_checks_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "engine", engine)
    monkeypatch.setattr(auth_service, "async_session_maker", maker)
    monkeypatch.setattr(notifications_service_module, "async_session_maker", maker)


def _wire_settings(
    *, db_path: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, **overrides
) -> Settings:
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{db_path}",
        backup_enabled=True,
        backup_dir=str(tmp_path / "backups"),
        restic_password="test-password-for-lifespan-tests",
        **overrides,
    )
    monkeypatch.setattr(app_factory_module, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)
    return settings


@pytest.mark.integration
async def test_lifespan_does_not_crash_when_db_is_missing_with_a_snapshot_and_bootstrap_configured(
    single_file_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path, maker, engine = single_file_db
    _isolate_module_globals(maker, engine, monkeypatch)

    await create_user(maker, username="original-admin", password="pw", role="admin")

    settings = _wire_settings(
        db_path=db_path,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        bootstrap_admin_username="should-not-be-created",
        bootstrap_admin_password="should-not-be-created-pw",
    )
    repo_dir, password_file, _ = resolve_backup_paths(settings)
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=maker,
    )

    # Dispose the pool BEFORE unlinking: otherwise a still-open pooled
    # connection from the create_user()/run_backup() calls above keeps a
    # valid file descriptor to the now-unlinked inode (classic POSIX
    # "delete while open" behavior) and the lifespan below would silently
    # reuse it — masking the very crash this test exists to catch. Found
    # by deliberately reverting the fix and noticing this test kept
    # passing when it shouldn't have (see the corrupted-file test below,
    # which already disposed first and DID fail against the reverted
    # code).
    await engine.dispose()
    db_path.unlink()  # total loss, matching the live DoD scenario

    app = create_app()
    with TestClient(app):
        pass  # would raise here if the lifespan crashed, per the bug found live

    async with maker() as session:
        original = await session.scalar(select(User).where(User.username == "original-admin"))
        bootstrap_created = await session.scalar(
            select(User).where(User.username == "should-not-be-created")
        )
    assert original is not None  # restored from the snapshot
    assert bootstrap_created is None  # bootstrap correctly skipped: users table wasn't empty


@pytest.mark.integration
async def test_lifespan_does_not_crash_when_db_is_corrupted_with_a_snapshot_and_bootstrap_configured(
    single_file_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    db_path, maker, engine = single_file_db
    _isolate_module_globals(maker, engine, monkeypatch)

    await create_user(maker, username="original-admin-2", password="pw", role="admin")

    settings = _wire_settings(
        db_path=db_path,
        tmp_path=tmp_path,
        monkeypatch=monkeypatch,
        bootstrap_admin_username="should-not-be-created-2",
        bootstrap_admin_password="should-not-be-created-pw",
    )
    repo_dir, password_file, _ = resolve_backup_paths(settings)
    await run_backup(
        repo_dir=repo_dir, password_file=password_file, db_path=db_path,
        triggered_by="manual", session_maker=maker,
    )

    await engine.dispose()
    db_path.write_bytes(b"\x00 corrupted, not a valid sqlite file " * 50)

    app = create_app()
    with TestClient(app):
        pass

    async with maker() as session:
        original = await session.scalar(
            select(User).where(User.username == "original-admin-2")
        )
    assert original is not None  # restored from the snapshot, not lost to the crash
