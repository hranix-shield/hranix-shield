"""A-59: the app must start (and the manual backup must fail honestly) when
`BACKUP_ENABLED=True` but the restic binary is absent from PATH — the exact
pre-existing startup crash from the A-59 plan-spec («Наблюдение 1»): the raw
FileNotFoundError from `create_subprocess_exec` used to fly straight through
run_startup_integrity_check's `except ResticError` and kill the lifespan.

Deliberately NO skipif on restic's presence (unlike every other backup test
file): the whole point here is the binary being missing, so each test
*simulates* that condition — monkeypatching the spawn itself to raise
FileNotFoundError (what a missing binary actually produces, at SPAWN time,
before any returncode/stderr exists) and, where the console's connector
status is asserted, `shutil.which` to honestly report the binary as absent —
so these tests run identically on machines with and without restic.

Production topology note: `launcher.py` applies Alembic migrations BEFORE
uvicorn starts, so by the time `_lifespan` runs the SQLite file always
exists — the lifespan test below mirrors that (migrated file present), not
the "file deleted out from under a running install" scenario that belongs to
A-12's auto-restore tests (test_backup_startup_lifespan.py).
"""

import asyncio
import shutil
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.app_factory as app_factory_module
import app.routers.security_console as security_console_router_module
import app.services.auth as auth_service
import app.services.backup.service as backup_service_module
import app.services.backup.wiring as backup_wiring_module
import app.services.event_bus as event_bus_module
import app.services.health.checks as health_checks_module
import app.services.notifications.service as notifications_service_module
from app.app_factory import create_app
from app.config import Settings
from app.db.session import get_session
from app.services.backup.wiring import run_startup_integrity_check
from tests.common.factories import create_user
from tests.conftest import _alembic_config_for


def _no_restic_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """`restic` not being on PATH fails the SPAWN itself with
    FileNotFoundError — the same simulation tests/unit/test_restic_client.py
    uses, patched on the asyncio module attribute so it is visible both to
    plain awaits and to the lifespan TestClient runs on its portal thread."""

    async def _raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _raise_file_not_found)


def _which_reports_no_restic(monkeypatch: pytest.MonkeyPatch) -> None:
    """Makes `shutil.which("restic")` honestly report the binary as absent
    (deterministically, even on a machine that has it) — the exact probe
    wiring.backup_connector_status uses for its `restic_binary_not_found`
    reason; every other binary keeps resolving normally."""
    real_which = shutil.which

    def _which_without_restic(name, *args, **kwargs):
        if name == "restic":
            return None
        return real_which(name, *args, **kwargs)

    monkeypatch.setattr(shutil, "which", _which_without_restic)


def _no_restic_settings(tmp_path: Path, db_path: Path, **overrides) -> Settings:
    """`backup_enabled=True` + everything else pointing at tmp_path — a
    fresh install whose operator enabled backups but never installed restic."""
    return Settings(
        _env_file=None,
        database_url=f"sqlite+aiosqlite:///{db_path}",
        backup_enabled=True,
        backup_dir=str(tmp_path / "backups"),
        restic_password="test-password-for-startup-no-restic",
        **overrides,
    )


@pytest.mark.integration
async def test_startup_integrity_check_returns_none_when_db_and_binary_are_both_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The exact crash from the plan-spec's Проблема, pinned at the wiring
    level: db file missing -> list_snapshots -> spawn fails -> must come back
    as a silent no-op (None, "genuinely a fresh install"), NOT a raw
    FileNotFoundError out of this function."""
    _no_restic_binary(monkeypatch)
    db_path = tmp_path / "assistant.db"
    assert not db_path.exists()

    result = await run_startup_integrity_check(settings=_no_restic_settings(tmp_path, db_path))

    assert result is None


@pytest.fixture
def single_file_db(tmp_path: Path):
    """A real, Alembic-migrated SQLite file at a KNOWN path — same shape as
    test_backup_startup_lifespan.py's fixture of the same name (its setup
    runs before pytest-asyncio starts the test's event loop, since Alembic's
    command.upgrade calls asyncio.run internally)."""
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
    """Redirects every module-global `async_session_maker`/`engine` the real
    lifespan could reach to this test's isolated tmp DB — the same set
    test_backup_startup_lifespan.py patches (see its docstring for why every
    single one of these matters)."""
    monkeypatch.setattr(event_bus_module, "async_session_maker", maker)
    monkeypatch.setattr(health_checks_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "engine", engine)
    monkeypatch.setattr(auth_service, "async_session_maker", maker)
    monkeypatch.setattr(notifications_service_module, "async_session_maker", maker)


@pytest.mark.integration
def test_app_starts_with_backup_enabled_and_no_restic_and_console_reports_it_honestly(
    single_file_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """The plan-spec's Целевое состояние #3 end to end: fresh install,
    restic absent, BACKUP_ENABLED=True -> the app STARTS (/health 200), and
    the backup console reports the honest
    not_configured/restic_binary_not_found connector status (A-55) instead of
    the process dying at startup."""
    db_path, maker, engine = single_file_db
    _isolate_module_globals(maker, engine, monkeypatch)
    _no_restic_binary(monkeypatch)
    _which_reports_no_restic(monkeypatch)

    settings = _no_restic_settings(
        tmp_path,
        db_path,
        bootstrap_admin_username="a59-admin",
        bootstrap_admin_password="a59-admin-pw",
    )
    monkeypatch.setattr(app_factory_module, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)
    # The console router resolves Settings through its own get_settings name
    # (security_console.py imports it straight from app.config) — patch that
    # too, or connector.status would reflect the real environment, not this
    # test's backup_enabled=True settings.
    monkeypatch.setattr(security_console_router_module, "get_settings", lambda: settings)

    app = create_app()

    # /auth/* (and every other router) resolves its session through the
    # get_session dependency — point it at this test's tmp DB too, or the
    # login below would query the real data/assistant.db (found live: the
    # lifespan-created bootstrap admin existed, yet login 401'd).
    async def _override_get_session() -> AsyncSession:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session

    with TestClient(app) as client:
        assert client.get("/health").status_code == 200

        # The lifespan reached ensure_bootstrap_admin (i.e. the backup block
        # above it did not abort startup) — this very login proves it.
        login = client.post(
            "/auth/login", json={"username": "a59-admin", "password": "a59-admin-pw"}
        )
        assert login.status_code == 200
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        console = client.get("/security/consoles/backup", headers=headers)
        assert console.status_code == 200
        connector = console.json()["connector"]
        assert connector["status"] == "not_configured"
        assert connector["reason"] == "restic_binary_not_found"


@pytest.mark.integration
def test_app_starts_even_when_the_startup_integrity_check_itself_raises(
    single_file_db, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """A-59's defense-in-depth wrapper in app_factory._lifespan, pinned
    directly: WHATEVER exception escapes run_startup_integrity_check (some
    future failure mode outside the ResticError vocabulary), the app still
    starts — the backup subsystem has no right to kill the process."""
    db_path, maker, engine = single_file_db
    _isolate_module_globals(maker, engine, monkeypatch)

    settings = _no_restic_settings(tmp_path, db_path)
    monkeypatch.setattr(app_factory_module, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)

    async def _always_raises(**kwargs):
        raise RuntimeError("simulated unexpected startup-check failure")

    monkeypatch.setattr(app_factory_module, "run_startup_integrity_check", _always_raises)

    app = create_app()
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200


@pytest.fixture
def backup_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The single-file HTTP topology of test_backup_console_router.py's
    fixture of the same name, minus that file's restic-presence skipif — the
    binary's absence is the very condition under test here."""
    db_path = tmp_path / "assistant.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    maker = async_sessionmaker(engine, expire_on_commit=False)

    monkeypatch.setattr(event_bus_module, "async_session_maker", maker)
    monkeypatch.setattr(health_checks_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "engine", engine)
    # NotificationService subscribes to Topic.BACKUP_STATUS unconditionally —
    # every snapshot call below publishes it, so keep that subscriber on this
    # test's tmp DB, not the real data/assistant.db (see A-13).
    monkeypatch.setattr(notifications_service_module, "async_session_maker", maker)

    settings = _no_restic_settings(tmp_path, db_path)
    monkeypatch.setattr(backup_wiring_module, "get_settings", lambda: settings)
    monkeypatch.setattr(security_console_router_module, "get_settings", lambda: settings)

    app = create_app()

    async def _override_get_session() -> AsyncSession:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session

    try:
        yield TestClient(app), maker
    finally:
        asyncio.run(engine.dispose())


@pytest.mark.integration
async def test_manual_backup_without_the_binary_records_a_failed_job_not_a_500(
    backup_client, monkeypatch: pytest.MonkeyPatch
):
    """DoD #4: the manual "Create full backup" button without restic
    installed answers HTTP 200 with an honestly-failed BackupJob (restic
    vocabulary, visible in the console's last_backup_status), never a 500."""
    _no_restic_binary(monkeypatch)
    client, maker = backup_client
    await create_user(maker, username="a59-backup-admin", password="pw", role="admin")
    login = client.post(
        "/auth/login", json={"username": "a59-backup-admin", "password": "pw"}
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

    response = client.post("/security/consoles/backup/snapshot", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "failed"
    assert body["triggered_by"] == "manual"
