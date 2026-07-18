"""A-12: /security/consoles/backup/snapshot + /restore/{snapshot_id} — real
restic subprocess driven through the actual HTTP layer (TestClient), plus
`/security/consoles/backup` returning genuinely non-placeholder data once a
snapshot exists.

Unlike the generic `client` fixture (tests/conftest.py), which points
`app.services.backup.wiring`'s Settings resolution at whatever the real
environment happens to have (Settings.database_url/backup_dir default to
the developer's real data//infra/backups/!), every test below builds its
own app wired to a single, KNOWN tmp SQLite file and monkeypatches
`app.services.backup.wiring.get_settings` to point at it — the same
"redirect the module-global at test time" pattern already used for
`app.services.event_bus.async_session_maker`/`app.services.health.checks.async_session_maker`
in conftest.py's `client` fixture, extended here to
`app.services.backup.service.async_session_maker`/`.engine` and
`app.services.backup.wiring.get_settings`. This is deliberately NOT wired
into the shared `client` fixture itself — doing so would make every one of
the ~200 other tests using that fixture pay for backup-specific setup they
don't need; only the tests that actually exercise these two endpoints
override it, here.
"""

import asyncio
import shutil
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.backup.service as backup_service_module
import app.services.backup.wiring as backup_wiring_module
import app.services.event_bus as event_bus_module
import app.services.health.checks as health_checks_module
import app.services.notifications.service as notifications_service_module
from app.app_factory import create_app
from app.config import Settings
from app.db.session import get_session
from tests.common.factories import create_user
from tests.conftest import _alembic_config_for

pytestmark = pytest.mark.skipif(
    shutil.which("restic") is None, reason="restic CLI is not installed on PATH"
)


@pytest.fixture
def backup_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple]:
    """A real TestClient wired end to end to one known tmp SQLite file that
    is BOTH the app's own DB (users/events/backup_jobs, via the `get_session`
    dependency override) AND the file A-12 backs up/restores (via
    `Settings.database_url`) — the same single-file topology production
    actually has (see tests/integration/test_backup_wiring.py's
    `single_file_db` fixture for the non-HTTP version of this same setup).
    """
    db_path = tmp_path / "assistant.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    maker = async_sessionmaker(engine, expire_on_commit=False)

    monkeypatch.setattr(event_bus_module, "async_session_maker", maker)
    monkeypatch.setattr(health_checks_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "async_session_maker", maker)
    monkeypatch.setattr(backup_service_module, "engine", engine)
    # A-13: NotificationService also subscribes to Topic.BACKUP_STATUS
    # (register_default_notification_subscribers, wired unconditionally in
    # create_app()) — every snapshot/restore call below publishes that
    # topic on the app's real event bus, so without this it would try to
    # write into the real data/assistant.db, same reasoning as the three
    # patches above.
    monkeypatch.setattr(notifications_service_module, "async_session_maker", maker)

    settings = Settings(
        _env_file=None,
        backup_dir=str(tmp_path / "backups"),
        restic_password="test-password-for-backup-router-tests",
        database_url=f"sqlite+aiosqlite:///{db_path}",
    )
    monkeypatch.setattr(backup_wiring_module, "get_settings", lambda: settings)

    app = create_app()

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with maker() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session

    try:
        yield TestClient(app), maker, db_path
    finally:
        asyncio.run(engine.dispose())


async def _admin_token(client: TestClient, maker: async_sessionmaker[AsyncSession]) -> str:
    await create_user(maker, username="backup-admin", password="pw", role="admin")
    response = client.post("/auth/login", json={"username": "backup-admin", "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
def test_snapshot_endpoint_without_token_is_401(backup_client):
    client, _maker, _db_path = backup_client

    response = client.post("/security/consoles/backup/snapshot")

    assert response.status_code == 401


@pytest.mark.integration
def test_restore_endpoint_without_token_is_401(backup_client):
    client, _maker, _db_path = backup_client

    response = client.post("/security/consoles/backup/restore/latest")

    assert response.status_code == 401


@pytest.mark.integration
async def test_snapshot_endpoint_creates_a_real_restic_snapshot(backup_client):
    client, maker, db_path = backup_client
    token = await _admin_token(client, maker)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/security/consoles/backup/snapshot", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "success"
    assert body["triggered_by"] == "manual"
    assert body["size_bytes"] == db_path.stat().st_size
    assert body["id"] is not None


@pytest.mark.integration
async def test_console_backup_reflects_real_data_after_a_snapshot(backup_client):
    client, maker, _db_path = backup_client
    token = await _admin_token(client, maker)
    headers = {"Authorization": f"Bearer {token}"}

    # Before any snapshot: honestly empty, not fabricated.
    before = client.get("/security/consoles/backup", headers=headers).json()
    assert before["metrics"]["last_backup_at"] is None
    assert before["metrics"]["last_backup_status"] is None
    assert before["chart"]["values"] == [0] * 7

    snapshot_response = client.post("/security/consoles/backup/snapshot", headers=headers)
    assert snapshot_response.json()["status"] == "success"

    after = client.get("/security/consoles/backup", headers=headers).json()
    assert after["metrics"]["last_backup_at"] is not None
    assert after["metrics"]["last_backup_status"] == "success"
    assert after["metrics"]["total_size_bytes"] > 0
    assert sum(after["chart"]["values"]) > 0
    database_module = next(m for m in after["modules"] if m["id"] == "database")
    assert database_module["last_backup_at"] is not None
    other_module = next(m for m in after["modules"] if m["id"] == "documents")
    assert other_module["last_backup_at"] is None  # Documents doesn't exist yet (Phase 1)


@pytest.mark.integration
async def test_restore_latest_round_trips_through_the_http_layer(backup_client):
    client, maker, db_path = backup_client
    token = await _admin_token(client, maker)
    headers = {"Authorization": f"Bearer {token}"}

    # Snapshot #1 captures the DB with just the admin user in it.
    first_snapshot = client.post("/security/consoles/backup/snapshot", headers=headers)
    assert first_snapshot.json()["status"] == "success"

    await create_user(maker, username="second-user", password="pw2", role="viewer")
    second_snapshot = client.post("/security/consoles/backup/snapshot", headers=headers)
    assert second_snapshot.json()["status"] == "success"

    restore_response = client.post(
        "/security/consoles/backup/restore/latest", headers=headers
    )

    assert restore_response.status_code == 200
    body = restore_response.json()
    assert body["status"] == "success"
    assert body["triggered_by"] == "manual"

    from sqlalchemy import select

    from app.db.models import User

    async with maker() as session:
        users = (await session.scalars(select(User.username))).all()
    assert "second-user" in users  # the LATEST snapshot, taken after this user existed


@pytest.mark.integration
async def test_restore_with_an_explicit_snapshot_id(backup_client):
    client, maker, db_path = backup_client
    token = await _admin_token(client, maker)
    headers = {"Authorization": f"Bearer {token}"}

    first_snapshot = client.post("/security/consoles/backup/snapshot", headers=headers).json()

    await create_user(maker, username="only-in-second-snapshot", password="pw2")
    client.post("/security/consoles/backup/snapshot", headers=headers)

    # Explicitly ask for the FIRST snapshot back, not "latest" — look it up
    # via the same (monkeypatched) settings resolution the app itself uses.
    from app.services.backup.restic_client import list_snapshots

    real_settings = backup_wiring_module.get_settings()
    repo_dir, password_file, _ = backup_wiring_module.resolve_backup_paths(real_settings)
    snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)
    first_short_id = snapshots[0]["short_id"]

    restore_response = client.post(
        f"/security/consoles/backup/restore/{first_short_id}", headers=headers
    )

    assert restore_response.status_code == 200
    assert restore_response.json()["status"] == "success"

    from sqlalchemy import select

    from app.db.models import User

    async with maker() as session:
        usernames = (await session.scalars(select(User.username))).all()
    assert "only-in-second-snapshot" not in usernames  # restored the FIRST snapshot


@pytest.mark.integration
async def test_restore_with_no_snapshots_available_reports_failed_not_500(backup_client):
    client, maker, _db_path = backup_client
    token = await _admin_token(client, maker)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/security/consoles/backup/restore/latest", headers=headers)

    assert response.status_code == 200  # the API call succeeded; the job's own result is "failed"
    assert response.json()["status"] == "failed"
