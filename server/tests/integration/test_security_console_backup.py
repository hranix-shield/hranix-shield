"""A-55: the backup console's honest `connector` status
(services/backup/wiring.py::backup_connector_status) and the `storages`
metric that now follows it — no longer a hardcoded «OK / Хранилищ: 1» on a
machine without restic (GUI-прогон 2026-09-19, находка F1).

Unlike test_backup_console_router.py (which drives REAL restic subprocesses
and therefore skips without the binary), this file is deliberately
restic-independent: every branch is deterministic on ANY machine. The
not_configured branches are exactly the "restic is absent/misconfigured"
states this task is about, so skipping without restic would skip the whole
point. Since the A-61 acceptance patch the binary leg of the status goes
through `_resolve_restic()` (the same resolver `_run_restic` uses): on a
dev machine (never frozen) the resolver returns its bare `"restic"` fallback,
whose PATH leg is still driven deterministically via `shutil.which`
monkeypatching; the packaged leg (vendored binary in the bundle) is driven
by mocking the PyInstaller `sys.frozen`/`sys._MEIPASS` detection plus a real
file at `<MEIPASS>/vendor/restic/` — the "snapshot succeeded while the UI
hid the buttons" regression this patch closes. The ok-branch mocks the
binary path (the plan's own "ok-ветка (мок пути)") — a real end-to-end
restic run through the HTTP layer already lives in
test_backup_console_router.py.

`Settings` here always points `backup_dir` at tmp_path (never the real
infra/backups/) and the password file at a tmp location, same
"redirect the module-global at test time" isolation
test_backup_console_router.py uses for `backup_wiring_module`.
"""

import shutil
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.backup.restic_client as restic_client_module
import app.services.backup.service as backup_service_module
import app.services.backup.wiring as backup_wiring_module
from app.config import Settings
from tests.common.factories import create_user


@pytest.fixture
def isolated_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Settings:
    """A Settings whose backup paths live under tmp_path, redirected at BOTH
    places that read settings for the backup console payload —
    `app.routers.security_console.get_settings` (the router's own
    `_backup_payload` call) and `app.services.backup.wiring.get_settings`
    (the wiring layer's own resolution when no explicit settings object is
    passed)."""
    settings = Settings(
        _env_file=None,
        backup_dir=str(tmp_path / "backups"),
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'unrelated.db'}",
    )
    monkeypatch.setattr(security_console_module, "get_settings", lambda: settings)
    monkeypatch.setattr(backup_wiring_module, "get_settings", lambda: settings)
    return settings


def _fake_restic_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """`shutil.which("restic")` → a plausible path regardless of what the
    host actually has installed — makes the ok/password/repo branches
    deterministic on restic-less machines (this Windows dev box included)."""
    original_which = shutil.which
    monkeypatch.setattr(
        backup_wiring_module.shutil,
        "which",
        lambda name: "/usr/bin/restic" if name == "restic" else original_which(name),
    )


def _no_restic_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backup_wiring_module.shutil, "which", lambda name: None)


def _packaged_with_vendored_restic(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Path:
    """Turns `_resolve_restic()` into its packaged happy path deterministically:
    mocks the exact PyInstaller bootloader detection `app.config.is_packaged()`
    checks (`sys.frozen` + `sys._MEIPASS`, patched on restic_client's own
    `sys` reference — same shape as test_restic_client.py's `_set_packaged`)
    and creates a real file at `<MEIPASS>/vendor/restic/restic[.exe]` so the
    resolver's vendored `is_file()` check genuinely passes. Returns the path
    the resolver must produce."""
    vendor_dir = tmp_path / "vendor" / "restic"
    vendor_dir.mkdir(parents=True)
    exe_name = "restic.exe" if sys.platform == "win32" else "restic"
    (vendor_dir / exe_name).write_text("fake vendored restic binary")
    monkeypatch.setattr(restic_client_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        restic_client_module.sys, "_MEIPASS", str(tmp_path), raising=False
    )
    return vendor_dir / exe_name


# ---------------------------------------------------------------------------
# backup_connector_status() itself — the four not_configured codes + ok.
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_connector_status_backups_disabled(isolated_settings: Settings):
    isolated_settings.backup_enabled = False

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status["status"] == "not_configured"
    assert status["reason"] == "backups_disabled"


@pytest.mark.integration
def test_connector_status_restic_binary_not_found(
    isolated_settings: Settings, monkeypatch: pytest.MonkeyPatch
):
    isolated_settings.backup_enabled = True
    _no_restic_on_path(monkeypatch)

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status["status"] == "not_configured"
    assert status["reason"] == "restic_binary_not_found"
    assert status["restic_binary"] is False


@pytest.mark.integration
def test_connector_status_vendored_restic_counts_as_binary_in_packaged_mode(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """Патч приёмки A-61: packaged-сборка вендорит restic — снапшоты через
    `_run_restic` работали (POST .../backup/snapshot → success), а статус,
    проверяя бинарь только через `shutil.which("restic")`, рапортовал
    `restic_binary_not_found` и UI прятал кнопки. Теперь бинарная нога
    статуса идёт через тот же резолвер: vendored-копия = бинарь есть, даже
    когда в PATH нет ничего (свежая пользовательская машина)."""
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = "configured-operator-password"
    isolated_settings.resolved_backup_dir.mkdir(parents=True, exist_ok=True)
    _no_restic_on_path(monkeypatch)
    vendored = _packaged_with_vendored_restic(monkeypatch, tmp_path)

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status == {
        "status": "ok",
        "reason": None,
        "restic_binary": True,
        "repo_ready": True,
    }
    assert vendored.is_file()  # the resolver's own is_file() leg was real


@pytest.mark.integration
def test_connector_status_packaged_without_vendored_and_without_path_is_not_found(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """Обратная честность того же резолвера: packaged-сборка, на которой
    restic НЕ вендорили (и в PATH его нет), — не «ок по умолчанию», а тот же
    `restic_binary_not_found`, что и на dev-машине: resolver свалился в
    bare-фолбэк, PATH-нога пуста."""
    isolated_settings.backup_enabled = True
    _no_restic_on_path(monkeypatch)
    monkeypatch.setattr(restic_client_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        restic_client_module.sys, "_MEIPASS", str(tmp_path), raising=False
    )

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status["status"] == "not_configured"
    assert status["reason"] == "restic_binary_not_found"
    assert status["restic_binary"] is False


@pytest.mark.integration
def test_connector_status_restic_password_missing(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = None
    _fake_restic_on_path(monkeypatch)
    # A password file that genuinely does not exist.
    monkeypatch.setattr(
        backup_service_module,
        "RESTIC_PASSWORD_FILE",
        tmp_path / "absent" / ".restic_password",
    )

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status["status"] == "not_configured"
    assert status["reason"] == "restic_password_missing"


@pytest.mark.integration
def test_connector_status_restic_repo_missing(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = "configured-operator-password"
    _fake_restic_on_path(monkeypatch)
    # Password READY via an existing password file (not the env field) —
    # proves the file-existence leg of the check works on its own.
    password_file = tmp_path / ".restic_password"
    password_file.write_text("stored-password")
    monkeypatch.setattr(backup_service_module, "RESTIC_PASSWORD_FILE", password_file)
    # backup_dir deliberately NOT created → no repository has ever been
    # initialized here (init_repo creates it on the first successful backup).

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status["status"] == "not_configured"
    assert status["reason"] == "restic_repo_missing"
    assert status["restic_binary"] is True
    assert status["repo_ready"] is False


@pytest.mark.integration
def test_connector_status_ok_when_fully_configured(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
):
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = "configured-operator-password"
    _fake_restic_on_path(monkeypatch)
    isolated_settings.resolved_backup_dir.mkdir(parents=True, exist_ok=True)

    status = backup_wiring_module.backup_connector_status(settings=isolated_settings)

    assert status == {
        "status": "ok",
        "reason": None,
        "restic_binary": True,
        "repo_ready": True,
    }


# ---------------------------------------------------------------------------
# storages follows the connector status (1 ok / 0 otherwise).
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_metrics_storages_zero_when_not_configured(
    isolated_settings: Settings, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    isolated_settings.backup_enabled = False

    async with migrated_session_maker() as session:
        metrics = await backup_wiring_module.backup_console_metrics(
            session, settings=isolated_settings
        )

    assert metrics["connector"]["reason"] == "backups_disabled"
    assert metrics["storages"] == 0


@pytest.mark.integration
async def test_metrics_storages_one_when_ok(
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = "configured-operator-password"
    _fake_restic_on_path(monkeypatch)
    isolated_settings.resolved_backup_dir.mkdir(parents=True, exist_ok=True)

    async with migrated_session_maker() as session:
        metrics = await backup_wiring_module.backup_console_metrics(
            session, settings=isolated_settings
        )

    assert metrics["connector"]["status"] == "ok"
    assert metrics["storages"] == 1


# ---------------------------------------------------------------------------
# The HTTP layer: GET /security/consoles/backup carries `connector` and the
# honest `storages`.
# ---------------------------------------------------------------------------


async def _admin_token(
    client: TestClient, maker: async_sessionmaker[AsyncSession]
) -> str:
    await create_user(maker, username="backup-console-admin", password="pw", role="admin")
    response = client.post(
        "/auth/login", json={"username": "backup-console-admin", "password": "pw"}
    )
    return response.json()["access_token"]


@pytest.mark.integration
async def test_console_backup_payload_reports_not_configured_connector(
    client: TestClient,
    isolated_settings: Settings,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    isolated_settings.backup_enabled = False

    token = await _admin_token(client, migrated_session_maker)
    response = client.get(
        "/security/consoles/backup", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connector"]["status"] == "not_configured"
    assert body["connector"]["reason"] == "backups_disabled"
    assert body["metrics"]["storages"] == 0


@pytest.mark.integration
async def test_console_backup_payload_reports_ok_connector_when_configured(
    client: TestClient,
    isolated_settings: Settings,
    monkeypatch: pytest.MonkeyPatch,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    isolated_settings.backup_enabled = True
    isolated_settings.restic_password = "configured-operator-password"
    _fake_restic_on_path(monkeypatch)
    isolated_settings.resolved_backup_dir.mkdir(parents=True, exist_ok=True)

    token = await _admin_token(client, migrated_session_maker)
    response = client.get(
        "/security/consoles/backup", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connector"] == {
        "status": "ok",
        "reason": None,
        "restic_binary": True,
        "repo_ready": True,
    }
    assert body["metrics"]["storages"] == 1
