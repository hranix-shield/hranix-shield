"""Post-merge user request (2026-08-02): `av`'s real settings —
`GET /security/consoles/av`'s new `settings` shape (no more hardcoded
`realtime_protection`/`scan_removable_media`, `full_scan_schedule` replaces
the old fake `scan_schedule` string), `POST .../settings/full-scan-schedule`
(real DB write), `POST .../clamav/update-databases` (elevated freshclam
trigger), `POST .../clamav/pick-folder` (native folder picker) — against the
real app wiring (client fixture, real migrated tmp SQLite DB, real HTTP
layer via TestClient), same monkeypatch-the-bare-name technique every other
integration test in this suite already uses.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.clamav import (
    ClamAvDbUpdateError,
    ClamAvFolderPickError,
)
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /security/consoles/av -> settings
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_av_settings_no_longer_include_the_old_fake_fields(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "av_settings_shape")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    settings = response.json()["settings"]
    assert "realtime_protection" not in settings
    assert "scan_removable_media" not in settings
    assert "scan_schedule" not in settings
    assert settings["action_on_threat"] == "quarantine"
    assert settings["full_scan_schedule"] == {
        "enabled": False,
        "hour": 6,
        "minute": 0,
        "days": [0, 1, 2, 3, 4, 5, 6],
    }


# ---------------------------------------------------------------------------
# POST /security/consoles/av/settings/full-scan-schedule
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_update_full_scan_schedule_endpoint_requires_a_token(client: TestClient):
    response = client.post(
        "/security/consoles/av/settings/full-scan-schedule",
        json={"enabled": True, "hour": 6, "minute": 0},
    )

    assert response.status_code == 401


@pytest.mark.integration
async def test_update_full_scan_schedule_endpoint_persists_and_is_read_back(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "av_schedule_write")

    write_response = client.post(
        "/security/consoles/av/settings/full-scan-schedule",
        json={"enabled": True, "hour": 3, "minute": 30, "days": [0, 2, 4]},
        headers=headers,
    )
    assert write_response.status_code == 200
    assert write_response.json() == {"enabled": True, "hour": 3, "minute": 30, "days": [0, 2, 4]}

    read_response = client.get("/security/consoles/av", headers=headers)
    assert read_response.json()["settings"]["full_scan_schedule"] == {
        "enabled": True,
        "hour": 3,
        "minute": 30,
        "days": [0, 2, 4],
    }


@pytest.mark.integration
async def test_update_full_scan_schedule_endpoint_accepts_an_empty_days_list(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """Post-merge user request (2026-08-02): an empty `days` list is an
    honest, harmless interim state (never fires), not a 422 — see
    AvScanScheduleRequest's own docstring."""
    headers = await _admin_headers(client, migrated_session_maker, "av_schedule_no_days")

    response = client.post(
        "/security/consoles/av/settings/full-scan-schedule",
        json={"enabled": True, "hour": 6, "minute": 0, "days": []},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["days"] == []


@pytest.mark.integration
async def test_update_full_scan_schedule_endpoint_rejects_an_out_of_range_day(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "av_schedule_bad_day")

    response = client.post(
        "/security/consoles/av/settings/full-scan-schedule",
        json={"enabled": True, "hour": 6, "minute": 0, "days": [7]},
        headers=headers,
    )

    assert response.status_code == 422


@pytest.mark.integration
@pytest.mark.parametrize("body", [{"enabled": True, "hour": 24, "minute": 0}, {"enabled": True, "hour": 6, "minute": 60}])
async def test_update_full_scan_schedule_endpoint_rejects_an_out_of_range_time(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], body: dict
):
    headers = await _admin_headers(client, migrated_session_maker, f"av_schedule_bad_{body['hour']}_{body['minute']}")

    response = client.post(
        "/security/consoles/av/settings/full-scan-schedule", json=body, headers=headers
    )

    assert response.status_code == 422


# ---------------------------------------------------------------------------
# POST /security/consoles/av/clamav/update-databases
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_update_databases_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/av/clamav/update-databases")

    assert response.status_code == 401


@pytest.mark.integration
async def test_update_databases_endpoint_returns_the_fresh_readback_on_success(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
):
    async def _fake_update():
        return {"status": "ok", "databases_updated_at": "2026-08-02T12:00:00", "database_version": "27500"}

    monkeypatch.setattr(security_console_module, "update_clamav_databases", _fake_update)
    headers = await _admin_headers(client, migrated_session_maker, "av_db_update_ok")

    response = client.post("/security/consoles/av/clamav/update-databases", headers=headers)

    assert response.status_code == 200
    assert response.json()["databases_updated_at"] == "2026-08-02T12:00:00"


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status", [("elevation_cancelled", 409), ("elevation_failed", 502)]
)
async def test_update_databases_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_update():
        raise ClamAvDbUpdateError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "update_clamav_databases", _raising_update)
    headers = await _admin_headers(client, migrated_session_maker, f"av_db_update_{reason}")

    response = client.post("/security/consoles/av/clamav/update-databases", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


# ---------------------------------------------------------------------------
# POST /security/consoles/av/clamav/pick-folder
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_pick_folder_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/av/clamav/pick-folder")

    assert response.status_code == 401


@pytest.mark.integration
async def test_pick_folder_endpoint_returns_the_picked_path_on_success(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
):
    async def _fake_pick():
        return "/Users/demo/Downloads/subfolder"

    monkeypatch.setattr(security_console_module, "pick_scan_folder", _fake_pick)
    headers = await _admin_headers(client, migrated_session_maker, "av_pick_folder_ok")

    response = client.post("/security/consoles/av/clamav/pick-folder", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"path": "/Users/demo/Downloads/subfolder"}


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [("folder_pick_cancelled", 409), ("unsupported_platform", 501), ("failed", 502)],
)
async def test_pick_folder_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_pick():
        raise ClamAvFolderPickError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "pick_scan_folder", _raising_pick)
    headers = await _admin_headers(client, migrated_session_maker, f"av_pick_folder_{reason}")

    response = client.post("/security/consoles/av/clamav/pick-folder", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}
