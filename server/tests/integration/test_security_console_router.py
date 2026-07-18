"""A-10: /security/* against the real app wiring (client fixture — real
migrated tmp SQLite DB, real EventBus, real HTTP layer via TestClient), not a
unit-level SecurityConsoleRegistry in isolation (see
tests/unit/test_security_console_registry.py for that).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.security_console import CONSOLE_IDS
from tests.common.factories import create_user

_DETAIL_ROUTES = {
    "perimeter": "/security/consoles/perimeter",
    "ids": "/security/consoles/ids",
    "av": "/security/consoles/av",
    "network": "/security/consoles/network",
    "backup": "/security/consoles/backup",
    "logs": "/security/consoles/logs",
}


async def _admin_token(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "iris"
) -> str:
    await create_user(session_maker, username=username, password="pw", role="admin")
    response = client.post("/auth/login", json={"username": username, "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
def test_overview_without_token_is_401(client: TestClient):
    response = client.get("/security/overview")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
@pytest.mark.parametrize("console_id,route", list(_DETAIL_ROUTES.items()))
def test_console_detail_without_token_is_401(client: TestClient, console_id: str, route: str):
    response = client.get(route)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
def test_toggle_without_token_is_401(client: TestClient):
    response = client.post("/security/consoles/ids/toggle", json={"enabled": False})

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_overview_lists_all_six_consoles_ok_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _admin_token(client, migrated_session_maker)

    response = client.get("/security/overview", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert set(body["consoles"].keys()) == set(CONSOLE_IDS)
    for entry in body["consoles"].values():
        assert entry == {"status": "ok", "enabled": True}
    assert "kpis" in body
    assert body["event_log"] == []


@pytest.mark.integration
@pytest.mark.parametrize("console_id,route", list(_DETAIL_ROUTES.items()))
async def test_each_console_detail_endpoint_returns_its_own_id_and_ok_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    console_id: str,
    route: str,
):
    token = await _admin_token(client, migrated_session_maker, username=f"user_{console_id}")

    response = client.get(route, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == console_id
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert "engine" in body and isinstance(body["engine"], list) and body["engine"]
    assert "settings" in body


@pytest.mark.integration
async def test_toggle_off_reports_degraded_and_persists_across_requests(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _admin_token(client, migrated_session_maker)
    headers = {"Authorization": f"Bearer {token}"}

    toggle_response = client.post(
        "/security/consoles/ids/toggle", json={"enabled": False}, headers=headers
    )
    assert toggle_response.status_code == 200
    assert toggle_response.json() == {"id": "ids", "status": "degraded", "enabled": False}

    # Persists across a fresh request within the same process (in-memory registry).
    detail_response = client.get("/security/consoles/ids", headers=headers)
    assert detail_response.json()["status"] == "degraded"
    assert detail_response.json()["enabled"] is False


@pytest.mark.integration
async def test_disabling_one_console_degrades_the_overview_aggregate(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _admin_token(client, migrated_session_maker)
    headers = {"Authorization": f"Bearer {token}"}

    baseline = client.get("/security/overview", headers=headers)
    assert baseline.json()["status"] == "ok"

    client.post("/security/consoles/av/toggle", json={"enabled": False}, headers=headers)

    degraded = client.get("/security/overview", headers=headers)
    assert degraded.json()["status"] == "degraded"
    assert degraded.json()["consoles"]["av"] == {"status": "degraded", "enabled": False}
    # Untouched consoles stay ok — degrading one must not degrade its siblings.
    assert degraded.json()["consoles"]["perimeter"] == {"status": "ok", "enabled": True}

    # Re-enabling restores the aggregate.
    client.post("/security/consoles/av/toggle", json={"enabled": True}, headers=headers)
    restored = client.get("/security/overview", headers=headers)
    assert restored.json()["status"] == "ok"


@pytest.mark.integration
async def test_toggle_with_unknown_console_id_is_422(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _admin_token(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/not-a-real-console/toggle",
        json={"enabled": False},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 422


@pytest.mark.integration
async def test_overview_event_log_reflects_a_real_security_alert_from_the_events_table(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """End-to-end: A-3's brute-force lock publishes `security.alert` (A-4) ->
    the default subscriber persists it to the real `events` table -> this
    endpoint's event_log genuinely queries that table, not a JS mock."""
    from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS

    await create_user(migrated_session_maker, username="locktarget", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post(
            "/auth/login", json={"username": "locktarget", "password": "wrong-pass"}
        )

    token = await _admin_token(client, migrated_session_maker, username="observer")
    response = client.get("/security/overview", headers={"Authorization": f"Bearer {token}"})

    event_log = response.json()["event_log"]
    assert any(
        entry["topic"] == "security.alert"
        and entry["payload"] == {"reason": "account_locked", "username": "locktarget"}
        for entry in event_log
    )
