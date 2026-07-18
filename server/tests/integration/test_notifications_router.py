"""A-13: /notifications/* against the real app wiring (client fixture —
real migrated tmp SQLite DB, real EventBus, real HTTP layer via
TestClient), mirroring tests/integration/test_security_console_router.py.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user


async def _token(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "mia"
) -> str:
    await create_user(session_maker, username=username, password="pw", role="admin")
    response = client.post("/auth/login", json={"username": username, "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
def test_recent_without_token_is_401(client: TestClient):
    response = client.get("/notifications/recent")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
def test_settings_without_token_is_401(client: TestClient):
    response = client.get("/notifications/settings")

    assert response.status_code == 401


@pytest.mark.integration
async def test_recent_starts_empty(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)

    response = client.get("/notifications/recent", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json() == {"items": [], "unread_count": 0, "unread_critical_count": 0}


@pytest.mark.integration
async def test_settings_reports_the_default_matrix_and_channel_availability(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)

    response = client.get("/notifications/settings", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["matrix"]["security.alert"]["critical"] is True
    assert body["matrix"]["health.changed"]["critical"] is False
    assert body["matrix"]["backup.status"]["critical"] is False
    assert body["channel_availability"] == {
        "sound": False,
        "voice": False,
        "text_window": False,
        "panel_icon": True,
        "email": True,
        "sms_call": False,
    }
    assert body["quiet_hours"] == {"enabled": True, "start": "22:00", "end": "08:00"}
    assert body["trusted_contacts"] == []
    assert body["smtp_configured"] is False


@pytest.mark.integration
async def test_update_matrix_flips_a_topics_channels(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/notifications/settings/matrix/backup.status",
        json={"channels": ["panel_icon"]},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() == {
        "topic": "backup.status",
        "channels": ["panel_icon"],
        "critical": False,
    }

    settings_response = client.get("/notifications/settings", headers=headers)
    assert settings_response.json()["matrix"]["backup.status"]["channels"] == ["panel_icon"]


@pytest.mark.integration
async def test_update_matrix_for_unknown_topic_is_404(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)

    response = client.post(
        "/notifications/settings/matrix/not-a-real-topic",
        json={"channels": ["email"]},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "unknown_topic"}


@pytest.mark.integration
async def test_update_trusted_contacts_replaces_the_whole_list(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/notifications/settings/trusted-contacts",
        json={"emails": ["a@example.com", "b@example.com"]},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json() == {"trusted_contacts": ["a@example.com", "b@example.com"]}

    settings_response = client.get("/notifications/settings", headers=headers)
    assert settings_response.json()["trusted_contacts"] == ["a@example.com", "b@example.com"]


@pytest.mark.integration
async def test_acknowledge_unknown_notification_is_404(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)

    response = client.post(
        "/notifications/999999/ack", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "notification_not_found"}


@pytest.mark.integration
async def test_full_flow_security_alert_then_ack_then_mark_read(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """End-to-end through the real event bus: a brute-force lock (A-3/A-4)
    publishes security.alert -> NotificationService persists it -> it shows
    up unread via GET /notifications/recent -> ack stops it from being
    escalation-eligible -> mark-read clears the badge."""
    from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS

    await create_user(migrated_session_maker, username="locktarget", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/auth/login", json={"username": "locktarget", "password": "wrong-pass"})

    token = await _token(client, migrated_session_maker, username="observer")
    headers = {"Authorization": f"Bearer {token}"}

    recent = client.get("/notifications/recent", headers=headers).json()
    assert recent["unread_count"] == 1
    assert recent["unread_critical_count"] == 1
    item = recent["items"][0]
    assert item["topic"] == "security.alert"
    assert item["critical"] is True
    assert item["payload"] == {"reason": "account_locked", "username": "locktarget"}

    ack_response = client.post(f"/notifications/{item['id']}/ack", headers=headers)
    assert ack_response.status_code == 200
    assert ack_response.json()["acknowledged_at"] is not None

    mark_read_response = client.post("/notifications/mark-read", headers=headers)
    assert mark_read_response.json() == {"unread_count": 0}

    final_recent = client.get("/notifications/recent", headers=headers).json()
    assert final_recent["unread_count"] == 0
    assert final_recent["items"][0]["read_at"] is not None
