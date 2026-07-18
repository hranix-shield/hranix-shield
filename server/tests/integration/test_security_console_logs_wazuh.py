"""A-16: GET /security/consoles/logs against the real app wiring (client
fixture — real migrated tmp SQLite DB, real HTTP layer via TestClient),
exercising the router's real (non-stub) Wazuh-backed fields. The router
calls `fetch_logs_console_data` by its bare name imported into
app.routers.security_console — monkeypatched here the same way
test_security_console_ids_crowdsec.py already redirects
`fetch_ids_console_data`, so no real Wazuh container is needed for this file
(that live-container coverage is tests/integration/test_wazuh_live.py,
marked `wazuh_live`).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession]
) -> dict[str, str]:
    await create_user(session_maker, username="logs_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "logs_admin", "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_logs_console_reports_not_configured_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching at all here: the real `fetch_logs_console_data`
    genuinely runs against real (test-default) Settings, which have no
    WAZUH_API_URL/WAZUH_API_USERNAME/WAZUH_API_PASSWORD set — the DoD's "no
    fabricated all-clear" scenario, exercised for real, not mocked. This is
    also the fix for this console's own former placeholder bug (used to
    hardcode zeros regardless of connection state)."""
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/logs", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "logs"
    assert body["connector"] == {"status": "not_configured"}
    assert body["metrics"] == {
        "events_24h": None,
        "warnings_24h": None,
        "security_errors_24h": None,
        "sources": None,
    }
    assert body["entries"] == []


@pytest.mark.integration
async def test_logs_console_surfaces_an_unreachable_connector_without_a_500(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD failure scenario: Wazuh configured but unreachable — the endpoint
    must still answer 200 with an honest status, never 500."""

    async def _raising_fetch(settings=None):
        return {
            "connector": {"status": "unreachable"},
            "metrics": {
                "events_24h": None,
                "warnings_24h": None,
                "security_errors_24h": None,
                "sources": None,
            },
            "chart": {"metric": "security_events_7d", "unit": "events", "values": []},
            "entries": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_logs_console_data", _raising_fetch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/logs", headers=headers)

    assert response.status_code == 200
    assert response.json()["connector"] == {"status": "unreachable"}


@pytest.mark.integration
async def test_logs_console_renders_real_fim_entries_when_wazuh_is_reachable(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_fetch(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {"events_24h": 2, "warnings_24h": None, "security_errors_24h": None, "sources": 1},
            "chart": {"metric": "security_events_7d", "unit": "events", "values": []},
            "entries": [
                {
                    "timestamp": "2026-07-16T14:19:56+00:00",
                    "level": "notice",
                    "source": "wazuh_fim",
                    "file": "/monitored/logs/assistant.log",
                    "description": "Изменение файла под контролем целостности: /monitored/logs/assistant.log",
                }
            ],
        }

    monkeypatch.setattr(security_console_module, "fetch_logs_console_data", _fake_fetch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/logs", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connector"] == {"status": "ok"}
    assert body["metrics"]["events_24h"] == 2
    assert body["entries"][0]["file"] == "/monitored/logs/assistant.log"
    # Toggle-backed fields (A-10) are untouched by A-16's connector wiring.
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert body["engine"] == ["wazuh_agent", "windows_event_log", "macos_unified_log"]
    assert "settings" in body
