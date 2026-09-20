"""A-11: GET /security/consoles/ids against the real app wiring (client
fixture — real migrated tmp SQLite DB, real HTTP layer via TestClient),
exercising the router's real (non-stub) CrowdSec-backed fields. The router
calls `fetch_ids_console_data` by its bare name imported into
app.routers.security_console — monkeypatched here the same way conftest.py
already redirects health.checks.async_session_maker, so no real CrowdSec
container is needed for this file (that live-container coverage is
tests/integration/test_crowdsec_live.py, marked `crowdsec_live`).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession]
) -> dict[str, str]:
    await create_user(session_maker, username="ids_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "ids_admin", "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_ids_console_reports_not_configured_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching at all here: the real `fetch_ids_console_data`
    genuinely runs against real (test-default) Settings, which have no
    CROWDSEC_LAPI_URL/CROWDSEC_API_KEY set — the DoD's "no fabricated
    all-clear" scenario, exercised for real, not mocked."""
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "ids"
    assert body["connector"] == {"status": "not_configured"}
    assert body["metrics"] == {
        "active_bans": None,
        "active_bans_local": None,
        "active_bans_community": None,
        "banned_24h": None,
        "scenarios": None,
        "last_event_at": None,
    }
    assert body["recent_attempts"] == []
    # A-42: the real (also unconfigured-by-default, also not monkeypatched)
    # `fetch_allowlists` — same "no CROWDSEC_MACHINE_ID/PASSWORD set" honest
    # state as the connector above, on its own nested key.
    assert body["allowlist"] == {"connector": {"status": "not_configured"}, "items": []}
    # A-42: the old A-11 placeholders are gone — never a fabricated number.
    assert body["settings"] == {"ban_policy": "per_scenario", "rule_source": "crowdsec_hub"}


@pytest.mark.integration
async def test_ids_console_surfaces_an_unreachable_connector_without_a_500(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD failure scenario: CrowdSec configured but unreachable — the
    endpoint must still answer 200 with an honest status, never 500."""

    async def _raising_fetch(settings=None):
        return {
            "connector": {"status": "unreachable"},
            "metrics": {
                "active_bans": None,
                "active_bans_local": None,
                "active_bans_community": None,
                "banned_24h": None,
                "scenarios": None,
                "last_event_at": None,
            },
            "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
            "recent_attempts": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _raising_fetch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    assert response.json()["connector"] == {"status": "unreachable"}


@pytest.mark.integration
async def test_ids_console_renders_real_decisions_when_crowdsec_is_reachable(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_fetch(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {
                "active_bans": 1,
                "active_bans_local": 1,
                "active_bans_community": 0,
                "banned_24h": None,
                "scenarios": 1,
                "last_event_at": None,
            },
            "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
            "recent_attempts": [
                {"ip": "198.51.100.23", "vector": "crowdsecurity/ssh-bf", "status": "ban"}
            ],
        }

    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_fetch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connector"] == {"status": "ok"}
    assert body["metrics"]["active_bans"] == 1
    assert body["metrics"]["active_bans_local"] == 1
    assert body["metrics"]["active_bans_community"] == 0
    assert body["recent_attempts"] == [
        {"ip": "198.51.100.23", "vector": "crowdsecurity/ssh-bf", "status": "ban"}
    ]
    # Toggle-backed fields (A-10) are untouched by A-11's connector wiring.
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert body["engine"] == ["crowdsec"]
    assert "settings" in body


@pytest.mark.integration
async def test_ids_console_renders_real_allowlist_entries_when_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A-42 DoD: a reachable, configured allowlist connector must show real
    entries on the console's own `allowlist` key — the fix this task exists
    for (A-11's `settings.whitelist_count` was always a hardcoded `0`)."""

    async def _fake_fetch_allowlists(settings=None):
        return {
            "connector": {"status": "ok"},
            "allowlists": [
                {
                    "allowlist_name": "test_al",
                    "value": "203.0.113.5",
                    "comment": "A-42 live verification test allowlist",
                    "expiration": None,
                    "created_at": "2026-07-23T12:00:00Z",
                }
            ],
        }

    monkeypatch.setattr(security_console_module, "fetch_allowlists", _fake_fetch_allowlists)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["allowlist"]["connector"] == {"status": "ok"}
    assert body["allowlist"]["items"] == [
        {
            "allowlist_name": "test_al",
            "value": "203.0.113.5",
            "comment": "A-42 live verification test allowlist",
            "expiration": None,
            "created_at": "2026-07-23T12:00:00Z",
        }
    ]
    # `settings` no longer carries the old fabricated `whitelist_count`.
    assert "whitelist_count" not in body["settings"]
    assert "ban_threshold" not in body["settings"]
    assert "ban_duration_hours" not in body["settings"]


@pytest.mark.integration
async def test_ids_console_allowlist_reports_unreachable_without_a_500(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A-42 regression/DoD scenario: the allowlist connector can legitimately
    fail independently of `ids`'s own bouncer-key connector (two different
    credentials, see crowdsec.py's fetch_allowlists docstring) — must stay
    an honest `connector.status`, never a 500, and must never silently
    report `items: []` as if a real check found nothing."""

    async def _fake_fetch_allowlists(settings=None):
        return {"connector": {"status": "unreachable"}, "allowlists": []}

    monkeypatch.setattr(security_console_module, "fetch_allowlists", _fake_fetch_allowlists)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["allowlist"] == {"connector": {"status": "unreachable"}, "items": []}
    # The read-side `ids` connector is untouched — the two are independent.
    assert body["connector"] == {"status": "not_configured"}
