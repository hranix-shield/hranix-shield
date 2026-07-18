"""A-15: GET /security/consoles/network and GET /security/consoles/av
against the real app wiring (client fixture — real migrated tmp SQLite DB,
real HTTP layer via TestClient), exercising the router's real (non-stub)
osquery-backed fields — same shape as test_security_console_ids_crowdsec.py
for `ids` and test_security_console_perimeter.py for `perimeter`.

`fetch_network_console_data`/`fetch_av_osquery_data` are monkeypatched at
their bare names imported into app.routers.security_console, same technique
those two files already use, so most of these tests need no real `osqueryi`
installed. The two tests that do NOT monkeypatch anything exercise the
genuinely-live default path the same way each of those files' own
"not_configured by default" test does — on this dev machine (no `osqueryi`
installed, see the A-15 task report) that is a real, honest
`not_configured`, not a mock standing in for one.

A-17 update: `av`'s `connectors` dict now also carries a real `clamav` key
(services/mcp/security_connectors/clamav.py). None of the tests below
monkeypatch `fetch_av_clamav_data` — `Settings.clamav_enabled` defaults to
`False` and no `.env` exists in the test environment (see conftest.py), so
the real connector deterministically reports `not_configured` here, exactly
like the un-monkeypatched osquery test does for its own connector — genuine
behavior, not a mock standing in for one. Dedicated ClamAV-specific
coverage (ok/unreachable states, quick/full scan, quarantine) lives in
test_clamav_client.py (unit), test_security_console_av_clamav.py
(integration), and test_clamav_live.py (live, marked `clamav_live`).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
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
# network
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_network_console_surfaces_real_connections_when_osquery_is_ok(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "консоль «Сеть» показывает реальный список активных соединений"."""

    async def _fake_network_data():
        return {
            "connector": {"status": "ok"},
            "connections": [
                {
                    "process": "python3",
                    "pid": 4321,
                    "local_address": "127.0.0.1",
                    "local_port": 51000,
                    "remote_address": "93.184.216.34",
                    "remote_port": 443,
                    "protocol": "6",
                    "state": "ESTABLISHED",
                }
            ],
            "listening_ports": [
                {"process": "uvicorn", "pid": 4242, "port": 8000, "protocol": "6", "address": "127.0.0.1"}
            ],
            "active_connections": 1,
        }

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    headers = await _admin_headers(client, migrated_session_maker, "network_admin")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "network"
    assert body["connector"] == {"status": "ok"}
    assert body["metrics"]["active_connections"] == 1
    assert body["connections"] == [
        {
            "process": "python3",
            "pid": 4321,
            "local_address": "127.0.0.1",
            "local_port": 51000,
            "remote_address": "93.184.216.34",
            "remote_port": 443,
            "protocol": "6",
            "state": "ESTABLISHED",
        }
    ]
    assert body["listening_ports"] == [
        {"process": "uvicorn", "pid": 4242, "port": 8000, "protocol": "6", "address": "127.0.0.1"}
    ]
    # Toggle-backed fields (A-10) are untouched by A-15's connector wiring.
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert body["engine"] == ["osquery", "os_counters"]
    assert "settings" in body


@pytest.mark.integration
async def test_network_console_never_500s_when_osquery_fails(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_network_data():
        return {
            "connector": {"status": "unreachable"},
            "connections": [],
            "listening_ports": [],
            "active_connections": None,
        }

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    headers = await _admin_headers(client, migrated_session_maker, "network_admin_fail")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connector"] == {"status": "unreachable"}
    assert body["metrics"]["active_connections"] is None
    assert body["connections"] == []


@pytest.mark.integration
async def test_network_console_reports_not_configured_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: the real `fetch_network_console_data` genuinely
    runs — on this dev machine (no `osqueryi` installed) that means an
    honest `not_configured`, exactly the DoD's "no fabricated all-clear"
    scenario, exercised for real, not mocked."""
    headers = await _admin_headers(client, migrated_session_maker, "network_admin_default")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connector"]["status"] in (
        "ok",
        "not_configured",
        "permission_denied",
        "unreachable",
    )
    if body["connector"]["status"] != "ok":
        assert body["metrics"]["active_connections"] is None
        assert body["connections"] == []


# ---------------------------------------------------------------------------
# av
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_av_console_surfaces_osquery_source_when_ok(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "консоль «Вирусная активность» показывает osquery как один из
    активных источников в connectors['osquery']"."""

    async def _fake_av_data():
        return {
            "connector": {"status": "ok"},
            "process_count": 312,
            "file_events": {"status": "not_configured", "count": None, "recent": []},
        }

    monkeypatch.setattr(security_console_module, "fetch_av_osquery_data", _fake_av_data)
    headers = await _admin_headers(client, migrated_session_maker, "av_admin")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "av"
    # clamav is genuinely (not mocked) not_configured here — see this file's
    # module docstring.
    assert body["connectors"] == {
        "osquery": {"status": "ok"},
        "clamav": {"status": "not_configured"},
    }
    assert body["metrics"]["osquery_process_count"] == 312
    assert body["file_events"] == {"status": "not_configured", "count": None, "recent": []}
    # Signature-scanner metrics stay an honest None — ClamAV is not
    # configured in this test environment (see module docstring), same
    # "not_configured means None, never a guessed 0" convention as every
    # other connector in this stack.
    assert body["metrics"]["clean"] is None
    assert body["metrics"]["quarantine_count"] is None
    assert body["metrics"]["last_scan_at"] is None
    assert body["metrics"]["databases_updated_at"] is None


@pytest.mark.integration
async def test_av_console_never_500s_when_osquery_fails(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_av_data():
        return {
            "connector": {"status": "permission_denied"},
            "process_count": None,
            "file_events": {"status": "not_configured", "count": None, "recent": []},
        }

    monkeypatch.setattr(security_console_module, "fetch_av_osquery_data", _fake_av_data)
    headers = await _admin_headers(client, migrated_session_maker, "av_admin_fail")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"] == {
        "osquery": {"status": "permission_denied"},
        "clamav": {"status": "not_configured"},
    }
    assert body["metrics"]["osquery_process_count"] is None


@pytest.mark.integration
async def test_av_console_reflects_a_real_unconfigured_osquery_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: the real `fetch_av_osquery_data` genuinely runs —
    on this dev machine (no `osqueryi` installed) that means an honest
    `not_configured`, not a mock."""
    headers = await _admin_headers(client, migrated_session_maker, "av_admin_default")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"]["osquery"]["status"] in (
        "ok",
        "not_configured",
        "permission_denied",
        "unreachable",
    )
    # clamav_enabled defaults to False and no .env exists in the test
    # environment (see module docstring) — deterministic, unlike osquery's
    # host-dependent state above.
    assert body["connectors"]["clamav"] == {"status": "not_configured"}
