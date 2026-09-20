"""A-29: POST /security/consoles/ids/crowdsec/ban and DELETE
/security/consoles/ids/crowdsec/decisions/{id} against the real app wiring
(client fixture — real migrated tmp SQLite DB, real HTTP layer via
TestClient), exercising the router's error-mapping/response shape. The
router calls `ban_ip`/`unban_decision` by their bare names imported into
app.routers.security_console — monkeypatched here the same way
test_security_console_ids_crowdsec.py already redirects
`fetch_ids_console_data`, so no real CrowdSec container/machine credential
is needed for this file (that live-container coverage is
tests/integration/test_crowdsec_write_live.py, marked `crowdsec_write_live`).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecError, CrowdSecNotConfiguredError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession]
) -> dict[str, str]:
    await create_user(session_maker, username="crowdsec_write_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "crowdsec_write_admin", "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/ids/crowdsec/ban
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_ban_reports_not_configured_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching at all here: the real `ban_ip` genuinely runs
    against real (test-default) Settings, which have no
    CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD set — the write-side
    analogue of test_security_console_ids_crowdsec.py's "not configured"
    scenario for reads."""
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/ids/crowdsec/ban", json={"ip": "192.0.2.1"}, headers=headers
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "crowdsec_write_not_configured"}


@pytest.mark.integration
async def test_ban_succeeds_and_returns_the_alert_ids(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_ban_ip(ip, *, duration="4h", reason="", settings=None):
        captured["ip"] = ip
        return ["24"]

    monkeypatch.setattr(security_console_module, "ban_ip", _fake_ban_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/ids/crowdsec/ban", json={"ip": "192.0.2.1"}, headers=headers
    )

    assert response.status_code == 200
    body = response.json()
    assert body == {"banned": True, "ip": "192.0.2.1", "alert_ids": ["24"]}
    assert captured["ip"] == "192.0.2.1"


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("unauthorized", 503),
        ("unreachable", 503),
        ("invalid_ip", 422),
        ("rejected", 502),
    ],
)
async def test_ban_maps_each_crowdsec_error_reason_to_the_right_http_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_ban_ip(ip, *, duration="4h", reason=reason, settings=None):
        raise CrowdSecError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "ban_ip", _raising_ban_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/ids/crowdsec/ban", json={"ip": "not-real"}, headers=headers
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": f"crowdsec_{reason}"}


@pytest.mark.integration
async def test_ban_maps_not_configured_error_even_when_read_side_is_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A deployment can have a working bouncer key (reads fine, `ids`'s
    GET keeps working) with no machine credential at all — this is in
    fact the Phase-0-until-now default this whole task exists to change,
    so it must map to its own distinct error code, not crash."""

    async def _raising_ban_ip(ip, *, duration="4h", reason="", settings=None):
        raise CrowdSecNotConfiguredError()

    monkeypatch.setattr(security_console_module, "ban_ip", _raising_ban_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/ids/crowdsec/ban", json={"ip": "192.0.2.1"}, headers=headers
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "crowdsec_write_not_configured"}


# ---------------------------------------------------------------------------
# DELETE /security/consoles/ids/crowdsec/decisions/{decision_id}
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_unban_reports_not_configured_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/ids/crowdsec/decisions/88500", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "crowdsec_write_not_configured"}


@pytest.mark.integration
async def test_unban_succeeds_and_returns_the_deleted_count(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_unban_decision(decision_id, *, settings=None):
        captured["decision_id"] = decision_id
        return 1

    monkeypatch.setattr(security_console_module, "unban_decision", _fake_unban_decision)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/ids/crowdsec/decisions/88500", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"deleted": True, "count": 1}
    assert captured["decision_id"] == 88500


@pytest.mark.integration
async def test_unban_maps_not_found_reason_to_http_404(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """CrowdSec's own "doesn't exist" case (see crowdsec.py's "A-29
    addendum" docstring for why this is a dedicated `reason`, not folded
    into the generic unreachable/unauthorized bucket) must read as a clean
    404 to the frontend, not a scary 503."""

    async def _raising_unban_decision(decision_id, *, settings=None):
        raise CrowdSecError("gone", reason="not_found")

    monkeypatch.setattr(security_console_module, "unban_decision", _raising_unban_decision)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/ids/crowdsec/decisions/999999999", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "crowdsec_decision_not_found"}


@pytest.mark.integration
@pytest.mark.parametrize("reason,expected_status", [("unauthorized", 503), ("unreachable", 503)])
async def test_unban_maps_each_other_crowdsec_error_reason_to_the_right_http_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_unban_decision(decision_id, *, settings=None):
        raise CrowdSecError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "unban_decision", _raising_unban_decision)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/ids/crowdsec/decisions/1", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": f"crowdsec_{reason}"}
