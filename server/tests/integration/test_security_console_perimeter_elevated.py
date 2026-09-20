"""A-36: POST /security/consoles/perimeter/firewall/{rules,block-all,
unblock-all} against the real app wiring (client fixture — real migrated
tmp SQLite DB, real HTTP layer via TestClient), exercising the router's
error-mapping/response shape. `read_firewall_rules`/`block_all_incoming`/
`unblock_all_incoming` are monkeypatched at their bare names imported into
app.routers.security_console — the same technique
test_security_console_crowdsec_ban_unban.py already uses for `ban_ip`/
`unban_decision` (this task's own closest sibling: a write/action
function that RAISES a typed error rather than returning a never-raise
dict, see os_firewall.py's "A-36" docstring section) — so none of this
needs a real macOS host/real `osascript`/a real system password prompt
(that live coverage is this task's own report, done by hand).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.os_firewall import OSFirewallError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "perimeter_elevated_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/perimeter/firewall/rules
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_firewall_rules_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/perimeter/firewall/rules")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_firewall_rules_endpoint_returns_the_real_ruleset_on_success(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_read_firewall_rules():
        return {"status": "ok", "rules": ["anchor \"com.apple/*\" all", "block in all"]}

    monkeypatch.setattr(security_console_module, "read_firewall_rules", _fake_read_firewall_rules)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/rules", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "rules": ['anchor "com.apple/*" all', "block in all"]}


@pytest.mark.integration
async def test_firewall_rules_endpoint_maps_elevation_cancelled_to_409_not_500(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: cancelling the OS admin prompt is an honest, distinct outcome —
    never a 500, and never the same HTTP status as a real failure."""

    async def _raising_read_firewall_rules():
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "read_firewall_rules", _raising_read_firewall_rules)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/rules", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}


@pytest.mark.integration
async def test_firewall_rules_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_read_firewall_rules():
        raise OSFirewallError("pfctl exploded", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "read_firewall_rules", _raising_read_firewall_rules)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/rules", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}


@pytest.mark.integration
async def test_firewall_rules_endpoint_maps_not_configured_to_503(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_read_firewall_rules():
        raise OSFirewallError("unsupported platform: 'PlanNine'", reason="not_configured")

    monkeypatch.setattr(security_console_module, "read_firewall_rules", _raising_read_firewall_rules)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/rules", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "connector_not_configured"}


# ---------------------------------------------------------------------------
# POST /security/consoles/perimeter/firewall/block-all
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_block_all_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/perimeter/firewall/block-all")

    assert response.status_code == 401


@pytest.mark.integration
async def test_block_all_endpoint_succeeds(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_block_all_incoming():
        return {"status": "ok", "blocked": True}

    monkeypatch.setattr(security_console_module, "block_all_incoming", _fake_block_all_incoming)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/block-all", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "blocked": True}


@pytest.mark.integration
async def test_block_all_endpoint_maps_elevation_cancelled_to_409(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_all_incoming():
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "block_all_incoming", _raising_block_all_incoming)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/block-all", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}


# ---------------------------------------------------------------------------
# POST /security/consoles/perimeter/firewall/unblock-all
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_unblock_all_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/perimeter/firewall/unblock-all")

    assert response.status_code == 401


@pytest.mark.integration
async def test_unblock_all_endpoint_succeeds(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_unblock_all_incoming():
        return {"status": "ok", "blocked": False}

    monkeypatch.setattr(security_console_module, "unblock_all_incoming", _fake_unblock_all_incoming)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/unblock-all", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "blocked": False}


@pytest.mark.integration
async def test_unblock_all_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_unblock_all_incoming():
        raise OSFirewallError("pfctl exploded", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "unblock_all_incoming", _raising_unblock_all_incoming)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/firewall/unblock-all", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}
