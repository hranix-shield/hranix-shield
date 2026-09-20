"""A-37: `POST/DELETE /security/consoles/perimeter/ports/{port}/block`
against the real app wiring (client fixture — real migrated tmp SQLite DB,
real HTTP layer via TestClient) — the per-port sibling of
test_security_console_perimeter_elevated.py's A-36 block-all/unblock-all
coverage, same "monkeypatch os_firewall.block_port/unblock_port at their
bare names imported into app.routers.security_console" technique so none
of this needs a real macOS host/real `osascript`/a real system password
prompt (that live coverage is this task's own report, done by hand).

Also covers `GET /security/consoles/perimeter`'s new `ports[].is_blocked`
enrichment (see security_console.py._perimeter_payload's A-37 addendum).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.db.models import BlockedPort
from app.services.mcp.security_connectors.os_firewall import OSFirewallError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "perimeter_ports_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/perimeter/ports/{port}/block
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_block_port_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/perimeter/ports/8080/block")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_block_port_endpoint_succeeds_and_persists_a_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_block_port(port, *, all_blocked_ports):
        captured["port"] = port
        captured["all_blocked_ports"] = all_blocked_ports
        return {"status": "ok", "port": port, "blocked": True}

    monkeypatch.setattr(security_console_module, "block_port", _fake_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/perimeter/ports/8080/block",
        headers=headers,
        json={"protocol": "tcp", "process_name": "nginx"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "port": 8080, "blocked": True}
    assert captured["port"] == 8080
    assert captured["all_blocked_ports"] == [8080]

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert len(rows) == 1
    assert rows[0].port == 8080
    assert rows[0].protocol == "tcp"
    assert rows[0].process_name == "nginx"


@pytest.mark.integration
async def test_block_port_endpoint_works_without_a_request_body(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`PerimeterBlockPortRequest` is optional — a bare POST with no body
    still blocks the port, just without descriptive protocol/process
    context."""

    async def _fake_block_port(port, *, all_blocked_ports):
        return {"status": "ok", "port": port, "blocked": True}

    monkeypatch.setattr(security_console_module, "block_port", _fake_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/ports/443/block", headers=headers)

    assert response.status_code == 200
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert len(rows) == 1
    assert rows[0].port == 443
    assert rows[0].protocol is None
    assert rows[0].process_name is None


@pytest.mark.integration
async def test_block_port_endpoint_passes_the_full_desired_set_including_existing_blocks(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Blocking a second port must not silently drop the first one from the
    set handed to `block_port` (macOS's own full-anchor-reconstruction
    need, see os_firewall.py's docstring)."""
    async with migrated_session_maker() as session:
        session.add(BlockedPort(port=22, protocol="tcp", process_name="sshd", blocked_at=__import__("datetime").datetime(2026, 1, 1)))
        await session.commit()

    captured: dict = {}

    async def _fake_block_port(port, *, all_blocked_ports):
        captured["all_blocked_ports"] = all_blocked_ports
        return {"status": "ok", "port": port, "blocked": True}

    monkeypatch.setattr(security_console_module, "block_port", _fake_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/ports/9090/block", headers=headers)

    assert response.status_code == 200
    assert captured["all_blocked_ports"] == [9090, 22] or sorted(captured["all_blocked_ports"]) == [22, 9090]


@pytest.mark.integration
async def test_block_port_endpoint_maps_elevation_cancelled_to_409_and_does_not_persist(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_port(port, *, all_blocked_ports):
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "block_port", _raising_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert rows == []  # never fabricates a "blocked" row when the OS action itself never happened


@pytest.mark.integration
async def test_block_port_endpoint_maps_elevation_failed_to_502_and_does_not_persist(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_port(port, *, all_blocked_ports):
        raise OSFirewallError("pfctl exploded", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "block_port", _raising_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert rows == []


@pytest.mark.integration
async def test_block_port_endpoint_maps_not_configured_to_503(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_port(port, *, all_blocked_ports):
        raise OSFirewallError("unsupported platform: 'PlanNine'", reason="not_configured")

    monkeypatch.setattr(security_console_module, "block_port", _raising_block_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "connector_not_configured"}


# ---------------------------------------------------------------------------
# DELETE /security/consoles/perimeter/ports/{port}/block
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_unblock_port_endpoint_requires_a_token(client: TestClient):
    response = client.delete("/security/consoles/perimeter/ports/8080/block")

    assert response.status_code == 401


@pytest.mark.integration
async def test_unblock_port_endpoint_succeeds_and_removes_the_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    import datetime as dt

    async with migrated_session_maker() as session:
        session.add(BlockedPort(port=8080, protocol="tcp", process_name="nginx", blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    captured: dict = {}

    async def _fake_unblock_port(port, *, all_blocked_ports):
        captured["all_blocked_ports"] = all_blocked_ports
        return {"status": "ok", "port": port, "blocked": False}

    monkeypatch.setattr(security_console_module, "unblock_port", _fake_unblock_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "port": 8080, "blocked": False}
    assert captured["all_blocked_ports"] == []

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert rows == []


@pytest.mark.integration
async def test_unblock_port_endpoint_maps_elevation_cancelled_to_409_and_keeps_the_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    import datetime as dt

    async with migrated_session_maker() as session:
        session.add(BlockedPort(port=8080, protocol="tcp", process_name=None, blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    async def _raising_unblock_port(port, *, all_blocked_ports):
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "unblock_port", _raising_unblock_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert len(rows) == 1  # still blocked — the OS-level unblock never actually happened


@pytest.mark.integration
async def test_unblock_port_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_unblock_port(port, *, all_blocked_ports):
        raise OSFirewallError("iptables exploded", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "unblock_port", _raising_unblock_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}


@pytest.mark.integration
async def test_unblock_port_endpoint_succeeds_even_when_no_row_existed(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Unblocking an already-unblocked port is an honest no-op, not an
    error (see `delete_blocked_port`'s own docstring)."""

    async def _fake_unblock_port(port, *, all_blocked_ports):
        return {"status": "ok", "port": port, "blocked": False}

    monkeypatch.setattr(security_console_module, "unblock_port", _fake_unblock_port)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/perimeter/ports/12345/block", headers=headers)

    assert response.status_code == 200


# ---------------------------------------------------------------------------
# GET /security/consoles/perimeter — ports[].is_blocked enrichment
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_perimeter_console_marks_blocked_ports_true_and_others_false(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    import datetime as dt

    async def _fake_fetch_listening_ports():
        return {
            "connector": {"status": "ok"},
            "open_ports": 2,
            "ports": [
                {"port": 8080, "protocol": "tcp", "pid": 111, "process_name": "nginx"},
                {"port": 5432, "protocol": "tcp", "pid": 222, "process_name": "postgres"},
            ],
        }

    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_fetch_listening_ports)
    async with migrated_session_maker() as session:
        session.add(BlockedPort(port=8080, protocol="tcp", process_name="nginx", blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    headers = await _admin_headers(client, migrated_session_maker)
    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    ports = {row["port"]: row["is_blocked"] for row in response.json()["ports"]}
    assert ports == {8080: True, 5432: False}
