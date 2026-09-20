"""A-52: `POST/DELETE /security/consoles/network/ips/{ip}/block` and
`POST /security/consoles/network/processes/{pid}/terminate` against the
real app wiring (client fixture — real migrated tmp SQLite DB, real HTTP
layer via TestClient) — same "monkeypatch at the bare name imported into
app.routers.security_console" technique
tests/integration/test_security_console_perimeter_ports.py already uses
for A-37's near-identical per-port block/unblock, so none of this needs a
real macOS host/real `osascript`/a real system password prompt (that live
coverage is this task's own report, done by hand — see
docs/отчёт-о-доработке-фаза-0-сеть-доработка-2026-08-17.md).

Also covers `GET /security/consoles/network`'s new `connections[].is_blocked`
enrichment (security_console.py's A-52 addendum to `_enrich_connections`).
"""

from __future__ import annotations

import datetime as dt

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.db.models import BlockedIp
from app.services.mcp.security_connectors.os_firewall import OSFirewallError
from app.services.mcp.security_connectors.os_processes import OSProcessError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "network_actions_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/network/ips/{ip}/block
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_block_ip_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/network/ips/8.8.8.8/block")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_block_ip_endpoint_succeeds_and_persists_a_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_block_ip(ip, *, all_blocked_ips):
        captured["ip"] = ip
        captured["all_blocked_ips"] = all_blocked_ips
        return {"status": "ok", "ip": ip, "blocked": True}

    monkeypatch.setattr(security_console_module, "block_ip", _fake_block_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/network/ips/8.8.8.8/block",
        headers=headers,
        json={"country": "US", "process_name": "curl", "reason": "Подозрительный узел"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "ip": "8.8.8.8", "blocked": True}
    assert captured["ip"] == "8.8.8.8"
    assert captured["all_blocked_ips"] == ["8.8.8.8"]

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert len(rows) == 1
    assert rows[0].ip == "8.8.8.8"
    assert rows[0].country == "US"
    assert rows[0].reason == "Подозрительный узел"


@pytest.mark.integration
async def test_block_ip_endpoint_maps_invalid_ip_to_422_and_does_not_persist(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_ip(ip, *, all_blocked_ips):
        raise OSFirewallError("not a valid IP", reason="invalid_ip")

    monkeypatch.setattr(security_console_module, "block_ip", _raising_block_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/network/ips/not-an-ip/block", headers=headers)

    assert response.status_code == 422
    assert response.json()["detail"] == {"error": "invalid_ip"}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert rows == []


@pytest.mark.integration
async def test_block_ip_endpoint_maps_elevation_cancelled_to_409_and_does_not_persist(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_ip(ip, *, all_blocked_ips):
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "block_ip", _raising_block_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/network/ips/8.8.8.8/block", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert rows == []


@pytest.mark.integration
async def test_block_ip_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_ip(ip, *, all_blocked_ips):
        raise OSFirewallError("pfctl exploded", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "block_ip", _raising_block_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/network/ips/8.8.8.8/block", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}


# ---------------------------------------------------------------------------
# DELETE /security/consoles/network/ips/{ip}/block
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_unblock_ip_endpoint_requires_a_token(client: TestClient):
    response = client.delete("/security/consoles/network/ips/8.8.8.8/block")

    assert response.status_code == 401


@pytest.mark.integration
async def test_unblock_ip_endpoint_succeeds_and_removes_the_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async with migrated_session_maker() as session:
        session.add(BlockedIp(ip="8.8.8.8", country="US", process_name=None, reason=None, blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    async def _fake_unblock_ip(ip, *, all_blocked_ips):
        return {"status": "ok", "ip": ip, "blocked": False}

    monkeypatch.setattr(security_console_module, "unblock_ip", _fake_unblock_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/network/ips/8.8.8.8/block", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "ip": "8.8.8.8", "blocked": False}
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert rows == []


@pytest.mark.integration
async def test_unblock_ip_endpoint_maps_elevation_cancelled_to_409_and_keeps_the_row(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async with migrated_session_maker() as session:
        session.add(BlockedIp(ip="8.8.8.8", country=None, process_name=None, reason=None, blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    async def _raising_unblock_ip(ip, *, all_blocked_ips):
        raise OSFirewallError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "unblock_ip", _raising_unblock_ip)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.delete("/security/consoles/network/ips/8.8.8.8/block", headers=headers)

    assert response.status_code == 409
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert len(rows) == 1  # still blocked — the OS-level unblock never actually happened


# ---------------------------------------------------------------------------
# POST /security/consoles/network/processes/{pid}/terminate
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_terminate_process_endpoint_requires_a_token(client: TestClient):
    response = client.post(
        "/security/consoles/network/processes/1234/terminate", json={"process_name": "sleep"}
    )

    assert response.status_code == 401


@pytest.mark.integration
async def test_terminate_process_endpoint_requires_a_process_name_in_the_body(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/network/processes/1234/terminate", headers=headers, json={})

    assert response.status_code == 422  # FastAPI's own body-validation, process_name is required


@pytest.mark.integration
async def test_terminate_process_endpoint_succeeds(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_terminate(pid, expected_name):
        captured["pid"] = pid
        captured["expected_name"] = expected_name
        return {"status": "ok", "pid": pid, "terminated": True}

    monkeypatch.setattr(security_console_module, "terminate_process", _fake_terminate)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/network/processes/4321/terminate",
        headers=headers,
        json={"process_name": "python3"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "pid": 4321, "terminated": True}
    assert captured == {"pid": 4321, "expected_name": "python3"}


@pytest.mark.integration
async def test_terminate_process_endpoint_maps_identity_mismatch_to_409(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_terminate(pid, expected_name):
        raise OSProcessError("mismatch", reason="process_identity_mismatch")

    monkeypatch.setattr(security_console_module, "terminate_process", _raising_terminate)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/network/processes/4321/terminate",
        headers=headers,
        json={"process_name": "python3"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "process_identity_mismatch"}


@pytest.mark.integration
async def test_terminate_process_endpoint_maps_elevation_cancelled_to_409(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_terminate(pid, expected_name):
        raise OSProcessError("declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "terminate_process", _raising_terminate)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/network/processes/4321/terminate",
        headers=headers,
        json={"process_name": "python3"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}


@pytest.mark.integration
async def test_terminate_process_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_terminate(pid, expected_name):
        raise OSProcessError("boom", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "terminate_process", _raising_terminate)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/network/processes/4321/terminate",
        headers=headers,
        json={"process_name": "python3"},
    )

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}


# ---------------------------------------------------------------------------
# GET /security/consoles/network — connections[].is_blocked enrichment
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_network_console_marks_blocked_ips_true_and_others_false(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_fetch_network_console_data():
        return {
            "connector": {"status": "ok"},
            "connections": [
                {"process": "curl", "pid": 111, "local_address": "10.0.0.5", "local_port": 5000,
                 "remote_address": "8.8.8.8", "remote_port": 443, "protocol": "6", "state": "ESTABLISHED"},
                {"process": "ssh", "pid": 222, "local_address": "10.0.0.5", "local_port": 5001,
                 "remote_address": "1.1.1.1", "remote_port": 22, "protocol": "6", "state": "ESTABLISHED"},
            ],
            "listening_ports": [],
            "active_connections": 2,
        }

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_fetch_network_console_data)
    async with migrated_session_maker() as session:
        session.add(BlockedIp(ip="8.8.8.8", country=None, process_name=None, reason=None, blocked_at=dt.datetime(2026, 1, 1)))
        await session.commit()

    headers = await _admin_headers(client, migrated_session_maker)
    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    by_remote = {row["remote_address"]: row["is_blocked"] for row in response.json()["connections"]}
    assert by_remote == {"8.8.8.8": True, "1.1.1.1": False}
