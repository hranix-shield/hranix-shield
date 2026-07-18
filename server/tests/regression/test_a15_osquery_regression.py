"""A-15 regression anchor.

Per docs/инструкция-разработка-фаза-0-стек-безопасности-2026-07-16.md, this
task adds at least one regression test that must stay green through the rest
of Phase 0 (and beyond, alongside the A-10/A-11/A-18 anchors). Pins the core
A-15 contract later tasks (A-16/A-17's own `av`/`logs` wiring) must not
break:
  - GET /security/consoles/network and GET /security/consoles/av still
    require a bearer token;
  - `network`'s response always carries a `connector` dict with a `status`
    field, and `metrics.active_connections`/`connections`/`listening_ports`
    are always present keys, on every request — regardless of whether
    `osqueryi` happens to be installed on the machine running the suite;
  - `av`'s response always carries a `connectors` dict with (at least) the
    `osquery` source id, each with a `status` field — a later A-16/A-17 may
    add `wazuh`/`clamav` keys alongside it, but must never remove `osquery`;
  - neither endpoint ever raises/500s even when the osquery connector is
    failing — the "честный пустой экран" contract A-11/A-18 established
    extends to `network`/`av` here.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user

_KNOWN_CONNECTOR_STATUSES = {"ok", "not_configured", "permission_denied", "unreachable", "unauthorized"}


@pytest.mark.integration
@pytest.mark.parametrize("route", ["/security/consoles/network", "/security/consoles/av"])
async def test_network_and_av_endpoints_still_require_a_token(client: TestClient, route: str):
    response = client.get(route)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_network_endpoint_always_reports_a_connector_and_connection_fields_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real osquery connector, whatever this
    machine's actual state is — the point of this anchor is the *shape* of
    the contract (a connector, honest status, never a crash), not any one
    machine's specific values."""
    await create_user(migrated_session_maker, username="a15_network_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a15_network_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert "status" in body["connector"]
    assert body["connector"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert "active_connections" in body["metrics"]
    assert isinstance(body["connections"], list)
    assert isinstance(body["listening_ports"], list)


@pytest.mark.integration
async def test_av_endpoint_always_reports_an_osquery_source_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="a15_av_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a15_av_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert "osquery" in body["connectors"]
    assert body["connectors"]["osquery"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert "osquery_process_count" in body["metrics"]
    assert "status" in body["file_events"]


@pytest.mark.integration
async def test_network_and_av_endpoints_survive_osquery_failing(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_network():
        return {
            "connector": {"status": "unreachable"},
            "connections": [],
            "listening_ports": [],
            "active_connections": None,
        }

    async def _raising_av():
        return {
            "connector": {"status": "unreachable"},
            "process_count": None,
            "file_events": {"status": "not_configured", "count": None, "recent": []},
        }

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _raising_network)
    monkeypatch.setattr(security_console_module, "fetch_av_osquery_data", _raising_av)
    await create_user(migrated_session_maker, username="a15_regress_fail", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a15_regress_fail", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    network_response = client.get("/security/consoles/network", headers=headers)
    av_response = client.get("/security/consoles/av", headers=headers)

    assert network_response.status_code == 200
    assert network_response.json()["connector"]["status"] == "unreachable"
    assert av_response.status_code == 200
    assert av_response.json()["connectors"]["osquery"]["status"] == "unreachable"
