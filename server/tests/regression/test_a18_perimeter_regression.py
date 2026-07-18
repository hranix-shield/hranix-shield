"""A-18 regression anchor.

Per docs/инструкция-разработка-фаза-0-стек-безопасности-2026-07-16.md, this
task adds at least one regression test that must stay green through the
rest of Phase 0 (and beyond, alongside the A-10/A-11 anchors). Pins the core
A-18 contract later tasks (A-15/A-16/A-17's own console wiring) must not
break:
  - GET /security/consoles/perimeter still requires a bearer token;
  - the response always carries a `connectors` dict with exactly the three
    A-18 source ids (`os_firewall`, `disk_encryption`, `crowdsec_bouncer`),
    each with a `status` field, on every request — regardless of what any
    individual source's real status happens to be on the machine running
    the suite;
  - `metrics.firewall_active`/`metrics.disk_encryption_active` are always
    present keys (`bool | None`, never missing, never a fabricated value
    dressed up as real);
  - the endpoint never raises/500s even when every source is failing —
    the "честный пустой экран" contract A-11 established for `ids` extends
    to all three of `perimeter`'s sources here.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user

_KNOWN_CONNECTOR_STATUSES = {"ok", "not_configured", "permission_denied", "unreachable", "unauthorized"}


@pytest.mark.integration
async def test_perimeter_endpoint_still_requires_a_token(client: TestClient):
    response = client.get("/security/consoles/perimeter")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_perimeter_endpoint_always_reports_all_three_sources_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real connectors, whatever this machine's
    actual pf/FileVault/CrowdSec state is — the point of this anchor is the
    *shape* of the contract (three sources, honest statuses, never a crash),
    not any one machine's specific values."""
    await create_user(migrated_session_maker, username="a18_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a18_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert set(body["connectors"].keys()) == {"os_firewall", "disk_encryption", "crowdsec_bouncer"}
    for source in body["connectors"].values():
        assert source["status"] in _KNOWN_CONNECTOR_STATUSES

    assert "firewall_active" in body["metrics"]
    assert "disk_encryption_active" in body["metrics"]
    assert body["metrics"]["firewall_active"] in (True, False, None)
    assert body["metrics"]["disk_encryption_active"] in (True, False, None)


@pytest.mark.integration
async def test_perimeter_endpoint_survives_every_source_failing_at_once(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_firewall():
        return {"connector": {"status": "unreachable"}, "active": None}

    async def _raising_disk_encryption():
        return {"connector": {"status": "unreachable"}, "active": None}

    async def _raising_crowdsec(settings=None):
        return {
            "connector": {"status": "unreachable"},
            "metrics": {"active_bans": None, "banned_24h": None, "scenarios": None, "last_event_at": None},
            "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
            "recent_attempts": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _raising_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _raising_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _raising_crowdsec)
    await create_user(migrated_session_maker, username="a18_regress_fail", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a18_regress_fail", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/perimeter", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    assert all(
        source["status"] == "unreachable" for source in response.json()["connectors"].values()
    )
