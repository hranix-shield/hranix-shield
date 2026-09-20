"""A-40: `GET /security/consoles/network`'s geoip country enrichment +
CrowdSec reputation cross-reference (`security_console.py._network_payload`
/ `_enrich_connections`) against the real app wiring (client fixture — real
migrated tmp SQLite DB, real HTTP layer via TestClient) — same shape as
test_security_console_network_av.py, which already covers the plain
osquery-backed fields this file does not re-test.

`fetch_network_console_data`/`fetch_active_decision_values`/`resolve_country`
are monkeypatched at their bare names imported into
`app.routers.security_console` (same technique that file's own tests
already use for `fetch_network_console_data`), so these tests need neither
`osqueryi` nor a real CrowdSec/geoip database installed.

A-41 update: two more per-row fields (`lat`/`lon`, `country_centroids.py`'s
`country_centroid()` applied to the already-resolved `country`) and a new
`connectors.geoip.status` reflecting `is_geoip_configured()` — covered here
too, not just in the regression anchor, since this file already owns the
"resolve_country was genuinely exercised with real country codes" fixture
`test_country_is_populated_per_row_from_resolve_country` below uses.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.country_centroids import country_centroid
from tests.common.factories import create_user

_TWO_CONNECTIONS = [
    {
        "process": "python3",
        "pid": 4321,
        "local_address": "127.0.0.1",
        "local_port": 51000,
        "remote_address": "198.51.100.23",  # matches the fake decision below
        "remote_port": 443,
        "protocol": "6",
        "state": "ESTABLISHED",
    },
    {
        "process": "curl",
        "pid": 5555,
        "local_address": "127.0.0.1",
        "local_port": 51001,
        "remote_address": "93.184.216.34",  # does not match
        "remote_port": 443,
        "protocol": "6",
        "state": "ESTABLISHED",
    },
]


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def _fake_network_data():
    return {
        "connector": {"status": "ok"},
        "connections": _TWO_CONNECTIONS,
        "listening_ports": [],
        "active_connections": len(_TWO_CONNECTIONS),
    }


@pytest.mark.integration
async def test_matching_ip_is_flagged_suspicious_and_the_aggregate_count_is_real(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "тестовый бан... подтверждает бейдж «подозрительный»" — exercised
    here with a mocked CrowdSec decision (real live confirmation against the
    actual `hranix-crowdsec` container is the separate live verification
    step, see the A-40 task report)."""

    async def _fake_decision_values():
        return {"connector": {"status": "ok"}, "values": ["198.51.100.23"]}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)
    headers = await _admin_headers(client, migrated_session_maker, "a40_reputation_admin")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    rows = {row["remote_address"]: row for row in body["connections"]}
    assert rows["198.51.100.23"]["is_suspicious"] is True
    assert rows["93.184.216.34"]["is_suspicious"] is False
    # Real sum, not a hardcoded 0 (the exact A-40 DoD line: "Пересчитай
    # metrics.suspicious_connections как реальный count").
    assert body["metrics"]["suspicious_connections"] == 1


@pytest.mark.integration
async def test_no_match_reports_false_not_none_when_crowdsec_was_actually_checked(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_decision_values():
        return {"connector": {"status": "ok"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)
    headers = await _admin_headers(client, migrated_session_maker, "a40_no_match_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    for row in body["connections"]:
        assert row["is_suspicious"] is False
    assert body["metrics"]["suspicious_connections"] == 0


@pytest.mark.integration
async def test_crowdsec_not_configured_leaves_is_suspicious_and_the_metric_honestly_none(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """The exact A-40 DoD line: "если CrowdSec недоступен/не настроен,
    suspicious_connections должен остаться None... не молчаливым 0". Also
    pins the SAME honesty at the per-row level (see `_enrich_connections`'s
    own docstring for why a per-row `False` here would be just as
    misleading as a fabricated aggregate `0`)."""

    async def _fake_decision_values():
        return {"connector": {"status": "not_configured"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)
    headers = await _admin_headers(client, migrated_session_maker, "a40_not_configured_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    assert body["metrics"]["suspicious_connections"] is None
    for row in body["connections"]:
        assert row["is_suspicious"] is None


@pytest.mark.integration
async def test_crowdsec_unreachable_also_leaves_the_metric_honestly_none(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_decision_values():
        return {"connector": {"status": "unreachable"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)
    headers = await _admin_headers(client, migrated_session_maker, "a40_unreachable_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    assert body["metrics"]["suspicious_connections"] is None


@pytest.mark.integration
async def test_country_is_populated_per_row_from_resolve_country(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_decision_values():
        return {"connector": {"status": "not_configured"}, "values": []}

    def _fake_resolve_country(ip, **kwargs):
        return {"198.51.100.23": "US", "93.184.216.34": "DE"}.get(ip)

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", _fake_resolve_country)
    headers = await _admin_headers(client, migrated_session_maker, "a40_country_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    rows = {row["remote_address"]: row for row in body["connections"]}
    assert rows["198.51.100.23"]["country"] == "US"
    assert rows["93.184.216.34"]["country"] == "DE"
    # A-41: `lat`/`lon` are the REAL country_centroids.py values for the
    # resolved country — not independently re-derived here, so this stays
    # correct even if the table's own numbers are later refined.
    us_lat, us_lon = country_centroid("US")
    de_lat, de_lon = country_centroid("DE")
    assert rows["198.51.100.23"]["lat"] == us_lat
    assert rows["198.51.100.23"]["lon"] == us_lon
    assert rows["93.184.216.34"]["lat"] == de_lat
    assert rows["93.184.216.34"]["lon"] == de_lon


@pytest.mark.integration
async def test_unresolved_country_gets_honestly_null_lat_lon_not_a_fabricated_origin(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A row with no resolved `country` at all must get `lat`/`lon` `None`/
    `None`, never a fabricated `(0.0, 0.0)` — see country_centroids.py's own
    docstring for why that specific fallback would be a fabrication (it is a
    real point in the Gulf of Guinea, not "unknown")."""

    async def _fake_decision_values():
        return {"connector": {"status": "not_configured"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)
    headers = await _admin_headers(client, migrated_session_maker, "a41_unresolved_lat_lon_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    for row in body["connections"]:
        assert row["country"] is None
        assert row["lat"] is None
        assert row["lon"] is None


@pytest.mark.integration
async def test_a_real_country_code_absent_from_the_centroid_table_also_degrades_honestly(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A `country` that DID resolve (geoip.py found a real code), but this
    build's small centroid table simply does not carry yet — `lat`/`lon`
    still degrade to honest `None`/`None`, not a crash and not a fabricated
    coordinate. Uses a syntactically-plausible but genuinely unassigned ISO
    3166-1 alpha-2 code ("ZZ", reserved by the standard itself as
    user-assignable/never a real country) so this test does not depend on
    the centroid table's exact current contents ever staying incomplete."""

    async def _fake_decision_values():
        return {"connector": {"status": "not_configured"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: "ZZ")
    headers = await _admin_headers(client, migrated_session_maker, "a41_uncovered_country_admin")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    for row in body["connections"]:
        assert row["country"] == "ZZ"
        assert row["lat"] is None
        assert row["lon"] is None


@pytest.mark.integration
async def test_connectors_geoip_status_reflects_is_geoip_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`connectors.geoip.status` (A-41) is what `app.js`'s map uses to show
    its honest "GeoIP не настроен" placeholder — pinned deterministically in
    both directions here via `is_geoip_configured` (bare name, same
    monkeypatch technique this file already uses for every other
    connector-status field)."""

    async def _fake_decision_values():
        return {"connector": {"status": "not_configured"}, "values": []}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", lambda ip, **kwargs: None)

    monkeypatch.setattr(security_console_module, "is_geoip_configured", lambda: True)
    headers = await _admin_headers(client, migrated_session_maker, "a41_geoip_ok_admin")
    response = client.get("/security/consoles/network", headers=headers)
    assert response.json()["connectors"]["geoip"] == {"status": "ok"}

    monkeypatch.setattr(security_console_module, "is_geoip_configured", lambda: False)
    headers = await _admin_headers(client, migrated_session_maker, "a41_geoip_not_configured_admin")
    response = client.get("/security/consoles/network", headers=headers)
    assert response.json()["connectors"]["geoip"] == {"status": "not_configured"}


@pytest.mark.integration
async def test_no_connections_never_500s_and_reports_none_suspicious(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _empty_network_data():
        return {"connector": {"status": "ok"}, "connections": [], "listening_ports": [], "active_connections": 0}

    async def _fake_decision_values():
        return {"connector": {"status": "ok"}, "values": ["198.51.100.23"]}

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _empty_network_data)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    headers = await _admin_headers(client, migrated_session_maker, "a40_empty_admin")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connections"] == []
    # CrowdSec WAS reachable (status "ok"), just nothing to sum over — a
    # real 0, not a `None`.
    assert body["metrics"]["suspicious_connections"] == 0
