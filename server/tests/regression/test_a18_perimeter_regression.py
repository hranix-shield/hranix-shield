"""A-18 regression anchor (loosened by A-28, see below).

Per docs/инструкция-разработка-фаза-0-стек-безопасности-2026-07-16.md, this
task adds at least one regression test that must stay green through the
rest of Phase 0 (and beyond, alongside the A-10/A-11 anchors). Pins the core
A-18 contract later tasks (A-15/A-16/A-17's own console wiring) must not
break:
  - GET /security/consoles/perimeter still requires a bearer token;
  - the response always carries a `connectors` dict with AT LEAST the three
    original A-18 source ids (`os_firewall`, `disk_encryption`,
    `crowdsec_bouncer`), each with a `status` field, on every request —
    regardless of what any individual source's real status happens to be on
    the machine running the suite;
  - `metrics.firewall_active`/`metrics.disk_encryption_active` are always
    present keys (`bool | None`, never missing, never a fabricated value
    dressed up as real);
  - the endpoint never raises/500s even when every source is failing —
    the "честный пустой экран" contract A-11 established for `ids` extends
    to all of `perimeter`'s sources here.

A-28 addendum: originally this anchor asserted `connectors.keys()` was
EXACTLY `{os_firewall, disk_encryption, crowdsec_bouncer}` — too strict once
A-28 legitimately added two more real sources (`osquery` for `open_ports`,
`firewall_rules` for the pf/netsh/iptables ruleset listing). Loosened here to
an "at least" check, the same future-proof shape
`test_a15_osquery_regression.py`'s own `av`-console anchor already uses for
exactly this reason ("a later A-16/A-17 may add wazuh/clamav keys alongside
it, but must never remove osquery") — this file adopts that same wording for
perimeter's three original keys, and adds its own A-28 anchor test below for
the two new ones, rather than only editing this file's assertions in place
and losing the "why" of the change.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.os_firewall import OSFirewallError
from tests.common.factories import create_user

_KNOWN_CONNECTOR_STATUSES = {"ok", "not_configured", "permission_denied", "unreachable", "unauthorized"}


@pytest.mark.integration
async def test_perimeter_endpoint_still_requires_a_token(client: TestClient):
    response = client.get("/security/consoles/perimeter")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_perimeter_endpoint_always_reports_the_original_three_sources_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real connectors, whatever this machine's
    actual pf/FileVault/CrowdSec/osquery state is — the point of this anchor
    is the *shape* of the contract (at least these three sources, honest
    statuses, never a crash), not any one machine's specific values."""
    await create_user(migrated_session_maker, username="a18_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a18_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert {"os_firewall", "disk_encryption", "crowdsec_bouncer"} <= set(body["connectors"].keys())
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

    async def _raising_ports():
        return {"connector": {"status": "unreachable"}, "open_ports": None, "ports": []}

    async def _raising_rules():
        return {"connector": {"status": "unreachable"}, "count": None}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _raising_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _raising_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _raising_crowdsec)
    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _raising_ports)
    monkeypatch.setattr(security_console_module, "fetch_firewall_rules", _raising_rules)
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


# ---------------------------------------------------------------------------
# A-28 regression anchor: perimeter's two new real sources
# (`open_ports`/`firewall_rules`, no longer hardcoded 0) and the new
# "Пересканировать порты" endpoint. Pins the contract A-29/A-30 (parallel,
# independent tasks touching the same two files) must not break.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_perimeter_endpoint_always_reports_osquery_and_firewall_rules_sources_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real `fetch_listening_ports()`/
    `fetch_firewall_rules()`, whatever this machine's actual osquery/pf
    state is — same "shape, not values" anchor philosophy as the A-18 test
    above."""
    await create_user(migrated_session_maker, username="a28_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a28_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert "osquery" in body["connectors"]
    assert "firewall_rules" in body["connectors"]
    assert body["connectors"]["osquery"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert body["connectors"]["firewall_rules"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert "open_ports" in body["metrics"]
    assert "firewall_rules" in body["metrics"]
    assert body["metrics"]["open_ports"] is None or isinstance(body["metrics"]["open_ports"], int)
    assert body["metrics"]["firewall_rules"] is None or isinstance(body["metrics"]["firewall_rules"], int)
    # A-31 regression anchor: `ports` (the per-port detail list) is always
    # present and always a list — its length must track `metrics.open_ports`
    # whenever the osquery source is genuinely `ok` (both come from the same
    # `fetch_listening_ports()` call — see osquery.py's docstring), never
    # length-mismatched.
    assert isinstance(body["ports"], list)
    if body["connectors"]["osquery"]["status"] == "ok":
        assert len(body["ports"]) == body["metrics"]["open_ports"]


@pytest.mark.integration
async def test_rescan_ports_endpoint_still_requires_a_token_and_never_500s(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    unauth_response = client.post("/security/consoles/perimeter/rescan-ports")
    assert unauth_response.status_code == 401
    assert unauth_response.json()["detail"] == {"error": "not_authenticated"}

    await create_user(migrated_session_maker, username="a28_rescan_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a28_rescan_regress", "password": "pw"}
    ).json()["access_token"]

    response = client.post(
        "/security/consoles/perimeter/rescan-ports", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connector"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert "open_ports" in body
    assert isinstance(body["ports"], list)


# ---------------------------------------------------------------------------
# A-36 regression anchor: the three new ELEVATED endpoints
# (firewall/rules, firewall/block-all, firewall/unblock-all). Every case
# below MUST monkeypatch `read_firewall_rules`/`block_all_incoming`/
# `unblock_all_incoming` — calling the REAL (unmocked) versions here would
# pop a genuine OS admin-password dialog and hang this automated suite
# waiting on a human, which must never happen in a regression run. Pins
# the contract A-37 (per-port blocking, next task in this same series,
# see the plan document's "Порядок разработки") must not break: all three
# routes require a token, never 500, and `elevation_cancelled`/
# `elevation_failed` map to their own distinct, non-500 HTTP statuses
# (409/502) rather than collapsing into a single generic error.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_a36_elevated_firewall_endpoints_all_require_a_token(client: TestClient):
    for path in (
        "/security/consoles/perimeter/firewall/rules",
        "/security/consoles/perimeter/firewall/block-all",
        "/security/consoles/perimeter/firewall/unblock-all",
    ):
        response = client.post(path)
        assert response.status_code == 401
        assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a36_elevated_firewall_endpoints_never_500_on_a_typed_os_firewall_error(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_read_firewall_rules():
        raise OSFirewallError("boom", reason="elevation_failed")

    async def _raising_block_all_incoming():
        raise OSFirewallError("boom", reason="elevation_cancelled")

    async def _raising_unblock_all_incoming():
        raise OSFirewallError("boom", reason="not_configured")

    monkeypatch.setattr(security_console_module, "read_firewall_rules", _raising_read_firewall_rules)
    monkeypatch.setattr(security_console_module, "block_all_incoming", _raising_block_all_incoming)
    monkeypatch.setattr(security_console_module, "unblock_all_incoming", _raising_unblock_all_incoming)
    await create_user(migrated_session_maker, username="a36_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a36_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    rules_response = client.post("/security/consoles/perimeter/firewall/rules", headers=headers)
    block_response = client.post("/security/consoles/perimeter/firewall/block-all", headers=headers)
    unblock_response = client.post("/security/consoles/perimeter/firewall/unblock-all", headers=headers)

    assert rules_response.status_code == 502
    assert rules_response.json()["detail"] == {"error": "elevation_failed"}
    # `elevation_cancelled` must never collapse into the same status/code
    # as `elevation_failed` — the DoD's own "never conflate" requirement.
    assert block_response.status_code == 409
    assert block_response.json()["detail"] == {"error": "elevation_cancelled"}
    assert block_response.status_code != rules_response.status_code
    assert unblock_response.status_code == 503
    assert unblock_response.json()["detail"] == {"error": "connector_not_configured"}


# ---------------------------------------------------------------------------
# A-37 regression anchor: per-port block/unblock
# (POST/DELETE .../ports/{port}/block) and `ports[].is_blocked`. Pins the
# contract this series' next task (whichever comes after A-37, see the plan
# document's "Порядок разработки") must not break: both routes require a
# token, never 500 on a typed OSFirewallError, `elevation_cancelled`/
# `elevation_failed`/`not_configured` map to their own distinct, non-500
# HTTP statuses exactly like the A-36 anchor above, and `GET
# /consoles/perimeter`'s `ports[]` rows always carry a real boolean
# `is_blocked` key.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_a37_port_block_unblock_endpoints_require_a_token(client: TestClient):
    block_response = client.post("/security/consoles/perimeter/ports/8080/block")
    unblock_response = client.delete("/security/consoles/perimeter/ports/8080/block")

    assert block_response.status_code == 401
    assert block_response.json()["detail"] == {"error": "not_authenticated"}
    assert unblock_response.status_code == 401
    assert unblock_response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a37_port_block_unblock_endpoints_never_500_on_a_typed_os_firewall_error(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_block_port(port, *, all_blocked_ports):
        raise OSFirewallError("boom", reason="elevation_cancelled")

    async def _raising_unblock_port(port, *, all_blocked_ports):
        raise OSFirewallError("boom", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "block_port", _raising_block_port)
    monkeypatch.setattr(security_console_module, "unblock_port", _raising_unblock_port)
    await create_user(migrated_session_maker, username="a37_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a37_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    block_response = client.post("/security/consoles/perimeter/ports/8080/block", headers=headers)
    unblock_response = client.delete("/security/consoles/perimeter/ports/8080/block", headers=headers)

    assert block_response.status_code == 409
    assert block_response.json()["detail"] == {"error": "elevation_cancelled"}
    assert unblock_response.status_code == 502
    assert unblock_response.json()["detail"] == {"error": "elevation_failed"}
    assert block_response.status_code != unblock_response.status_code


@pytest.mark.integration
async def test_a37_perimeter_ports_always_carry_a_real_is_blocked_boolean(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real `fetch_listening_ports()` +
    `list_blocked_ports()`, whatever this machine's actual open-ports/
    blocked_ports-table state is — same "shape, not values" anchor
    philosophy as the A-18/A-28 tests above."""
    await create_user(migrated_session_maker, username="a37_shape_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a37_shape_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    for row in response.json()["ports"]:
        assert isinstance(row["is_blocked"], bool)


@pytest.mark.integration
async def test_a37_blocked_port_is_real_persistence_not_process_memory(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """The DoD-defining regression anchor for A-37, same "in-process proxy
    for survives a server restart" technique
    tests/regression/test_a33_scan_history_regression.py's own anchor
    already established for `scan_history`: a `blocked_ports` row written
    through one `AsyncSession` must be readable back — as `is_blocked:
    true` on the matching `ports[]` row — through a COMPLETELY INDEPENDENT
    session from the same session maker (the real restart, with a real
    `kill`+relaunch of the uvicorn process, is exercised live outside
    pytest, per this task's own DoD; see this task's own report)."""
    import datetime as dt

    from app.db.models import BlockedPort

    async with migrated_session_maker() as write_session:
        write_session.add(
            BlockedPort(port=8080, protocol="tcp", process_name="nginx", blocked_at=dt.datetime(2026, 1, 1))
        )
        await write_session.commit()

    async def _fake_ports():
        return {
            "connector": {"status": "ok"},
            "open_ports": 1,
            "ports": [{"port": 8080, "protocol": "tcp", "pid": 111, "process_name": "nginx"}],
        }

    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    await create_user(migrated_session_maker, username="a37_persist_regress", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "a37_persist_regress", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/perimeter", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    ports = response.json()["ports"]
    assert len(ports) == 1
    assert ports[0]["is_blocked"] is True
