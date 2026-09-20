"""A-18: GET /security/consoles/perimeter against the real app wiring
(client fixture — real migrated tmp SQLite DB, real HTTP layer via
TestClient), exercising the router's real (non-stub) source-backed fields —
same shape as test_security_console_ids_crowdsec.py for `ids`, but covering
several independent connectors instead of one:
  - CrowdSec bouncer (A-11, reused here — never a second implementation)
  - os_firewall (A-18)
  - os_disk_encryption (A-18)
  - osquery's `listening_ports` -> `open_ports` (A-28, reused from `network`)
  - os_firewall's rule-listing -> `firewall_rules` (A-28, a distinct pf/
    netsh/iptables invocation from the on/off toggle above, see
    os_firewall.py.fetch_firewall_rules()'s docstring)

`fetch_ids_console_data`/`fetch_firewall_status`/`fetch_disk_encryption_status`/
`fetch_listening_ports`/`fetch_firewall_rules` are monkeypatched at their bare
names imported into `app.routers.security_console`, same technique
test_security_console_ids_crowdsec.py already uses, so none of these tests
needs a real CrowdSec container, a real `osqueryi` binary, nor depends on the
host OS's actual firewall/disk-encryption/ruleset state. The one test that
does NOT monkeypatch CrowdSec
(`test_perimeter_console_reflects_a_real_unconfigured_crowdsec_by_default`)
exercises the genuinely-live default path the same way that file's own
"not_configured by default" test does — os_firewall/os_disk_encryption/
osquery/firewall_rules stay monkeypatched there too, for the same
determinism reason its own docstring already gives.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "perimeter_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _ok_crowdsec():
    return {
        "connector": {"status": "ok"},
        "metrics": {
            "active_bans": 3,
            "active_bans_local": 0,
            "active_bans_community": 3,
            "banned_24h": None,
            "scenarios": 2,
            "last_event_at": None,
        },
        "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
        "recent_attempts": [],
    }


def _not_configured_crowdsec():
    return {
        "connector": {"status": "not_configured"},
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


def _patch_a28_sources_ok(monkeypatch: pytest.MonkeyPatch, *, open_ports: int = 7, rule_count: int = 42) -> None:
    """A-28's two new sources, faked to a deterministic `ok` — shared by the
    tests below that don't care about their specific failure modes (those
    get their own dedicated fakes, see `test_perimeter_console_never_500s_...`).

    A-31: `ports` is a fixture row list padded/truncated to `open_ports`
    entries so `len(ports) == open_ports` stays true (the real connector's
    own invariant, see osquery.py's `fetch_listening_ports` docstring) even
    though the tests exercising this fixture only ever assert on the count."""

    async def _fake_ports():
        ports = [
            {"port": 1000 + i, "protocol": "tcp", "pid": 100 + i, "process_name": f"proc{i}"}
            for i in range(open_ports)
        ]
        return {"connector": {"status": "ok"}, "open_ports": open_ports, "ports": ports}

    async def _fake_rules():
        return {"connector": {"status": "ok"}, "count": rule_count}

    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    monkeypatch.setattr(security_console_module, "fetch_firewall_rules", _fake_rules)


def _ok_network_profile():
    return {
        "connector": {"status": "ok"},
        "current": {
            "network_key": "wifi:HomeWifi",
            "display_name": "HomeWifi",
            "kind": "wifi",
            "id_kind": "ssid",
            "category": "public",
        },
        "known": [],
    }


def _patch_a38_network_profile_ok(monkeypatch: pytest.MonkeyPatch) -> None:
    """A-38's own new source, faked to a deterministic `ok` — same
    "replace the whole imported-into-router callable" technique every other
    fake in this file already uses (`network_profile_payload` is a pure
    read, see network_profile.py's own docstring, so faking it here needs
    no DB interaction at all)."""

    async def _fake_network_profile(session):
        return _ok_network_profile()

    monkeypatch.setattr(security_console_module, "network_profile_payload", _fake_network_profile)


@pytest.mark.integration
async def test_perimeter_console_surfaces_all_five_sources_when_everything_is_ok(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "все источники видны в ответе GET /security/consoles/perimeter"."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": False}

    async def _fake_crowdsec(settings=None):
        return _ok_crowdsec()

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    _patch_a28_sources_ok(monkeypatch, open_ports=7, rule_count=42)
    _patch_a38_network_profile_ok(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "perimeter"
    assert body["connectors"] == {
        "os_firewall": {"status": "ok"},
        "disk_encryption": {"status": "ok"},
        "crowdsec_bouncer": {"status": "ok"},
        "osquery": {"status": "ok"},
        "firewall_rules": {"status": "ok"},
    }
    assert body["metrics"]["firewall_active"] is True
    assert body["metrics"]["disk_encryption_active"] is False
    assert body["metrics"]["crowdsec_active_bans"] == 3
    # Замечание пользователя (2026-07-31): текущий local/community split
    # прямо в metrics (не только 7-дневная история в chart) — тот же split
    # A-23 уже даёт для ids.
    assert body["metrics"]["active_bans_local"] == 0
    assert body["metrics"]["active_bans_community"] == 3
    # A-28: no longer hardcoded 0 — real counts from the two new sources.
    assert body["metrics"]["open_ports"] == 7
    assert body["metrics"]["firewall_rules"] == 42
    # A-31: the per-port detail itself (process/pid/protocol), not only its
    # count — proves it is genuinely proxied through, not dropped in transit.
    # A-37: each row also carries `is_blocked` (False here — no
    # `blocked_ports` DB row exists for it in this test's fresh migrated
    # DB, see security_console.py._perimeter_payload's A-37 addendum).
    assert len(body["ports"]) == 7
    assert body["ports"][0] == {
        "port": 1000, "protocol": "tcp", "pid": 100, "process_name": "proc0", "is_blocked": False,
    }
    # Toggle-backed fields (A-10) are untouched by A-18/A-28's connector wiring.
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert body["engine"] == [
        "os_firewall", "bitlocker_filevault", "crowdsec_bouncer", "osquery", "network_profile",
    ]
    assert "settings" in body
    # A-38: the new top-level `network_profile` key — a NEW kind of context
    # (not folded into `connectors` above, see _perimeter_payload's own
    # docstring), proxied through verbatim.
    assert body["network_profile"] == _ok_network_profile()


@pytest.mark.integration
async def test_perimeter_console_never_500s_when_every_source_fails(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD failure scenario: unsupported platform/no privileges/unreachable
    CrowdSec/no osqueryi/pf denied — the endpoint must still answer 200 with
    honest per-source statuses, never a 500 and never a fabricated
    all-clear."""

    async def _fake_firewall():
        return {"connector": {"status": "permission_denied"}, "active": None}

    async def _fake_disk_encryption():
        return {"connector": {"status": "not_configured"}, "active": None}

    async def _fake_crowdsec(settings=None):
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

    async def _fake_ports():
        return {"connector": {"status": "not_configured"}, "open_ports": None, "ports": []}

    async def _fake_rules():
        return {"connector": {"status": "permission_denied"}, "count": None}

    async def _fake_network_profile(session):
        return {
            "connector": {"status": "not_connected"},
            "current": {
                "network_key": None, "display_name": None, "kind": None,
                "id_kind": None, "category": None,
            },
            "known": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    monkeypatch.setattr(security_console_module, "fetch_firewall_rules", _fake_rules)
    monkeypatch.setattr(security_console_module, "network_profile_payload", _fake_network_profile)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"] == {
        "os_firewall": {"status": "permission_denied"},
        "disk_encryption": {"status": "not_configured"},
        "crowdsec_bouncer": {"status": "unreachable"},
        "osquery": {"status": "not_configured"},
        "firewall_rules": {"status": "permission_denied"},
    }
    assert body["metrics"]["firewall_active"] is None
    assert body["metrics"]["disk_encryption_active"] is None
    assert body["metrics"]["crowdsec_active_bans"] is None
    assert body["metrics"]["active_bans_local"] is None
    assert body["metrics"]["active_bans_community"] is None
    assert body["metrics"]["open_ports"] is None
    assert body["metrics"]["firewall_rules"] is None
    # A-31: an honestly-empty ports list, never a fabricated one, when the
    # osquery source itself is not_configured.
    assert body["ports"] == []
    # A-38: a genuinely undetectable network is its own honest state, never
    # a 500 and never a fabricated category.
    assert body["network_profile"]["connector"]["status"] == "not_connected"
    assert body["network_profile"]["current"]["category"] is None


@pytest.mark.integration
async def test_perimeter_console_reflects_a_real_unconfigured_crowdsec_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
):
    """No CrowdSec monkeypatching here: real `fetch_ids_console_data` runs
    against real (test-default) Settings, which have no
    CROWDSEC_LAPI_URL/CROWDSEC_API_KEY set — same honest not_configured this
    task's brief requires. os_firewall/os_disk_encryption/osquery/
    firewall_rules ARE monkeypatched (their true value depends on the
    machine actually running this test suite, which must not leak into a
    deterministic assertion here — the live cross-check against this dev
    machine's real pf/FileVault/open-ports state is done separately, by
    hand, not by this automated test)."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": False}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    _patch_a28_sources_ok(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"]["crowdsec_bouncer"] == {"status": "not_configured"}
    assert body["metrics"]["crowdsec_active_bans"] is None
    assert body["metrics"]["active_bans_local"] is None
    assert body["metrics"]["active_bans_community"] is None


@pytest.mark.integration
async def test_perimeter_console_reuses_the_same_crowdsec_data_as_the_ids_console(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: this task reuses A-11's existing CrowdSec connector, it does not
    build a second one — proven here by pointing the same monkeypatched
    `fetch_ids_console_data` at both /security/consoles/ids and
    /security/consoles/perimeter and checking both reflect it identically."""

    async def _fake_crowdsec(settings=None):
        return _ok_crowdsec()

    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    _patch_a28_sources_ok(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    ids_response = client.get("/security/consoles/ids", headers=headers)
    perimeter_response = client.get("/security/consoles/perimeter", headers=headers)

    assert ids_response.json()["connector"] == {"status": "ok"}
    assert ids_response.json()["metrics"]["active_bans"] == 3
    assert ids_response.json()["metrics"]["active_bans_local"] == 0
    assert perimeter_response.json()["connectors"]["crowdsec_bouncer"] == {"status": "ok"}
    assert perimeter_response.json()["metrics"]["crowdsec_active_bans"] == 3
    assert perimeter_response.json()["metrics"]["active_bans_local"] == 0
    assert perimeter_response.json()["metrics"]["active_bans_community"] == 3


# ---------------------------------------------------------------------------
# A-28: POST /security/consoles/perimeter/rescan-ports — the "Пересканировать
# порты" button's real endpoint. Reuses `fetch_listening_ports()` verbatim
# (monkeypatched here the same way the GET tests above do), it is not a
# second implementation of the osquery query.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_rescan_ports_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/perimeter/rescan-ports")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_rescan_ports_endpoint_returns_the_real_open_port_count(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_ports():
        ports = [{"port": 22, "protocol": "tcp", "pid": 1, "process_name": "sshd"}]
        return {"connector": {"status": "ok"}, "open_ports": 5, "ports": ports}

    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/rescan-ports", headers=headers)

    assert response.status_code == 200
    # A-31: this endpoint returns fetch_listening_ports()'s own payload
    # verbatim (see the router's docstring) — `ports` is proxied through
    # unmodified, same as `open_ports`.
    assert response.json() == {
        "connector": {"status": "ok"},
        "open_ports": 5,
        "ports": [{"port": 22, "protocol": "tcp", "pid": 1, "process_name": "sshd"}],
    }


@pytest.mark.integration
async def test_rescan_ports_endpoint_never_500s_when_osquery_fails(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_ports():
        return {"connector": {"status": "not_configured"}, "open_ports": None, "ports": []}

    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/perimeter/rescan-ports", headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "connector": {"status": "not_configured"},
        "open_ports": None,
        "ports": [],
    }
