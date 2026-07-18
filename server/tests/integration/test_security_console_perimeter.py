"""A-18: GET /security/consoles/perimeter against the real app wiring
(client fixture — real migrated tmp SQLite DB, real HTTP layer via
TestClient), exercising the router's real (non-stub) three-source-backed
fields — same shape as test_security_console_ids_crowdsec.py for `ids`, but
covering three independent connectors instead of one:
  - CrowdSec bouncer (A-11, reused here — never a second implementation)
  - os_firewall (new this task)
  - os_disk_encryption (new this task)

`fetch_ids_console_data`/`fetch_firewall_status`/`fetch_disk_encryption_status`
are monkeypatched at their bare names imported into
`app.routers.security_console`, same technique
test_security_console_ids_crowdsec.py already uses, so none of these tests
needs a real CrowdSec container nor depends on the host OS's actual
firewall/disk-encryption state. The one test that does NOT monkeypatch
anything (`test_perimeter_console_reflects_a_real_unconfigured_crowdsec_by_default`)
exercises the genuinely-live default path the same way that file's own
"not_configured by default" test does.
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
        "metrics": {"active_bans": 3, "banned_24h": None, "scenarios": 2, "last_event_at": None},
        "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
        "recent_attempts": [],
    }


def _not_configured_crowdsec():
    return {
        "connector": {"status": "not_configured"},
        "metrics": {"active_bans": None, "banned_24h": None, "scenarios": None, "last_event_at": None},
        "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
        "recent_attempts": [],
    }


@pytest.mark.integration
async def test_perimeter_console_surfaces_all_three_sources_when_everything_is_ok(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "все три источника видны в ответе GET /security/consoles/perimeter"."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": False}

    async def _fake_crowdsec(settings=None):
        return _ok_crowdsec()

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "perimeter"
    assert body["connectors"] == {
        "os_firewall": {"status": "ok"},
        "disk_encryption": {"status": "ok"},
        "crowdsec_bouncer": {"status": "ok"},
    }
    assert body["metrics"]["firewall_active"] is True
    assert body["metrics"]["disk_encryption_active"] is False
    assert body["metrics"]["crowdsec_active_bans"] == 3
    # Toggle-backed fields (A-10) are untouched by A-18's connector wiring.
    assert body["status"] == "ok"
    assert body["enabled"] is True
    assert body["engine"] == ["os_firewall", "bitlocker_filevault", "crowdsec_bouncer"]
    assert "settings" in body


@pytest.mark.integration
async def test_perimeter_console_never_500s_when_all_three_sources_fail(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD failure scenario: unsupported platform/no privileges/unreachable
    CrowdSec — the endpoint must still answer 200 with honest per-source
    statuses, never a 500 and never a fabricated all-clear."""

    async def _fake_firewall():
        return {"connector": {"status": "permission_denied"}, "active": None}

    async def _fake_disk_encryption():
        return {"connector": {"status": "not_configured"}, "active": None}

    async def _fake_crowdsec(settings=None):
        return {
            "connector": {"status": "unreachable"},
            "metrics": {"active_bans": None, "banned_24h": None, "scenarios": None, "last_event_at": None},
            "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
            "recent_attempts": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"] == {
        "os_firewall": {"status": "permission_denied"},
        "disk_encryption": {"status": "not_configured"},
        "crowdsec_bouncer": {"status": "unreachable"},
    }
    assert body["metrics"]["firewall_active"] is None
    assert body["metrics"]["disk_encryption_active"] is None
    assert body["metrics"]["crowdsec_active_bans"] is None


@pytest.mark.integration
async def test_perimeter_console_reflects_a_real_unconfigured_crowdsec_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch: pytest.MonkeyPatch
):
    """No CrowdSec monkeypatching here: real `fetch_ids_console_data` runs
    against real (test-default) Settings, which have no
    CROWDSEC_LAPI_URL/CROWDSEC_API_KEY set — same honest not_configured this
    task's brief requires. os_firewall/os_disk_encryption ARE monkeypatched
    (their true value depends on the machine actually running this test
    suite, which must not leak into a deterministic assertion here — the
    live cross-check against this dev machine's real pf/FileVault state is
    done separately, by hand, not by this automated test)."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": False}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"]["crowdsec_bouncer"] == {"status": "not_configured"}
    assert body["metrics"]["crowdsec_active_bans"] is None


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
    headers = await _admin_headers(client, migrated_session_maker)

    ids_response = client.get("/security/consoles/ids", headers=headers)
    perimeter_response = client.get("/security/consoles/perimeter", headers=headers)

    assert ids_response.json()["connector"] == {"status": "ok"}
    assert ids_response.json()["metrics"]["active_bans"] == 3
    assert perimeter_response.json()["connectors"]["crowdsec_bouncer"] == {"status": "ok"}
    assert perimeter_response.json()["metrics"]["crowdsec_active_bans"] == 3
