"""A-11 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task adds at
least one regression test that must stay green through the rest of Phase 0
(and beyond). This pins the core A-11 contract later tasks (a future
Osquery/Wazuh/ClamAV connector, A-14's diagnostics panel) must not break:
  - GET /security/consoles/ids never 500s regardless of whether CrowdSec is
    configured/reachable — an honest `connector.status`, not a crash and not
    a fabricated all-clear;
  - the CrowdSec connector is registered in `app.state.mcp_registry` at
    startup (A-11's "wire the connector into MCPRegistry" requirement);
  - A-10's pre-existing "ids" console contract (toggle-backed
    `status`/`enabled`, `engine`, `settings`) is untouched by A-11's real
    data wiring.

A-23 adds one more anchor below (`test_ids_console_metrics_stay_split_into_
local_and_community_bans`): `metrics` must keep exposing
`active_bans_local`/`active_bans_community` as distinct keys (not collapsed
back into a single unexplained `active_bans`) — that split is the actual
fix for the "16673 active bans with no explanation" complaint the A-23 task
brief documents, so a future change silently re-merging them would
reintroduce the exact bug this task fixed.

A-29 adds two more anchors below: the write-side endpoints
(`POST /security/consoles/ids/crowdsec/ban` /
`DELETE .../decisions/{id}`) must both keep answering an honest
`crowdsec_write_not_configured` (never a 500, never a silent no-op) when the
machine credential isn't set — the write-side analogue of the read-side
"never 500, never a fabricated all-clear" contract this file already pins —
AND that must stay true even when the READ-side bouncer key IS configured
(the two credentials are genuinely independent, see crowdsec.py's
`is_crowdsec_write_configured` docstring).

A-42 adds two more anchors below: `GET /security/consoles/ids`'s `settings`
must never again carry the old A-11 placeholders (`ban_threshold`,
`ban_duration_hours`, `whitelist_count`) — CrowdSec has no LAPI endpoint for
a single global ban threshold at all (confirmed live, see crowdsec.py's
"A-42 addendum" docstring section), so a future change resurrecting a
hardcoded number here would reintroduce exactly the fabricated-setting bug
this task fixes — and the new `allowlist` key must keep reporting an honest
`connector.status` (never a 500, never a silently-empty list standing in for
"could not check") independently of `ids`'s own read-side `connector`.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.app_factory import create_app
from tests.common.factories import create_user


@pytest.mark.integration
async def test_ids_console_still_never_500s_with_crowdsec_unconfigured(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="regress_a11", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a11", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/ids", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connector"]["status"] == "not_configured"
    assert body["status"] == "ok"  # toggle-backed status: untouched by A-11
    assert body["enabled"] is True
    assert body["engine"] == ["crowdsec"]


@pytest.mark.integration
async def test_ids_console_metrics_stay_split_into_local_and_community_bans(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A-23 regression anchor: `metrics` must always expose both
    `active_bans_local` and `active_bans_community` as distinct keys (here,
    both honestly `None` — CrowdSec is unconfigured in the test default
    Settings — but the *keys* must be present regardless of connector
    status) alongside the backward-compatible summed `active_bans`."""
    await create_user(migrated_session_maker, username="regress_a23", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a23", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/ids", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    metrics = response.json()["metrics"]
    assert "active_bans_local" in metrics
    assert "active_bans_community" in metrics
    assert "active_bans" in metrics  # backward-compat sum, kept on purpose


@pytest.mark.unit
def test_crowdsec_connector_is_registered_in_the_apps_mcp_registry():
    app = create_app()

    connector = app.state.mcp_registry.get("crowdsec")

    assert connector.name == "crowdsec"
    assert connector.transport == "http"


@pytest.mark.integration
async def test_crowdsec_ban_still_never_500s_with_the_write_credential_unconfigured(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A-29 regression anchor: the real (non-monkeypatched) `ban_ip` against
    real test-default Settings (no CROWDSEC_MACHINE_ID/
    CROWDSEC_MACHINE_PASSWORD) must answer an honest 503
    `crowdsec_write_not_configured` — never a 500 and never a silent
    `{"banned": true}` for an action nothing actually performed."""
    await create_user(migrated_session_maker, username="regress_a29", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a29", "password": "pw"}
    ).json()["access_token"]

    response = client.post(
        "/security/consoles/ids/crowdsec/ban",
        json={"ip": "192.0.2.1"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "crowdsec_write_not_configured"}


@pytest.mark.integration
async def test_ids_console_settings_never_carry_the_old_a11_placeholders_again(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A-42 regression anchor: `ban_threshold`/`ban_duration_hours`/
    `whitelist_count` were hardcoded A-11 numbers, never read from real
    CrowdSec and never editable — a real user asked how to change them,
    which is what prompted this fix. Pinning their absence (not just the
    presence of the new honest keys) so a future change cannot silently
    reintroduce a fabricated setting."""
    await create_user(migrated_session_maker, username="regress_a42", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a42", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/ids", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    settings = body["settings"]
    assert "ban_threshold" not in settings
    assert "ban_duration_hours" not in settings
    assert "whitelist_count" not in settings
    assert settings["ban_policy"] == "per_scenario"  # machine-readable, never a fabricated number
    assert "allowlist" in body
    assert "connector" in body["allowlist"]
    assert "items" in body["allowlist"]


@pytest.mark.unit
def test_crowdsec_write_configured_stays_independent_of_the_read_side_bouncer_key():
    """A-29 regression anchor: a deployment with a working read-only
    bouncer key (`ids`'s GET keeps working) but no machine credential must
    still report writes as unconfigured — the two credential classes must
    never be conflated, see crowdsec.py's "A-29 addendum" docstring section
    for exactly why a bouncer key cannot substitute for a machine login."""
    from app.config import Settings
    from app.services.mcp.security_connectors.crowdsec import (
        is_crowdsec_configured,
        is_crowdsec_write_configured,
    )

    settings = Settings(
        crowdsec_lapi_url="http://crowdsec.test",
        crowdsec_api_key="a-real-bouncer-key",
        crowdsec_machine_id=None,
        crowdsec_machine_password=None,
    )

    assert is_crowdsec_configured(settings) is True
    assert is_crowdsec_write_configured(settings) is False
