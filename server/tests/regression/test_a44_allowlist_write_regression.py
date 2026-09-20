"""A-44 regression anchor.

Per docs/методология-поэтапной-разработки.md, this task adds at least one
regression test that must stay green through the rest of Phase 0. Pins the
core A-44 contract later tasks must not break:

  - `POST/DELETE /security/consoles/ids/crowdsec/allowlist[/...]` both
    still require a bearer token;
  - `elevation_cancelled`/`elevation_failed` map to their own distinct,
    non-500 HTTP statuses (409/502) — never collapsed into one, same
    discipline test_a43_scenario_thresholds_regression.py's own anchor
    already pins for the sibling elevated endpoints;
  - `crowdsec.add_to_allowlist`'s own readback-over-exit-code discipline:
    a `cscli allowlists add` that reports failure (e.g. "already in
    allowlist") must still report SUCCESS if a fresh readback shows the
    value present — the operator's actual goal, never a spurious error
    just because a second attempt's own exit code says "no-op" (confirmed
    live against the real `hranix-crowdsec` container while building this
    task, see crowdsec.py's "A-44 addendum" docstring section);
  - conversely, a write that reports success but a fresh readback
    disagrees must NEVER be reported as success (`allowlist_readback_
    mismatch`) — the same "a clean exit is not proof it applied"
    discipline A-43's `write_scenario_threshold` already established for
    scenario thresholds, applied here to allowlist writes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecAllowlistError,
    add_to_allowlist,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "a44_regress"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_a44_allowlist_write_endpoints_require_a_token(client: TestClient):
    add_response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", json={"value": "203.0.113.5"}
    )
    remove_response = client.delete("/security/consoles/ids/crowdsec/allowlist/203.0.113.5")

    assert add_response.status_code == 401
    assert add_response.json()["detail"] == {"error": "not_authenticated"}
    assert remove_response.status_code == 401
    assert remove_response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a44_add_endpoint_never_collapses_cancelled_and_failed_into_one_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _cancelled(value, *, comment=None):
        raise CrowdSecAllowlistError("boom", reason="elevation_cancelled")

    async def _failed(value, *, comment=None):
        raise CrowdSecAllowlistError("boom", reason="elevation_failed")

    headers = await _admin_headers(client, migrated_session_maker)

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _cancelled)
    cancelled_response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )
    assert cancelled_response.status_code == 409
    assert cancelled_response.json()["detail"] == {"error": "elevation_cancelled"}

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _failed)
    failed_response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )
    assert failed_response.status_code == 502
    assert failed_response.json()["detail"] == {"error": "elevation_failed"}
    assert cancelled_response.status_code != failed_response.status_code


@pytest.mark.unit
async def test_a44_add_to_allowlist_reports_success_when_readback_confirms_presence_despite_a_failed_marker(
    monkeypatch: pytest.MonkeyPatch,
):
    """Pinned directly against `crowdsec.add_to_allowlist` (not just the
    router mock above): live-confirmed real `cscli` behaviour — re-adding a
    value already present answers a non-zero-flavoured "no new values"
    outcome, but the value genuinely IS in the allowlist, which is the
    operator's actual goal. Must never surface as an error."""

    async def _fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        return ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_ADD_FAILED\nvalue already in allowlist")

    async def _fake_fetch_allowlists(settings=None):
        return {
            "connector": {"status": "ok"},
            "allowlists": [
                {
                    "allowlist_name": "hranix_manual",
                    "value": "203.0.113.5",
                    "comment": "already there",
                    "expiration": None,
                    "created_at": "2026-07-25T08:00:00Z",
                }
            ],
        }

    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run)
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists)

    result = await add_to_allowlist("203.0.113.5")

    assert result["status"] == "ok"
    assert result["item"]["value"] == "203.0.113.5"


@pytest.mark.unit
async def test_a44_add_to_allowlist_readback_mismatch_never_reports_a_fake_success(
    monkeypatch: pytest.MonkeyPatch,
):
    """The mirror-image regression case: a write script reporting a clean
    `ADD_OK` marker is NOT proof the value is really there — a readback
    that disagrees must raise `allowlist_readback_mismatch`, never be
    silently reported as success."""

    async def _fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        return ElevatedRunResult(status="ok", stdout="HRANIX_ALLOWLIST_ADD_OK\nadded 1 values")

    async def _fake_fetch_allowlists(settings=None):
        return {"connector": {"status": "ok"}, "allowlists": []}  # value NOT actually present

    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run)
    monkeypatch.setattr(crowdsec_module, "fetch_allowlists", _fake_fetch_allowlists)

    with pytest.raises(CrowdSecAllowlistError) as exc_info:
        await add_to_allowlist("203.0.113.5")

    assert exc_info.value.reason == "allowlist_readback_mismatch"
