"""A-43 regression anchor.

Per docs/методология-поэтапной-разработки.md, this task adds at least one
regression test that must stay green through the rest of Phase 0. Pins the
core A-43 contract later tasks must not break:

  - `GET/PUT /security/consoles/ids/crowdsec/scenario-thresholds[/...]`
    both still require a bearer token;
  - `elevation_cancelled`/`elevation_failed` map to their own distinct,
    non-500 HTTP statuses (409/502) — never collapsed into one, same
    discipline test_a18_perimeter_regression.py's A-36/A-37 anchors already
    pin for the sibling elevated endpoints;
  - a `type: trigger` scenario is honestly rejected (`scenario_has_no_
    threshold`, 422) — never silently accepted just because a client sent
    a request, even though the real UI never offers input fields for one
    (defense in depth, server-side, matching this project's other write
    endpoints);
  - `crowdsec.read_scenario_thresholds`'s own parsing NEVER turns a
    trigger scenario's missing `capacity`/`leakspeed` into a fabricated
    `0` — pinned here against the REAL live output shape (multi-document
    files included, see crowdsec.py's "A-43 addendum" docstring section),
    not just a synthetic single-scenario fixture.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecScenarioError, read_scenario_thresholds
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from tests.common.factories import create_user

# The same real live-container excerpt test_crowdsec_scenario_thresholds.py
# uses — kept here too (not imported from that file) so this anchor stays
# self-contained and does not silently start passing/failing because of an
# edit to a shared fixture living in a non-regression test file.
_REAL_READ_OUTPUT = """\
===HRANIX-SCENARIO-FILE:/etc/crowdsec/scenarios/ssh-bf.yaml===
type: leaky
name: crowdsecurity/ssh-bf
leakspeed: "10s"
capacity: 5
---
type: leaky
name: crowdsecurity/ssh-bf_user-enum
leakspeed: 10s
capacity: 5
===HRANIX-SCENARIO-FILE:/etc/crowdsec/scenarios/ssh-generic-test.yaml===
type: trigger
name: crowdsecurity/ssh-generic-test
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
"""


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "a43_regress"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_a43_scenario_threshold_endpoints_require_a_token(client: TestClient):
    read_response = client.get("/security/consoles/ids/crowdsec/scenario-thresholds")
    write_response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        json={"capacity": 7, "leakspeed": "15s"},
    )

    assert read_response.status_code == 401
    assert read_response.json()["detail"] == {"error": "not_authenticated"}
    assert write_response.status_code == 401
    assert write_response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a43_write_endpoint_never_collapses_cancelled_and_failed_into_one_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _cancelled(scenario_name, *, capacity, leakspeed):
        raise CrowdSecScenarioError("boom", reason="elevation_cancelled")

    async def _failed(scenario_name, *, capacity, leakspeed):
        raise CrowdSecScenarioError("boom", reason="elevation_failed")

    headers = await _admin_headers(client, migrated_session_maker)

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _cancelled)
    cancelled_response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        headers=headers,
        json={"capacity": 7, "leakspeed": "15s"},
    )
    assert cancelled_response.status_code == 409
    assert cancelled_response.json()["detail"] == {"error": "elevation_cancelled"}

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _failed)
    failed_response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        headers=headers,
        json={"capacity": 7, "leakspeed": "15s"},
    )
    assert failed_response.status_code == 502
    assert failed_response.json()["detail"] == {"error": "elevation_failed"}
    assert cancelled_response.status_code != failed_response.status_code


@pytest.mark.integration
async def test_a43_write_endpoint_honestly_rejects_a_trigger_scenario_server_side(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Defense in depth: even though the real UI never renders input
    fields for a `trigger` scenario (app.js's renderScenarioThresholdsModal),
    the SERVER must independently refuse a write attempt for one — never
    trust the client alone, same discipline every other write endpoint in
    this panel already follows."""

    async def _raising_write(scenario_name, *, capacity, leakspeed):
        raise CrowdSecScenarioError(f"'{scenario_name}' is a trigger scenario", reason="scenario_has_no_threshold")

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _raising_write)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-generic-test",
        headers=headers,
        json={"capacity": 5, "leakspeed": "10s"},
    )

    assert response.status_code == 422
    assert response.json()["detail"] == {"error": "scenario_has_no_threshold"}


@pytest.mark.unit
async def test_a43_read_scenario_thresholds_never_fabricates_a_trigger_capacity(
    monkeypatch: pytest.MonkeyPatch,
):
    """Pinned directly against `crowdsec.read_scenario_thresholds` (not
    just the router mock above) using the REAL multi-document live output
    shape — a `type: trigger` scenario's `capacity`/`leakspeed` must stay
    `None`, never round to a fabricated `0`, and a two-scenario file
    (`ssh-bf.yaml`, confirmed live) must yield BOTH scenarios, not just
    the first one a naive one-document-per-file parser would find."""

    async def _fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        return ElevatedRunResult(status="ok", stdout=_REAL_READ_OUTPUT)

    monkeypatch.setattr(crowdsec_module, "elevated_run", _fake_elevated_run)

    result = await read_scenario_thresholds()

    by_name = {s["name"]: s for s in result["scenarios"]}
    assert by_name["crowdsecurity/ssh-generic-test"]["capacity"] is None
    assert by_name["crowdsecurity/ssh-generic-test"]["leakspeed"] is None
    assert by_name["crowdsecurity/ssh-generic-test"]["type"] == "trigger"
    assert "crowdsecurity/ssh-bf" in by_name
    assert "crowdsecurity/ssh-bf_user-enum" in by_name
    assert by_name["crowdsecurity/ssh-bf"]["capacity"] == 5
