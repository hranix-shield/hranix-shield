"""A-45 regression anchor.

Per docs/методология-поэтапной-разработки.md, this task adds at least one
regression test that must stay green through the rest of Phase 0. Pins the
core A-45 contract later tasks must not break:

  - `POST /security/consoles/ids/crowdsec/scenario-updates/{check,apply}`
    both still require a bearer token;
  - `elevation_cancelled`/`elevation_failed` map to their own distinct,
    non-500 HTTP statuses (409/502) — never collapsed into one, same
    discipline test_a43_scenario_thresholds_regression.py's anchor already
    pins for the sibling scenario-threshold endpoints;
  - an empty/"already current" `cscli hub upgrade --dry-run` plan is
    honestly reported as `has_upgrades: false` — pinned directly against
    `crowdsec._scenario_update_plan_has_upgrades` using the REAL live output
    shape (the `🔄 check & update data files` line alone must never be
    mistaken for "nothing to apply", see crowdsec.py's "A-45 addendum"
    docstring section) — the frontend's own "no Применить button" honest
    degradation (app.js's renderScenarioUpdatesSection) depends entirely on
    this flag being correct;
  - `apply_scenario_updates`'s mandatory readback never reports a fake
    success — a restart that exits zero with a fresh `cscli hub list -o
    json` still showing an outdated item must raise `readback_mismatch`,
    never be silently treated as `applied: true`.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecScenarioError, apply_scenario_updates
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from tests.common.factories import create_user

# The same real live-container excerpts test_crowdsec_scenario_updates.py
# uses — kept here too (not imported from that file) so this anchor stays
# self-contained, same convention test_a43_scenario_thresholds_regression.py
# already follows for its own fixture.
_REAL_PLAN_ALREADY_CURRENT = """\
Action plan:
🔄 check & update data files

Dry run, no action taken.
"""

_REAL_HUB_LIST_STILL_OUTDATED = json.dumps(
    {
        "scenarios": [
            {
                "name": "crowdsecurity/ssh-time-based-bf",
                "local_version": "0.2",
                "status": "enabled,update-available",
            },
        ],
    }
)


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "a45_regress"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_a45_scenario_update_endpoints_require_a_token(client: TestClient):
    check_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/check")
    apply_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply")

    assert check_response.status_code == 401
    assert check_response.json()["detail"] == {"error": "not_authenticated"}
    assert apply_response.status_code == 401
    assert apply_response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a45_apply_endpoint_never_collapses_cancelled_and_failed_into_one_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _cancelled():
        raise CrowdSecScenarioError("boom", reason="elevation_cancelled")

    async def _failed():
        raise CrowdSecScenarioError("boom", reason="elevation_failed")

    headers = await _admin_headers(client, migrated_session_maker)

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _cancelled)
    cancelled_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)
    assert cancelled_response.status_code == 409
    assert cancelled_response.json()["detail"] == {"error": "elevation_cancelled"}

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _failed)
    failed_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)
    assert failed_response.status_code == 502
    assert failed_response.json()["detail"] == {"error": "elevation_failed"}
    assert cancelled_response.status_code != failed_response.status_code


@pytest.mark.unit
def test_a45_plan_with_only_data_files_line_never_reads_as_has_upgrades():
    """The exact confusion this task's own DoD warned against: `🔄 check &
    update data files` is present in the "nothing to apply" fixture too —
    must never flip `has_upgrades` to `True` on its own."""
    assert crowdsec_module._scenario_update_plan_has_upgrades(_REAL_PLAN_ALREADY_CURRENT) is False


@pytest.mark.unit
async def test_a45_apply_readback_mismatch_never_reports_a_fake_success(monkeypatch: pytest.MonkeyPatch):
    calls: list[dict] = []

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        calls.append({"command": command})
        if len(calls) == 1:
            return ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_UPDATES_APPLIED\n")
        return ElevatedRunResult(status="ok", stdout=_REAL_HUB_LIST_STILL_OUTDATED)

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)
    monkeypatch.setattr(crowdsec_module, "_resolve_docker_binary", lambda: "/usr/local/bin/docker")

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await apply_scenario_updates()

    assert exc_info.value.reason == "readback_mismatch"
    assert len(calls) == 2  # the readback WAS attempted, it just did not confirm the change
