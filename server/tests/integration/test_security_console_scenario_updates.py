"""A-45: `POST /security/consoles/ids/crowdsec/scenario-updates/{check,apply}`
against the real app wiring (client fixture — real HTTP layer via
TestClient) — same "monkeypatch crowdsec.check_scenario_updates/
apply_scenario_updates at their bare names imported into
app.routers.security_console" technique
test_security_console_scenario_thresholds.py already uses for A-43, so none
of this needs a real macOS host/real `docker`/a real system password prompt
(that live coverage is this task's own report, done by hand).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecScenarioError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "scenario_updates_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/ids/crowdsec/scenario-updates/check
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_check_scenario_updates_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/check")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_check_scenario_updates_endpoint_returns_the_real_plan_and_flag(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_check():
        return {"status": "ok", "plan": "Action plan:\n📥 download\n scenarios: x (1 -> 2)\n", "has_upgrades": True}

    monkeypatch.setattr(security_console_module, "check_scenario_updates", _fake_check)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/check", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["has_upgrades"] is True
    assert "Action plan" in body["plan"]


@pytest.mark.integration
async def test_check_scenario_updates_endpoint_returns_honest_no_upgrades_flag(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_check():
        return {"status": "ok", "plan": "Action plan:\n🔄 check & update data files\n\nDry run, no action taken.\n", "has_upgrades": False}

    monkeypatch.setattr(security_console_module, "check_scenario_updates", _fake_check)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/check", headers=headers)

    assert response.status_code == 200
    assert response.json()["has_upgrades"] is False


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [("elevation_cancelled", 409), ("elevation_failed", 502)],
)
async def test_check_scenario_updates_endpoint_maps_elevated_errors(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_check():
        raise CrowdSecScenarioError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "check_scenario_updates", _raising_check)
    headers = await _admin_headers(client, migrated_session_maker, username=f"scenario_check_{reason}")

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/check", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


# ---------------------------------------------------------------------------
# POST /security/consoles/ids/crowdsec/scenario-updates/apply
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_apply_scenario_updates_endpoint_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_apply_scenario_updates_endpoint_returns_applied_true_on_a_real_write(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_apply():
        return {"status": "ok", "applied": True, "plan": "downloading scenarios:crowdsecurity/x\n"}

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _fake_apply)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)

    assert response.status_code == 200
    assert response.json()["applied"] is True


@pytest.mark.integration
async def test_apply_scenario_updates_endpoint_returns_applied_false_as_an_honest_noop(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`applied: false` is a legitimate 200, not an error — see
    crowdsec.apply_scenario_updates' own docstring for why (CrowdSec's own
    state can change between "check" and "apply")."""

    async def _fake_apply():
        return {"status": "ok", "applied": False, "plan": "Action plan:\n🔄 check & update data files\n"}

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _fake_apply)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)

    assert response.status_code == 200
    assert response.json()["applied"] is False


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("elevation_cancelled", 409),
        ("elevation_failed", 502),
        ("readback_mismatch", 502),
    ],
)
async def test_apply_scenario_updates_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_apply():
        raise CrowdSecScenarioError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _raising_apply)
    headers = await _admin_headers(client, migrated_session_maker, username=f"scenario_apply_{reason}")

    response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


@pytest.mark.integration
async def test_apply_scenario_updates_endpoint_never_500s_on_a_typed_error(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`elevation_cancelled`/`elevation_failed` must never collapse into the
    same status/code — the DoD's own "never conflate" requirement, same
    anchor style test_a43_scenario_thresholds_regression.py already
    established for the sibling scenario-write endpoint."""

    async def _cancelled():
        raise CrowdSecScenarioError("boom", reason="elevation_cancelled")

    async def _failed():
        raise CrowdSecScenarioError("boom", reason="elevation_failed")

    headers = await _admin_headers(client, migrated_session_maker)

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _cancelled)
    cancelled_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)

    monkeypatch.setattr(security_console_module, "apply_scenario_updates", _failed)
    failed_response = client.post("/security/consoles/ids/crowdsec/scenario-updates/apply", headers=headers)

    assert cancelled_response.status_code != failed_response.status_code
    assert cancelled_response.status_code != 500
    assert failed_response.status_code != 500
