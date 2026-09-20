"""A-43: `GET/PUT /security/consoles/ids/crowdsec/scenario-thresholds[/...]`
against the real app wiring (client fixture — real HTTP layer via
TestClient) — same "monkeypatch crowdsec.read_scenario_thresholds/
write_scenario_threshold at their bare names imported into
app.routers.security_console" technique test_security_console_perimeter_ports.py
already uses for A-37, so none of this needs a real macOS host/real
`docker`/a real system password prompt (that live coverage is this task's
own report, done by hand).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecScenarioError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "scenario_thresholds_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /security/consoles/ids/crowdsec/scenario-thresholds
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_read_scenario_thresholds_endpoint_requires_a_token(client: TestClient):
    response = client.get("/security/consoles/ids/crowdsec/scenario-thresholds")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_read_scenario_thresholds_endpoint_returns_the_real_scenario_list(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_read():
        return {
            "status": "ok",
            "scenarios": [
                {
                    "name": "crowdsecurity/ssh-bf",
                    "type": "leaky",
                    "capacity": 5,
                    "leakspeed": "10s",
                    "file": "/etc/crowdsec/scenarios/ssh-bf.yaml",
                },
                {
                    "name": "crowdsecurity/ssh-generic-test",
                    "type": "trigger",
                    "capacity": None,
                    "leakspeed": None,
                    "file": "/etc/crowdsec/scenarios/ssh-generic-test.yaml",
                },
            ],
        }

    monkeypatch.setattr(security_console_module, "read_scenario_thresholds", _fake_read)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids/crowdsec/scenario-thresholds", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body["scenarios"]) == 2
    trigger_row = next(s for s in body["scenarios"] if s["type"] == "trigger")
    assert trigger_row["capacity"] is None
    assert trigger_row["leakspeed"] is None


@pytest.mark.integration
async def test_read_scenario_thresholds_endpoint_maps_elevation_cancelled_to_409(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_read():
        raise CrowdSecScenarioError("the user declined", reason="elevation_cancelled")

    monkeypatch.setattr(security_console_module, "read_scenario_thresholds", _raising_read)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids/crowdsec/scenario-thresholds", headers=headers)

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "elevation_cancelled"}


@pytest.mark.integration
async def test_read_scenario_thresholds_endpoint_maps_elevation_failed_to_502(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_read():
        raise CrowdSecScenarioError("docker exec failed", reason="elevation_failed")

    monkeypatch.setattr(security_console_module, "read_scenario_thresholds", _raising_read)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.get("/security/consoles/ids/crowdsec/scenario-thresholds", headers=headers)

    assert response.status_code == 502
    assert response.json()["detail"] == {"error": "elevation_failed"}


# ---------------------------------------------------------------------------
# PUT /security/consoles/ids/crowdsec/scenario-thresholds/{scenario_name}
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_write_scenario_threshold_endpoint_requires_a_token(client: TestClient):
    response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        json={"capacity": 7, "leakspeed": "15s"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_write_scenario_threshold_endpoint_accepts_a_slash_in_the_scenario_name(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Every real scenario name is `crowdsecurity/<name>` — the `:path`
    converter on this route must let that literal `/` through, not 404 on
    it (FastAPI's default `{param}` converter would)."""
    captured: dict = {}

    async def _fake_write(scenario_name, *, capacity, leakspeed):
        captured["scenario_name"] = scenario_name
        captured["capacity"] = capacity
        captured["leakspeed"] = leakspeed
        return {
            "status": "ok",
            "scenario": {
                "name": scenario_name,
                "type": "leaky",
                "capacity": capacity,
                "leakspeed": leakspeed,
                "file": "/etc/crowdsec/scenarios/ssh-bf.yaml",
            },
        }

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _fake_write)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        headers=headers,
        json={"capacity": 7, "leakspeed": "15s"},
    )

    assert response.status_code == 200
    assert captured["scenario_name"] == "crowdsecurity/ssh-bf"
    assert captured["capacity"] == 7
    assert captured["leakspeed"] == "15s"
    assert response.json()["scenario"]["capacity"] == 7


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("elevation_cancelled", 409),
        ("elevation_failed", 502),
        ("scenario_has_no_threshold", 422),
        ("scenario_not_found", 404),
        ("invalid_capacity", 422),
        ("invalid_leakspeed", 422),
        ("readback_mismatch", 502),
    ],
)
async def test_write_scenario_threshold_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_write(scenario_name, *, capacity, leakspeed):
        raise CrowdSecScenarioError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _raising_write)
    headers = await _admin_headers(client, migrated_session_maker, username=f"scenario_write_{reason}")

    response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        headers=headers,
        json={"capacity": 7, "leakspeed": "15s"},
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


@pytest.mark.integration
async def test_write_scenario_threshold_endpoint_never_500s_on_a_typed_error(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`elevation_cancelled`/`elevation_failed` must never collapse into
    the same status/code — the DoD's own "never conflate" requirement,
    same anchor style test_a18_perimeter_regression.py's A-36 section
    already established."""

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

    monkeypatch.setattr(security_console_module, "write_scenario_threshold", _failed)
    failed_response = client.put(
        "/security/consoles/ids/crowdsec/scenario-thresholds/crowdsecurity/ssh-bf",
        headers=headers,
        json={"capacity": 7, "leakspeed": "15s"},
    )

    assert cancelled_response.status_code != failed_response.status_code
    assert cancelled_response.status_code != 500
    assert failed_response.status_code != 500
