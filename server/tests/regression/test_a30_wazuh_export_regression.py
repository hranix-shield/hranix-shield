"""A-30 regression anchor.

Per docs/методология-поэтапной-разработки.md, every task adds at least one
regression test that must stay green through the rest of Phase 0. Pins the
core A-30 contract later tasks must not break:
  - `POST /security/consoles/logs/wazuh/syscheck` never 500s regardless of
    whether Wazuh is configured/reachable — an honest `wazuh_*` error code,
    never a crash (mirrors A-16's own "never 500" anchor for the read path);
  - `POST /security/consoles/export` is genuinely console-agnostic: it
    round-trips arbitrary rows to CSV without knowing/caring which console
    they came from — the "universal, not duplicated per console" mechanism
    the A-30 task brief required;
  - both endpoints require authentication, same as every other
    `/security/consoles/*` action endpoint.
"""

import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user

_KNOWN_ERROR_CODES = {"wazuh_not_configured", "wazuh_unreachable", "wazuh_unauthorized"}


@pytest.mark.integration
async def test_trigger_syscheck_never_500s_with_wazuh_unconfigured(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: the real `trigger_syscheck_scan` genuinely runs
    against real (test-default) Settings, which have no
    WAZUH_API_URL/WAZUH_API_USERNAME/WAZUH_API_PASSWORD set."""
    await create_user(migrated_session_maker, username="regress_a30", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a30", "password": "pw"}
    ).json()["access_token"]

    response = client.post(
        "/security/consoles/logs/wazuh/syscheck",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 503
    assert response.json()["detail"]["error"] in _KNOWN_ERROR_CODES


@pytest.mark.integration
async def test_export_endpoint_is_console_agnostic_for_arbitrary_row_shapes(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(
        migrated_session_maker, username="regress_a30_export", password="pw", role="admin"
    )
    token = client.post(
        "/auth/login", json={"username": "regress_a30_export", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for console_id, rows in (
        ("logs", [{"file": "/a", "description": "x"}]),
        ("network", [{"process": "curl", "pid": 1}]),
        ("some_future_console", [{"anything": "goes", "here": 1}]),
    ):
        response = client.post(
            "/security/consoles/export",
            headers=headers,
            json={"console_id": console_id, "format": "csv", "rows": rows},
        )
        assert response.status_code == 200, console_id
        parsed = list(csv.DictReader(io.StringIO(response.text)))
        assert len(parsed) == len(rows), console_id


@pytest.mark.integration
async def test_both_a30_action_endpoints_require_authentication(client: TestClient):
    assert client.post("/security/consoles/logs/wazuh/syscheck").status_code == 401
    assert (
        client.post(
            "/security/consoles/export", json={"console_id": "logs", "rows": []}
        ).status_code
        == 401
    )
