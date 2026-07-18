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


@pytest.mark.unit
def test_crowdsec_connector_is_registered_in_the_apps_mcp_registry():
    app = create_app()

    connector = app.state.mcp_registry.get("crowdsec")

    assert connector.name == "crowdsec"
    assert connector.transport == "http"
