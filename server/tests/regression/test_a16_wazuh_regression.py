"""A-16 regression anchor.

Per docs/методология-поэтапной-разработки.md, every task adds at least one
regression test that must stay green through the rest of Phase 0 (and
beyond, alongside the A-10/A-11/A-15/A-17/A-18 anchors). Pins the core A-16
contract later tasks must not break:
  - GET /security/consoles/logs never 500s regardless of whether Wazuh is
    configured/reachable — an honest `connector.status`, not a crash and not
    a fabricated all-clear (fixing this console's own former placeholder
    bug that used to hardcode zeros);
  - the Wazuh connector is registered in `app.state.mcp_registry` at startup
    (same "wire the connector into MCPRegistry" requirement A-11/A-17
    established);
  - A-10's pre-existing "logs" console contract (toggle-backed
    `status`/`enabled`, `engine`, `settings`) is untouched by A-16's real
    data wiring;
  - all 6 consoles are real now — no console left on the `_base`-only stub
    shape (the milestone this task closes out).
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.app_factory import create_app
from tests.common.factories import create_user

_KNOWN_CONNECTOR_STATUSES = {"ok", "not_configured", "unreachable", "unauthorized"}


@pytest.mark.integration
async def test_logs_console_still_never_500s_with_wazuh_unconfigured(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="regress_a16", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a16", "password": "pw"}
    ).json()["access_token"]

    response = client.get(
        "/security/consoles/logs", headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    body = response.json()
    assert body["connector"]["status"] in _KNOWN_CONNECTOR_STATUSES
    assert body["status"] == "ok"  # toggle-backed status: untouched by A-16
    assert body["enabled"] is True
    assert body["engine"] == ["wazuh_agent", "windows_event_log", "macos_unified_log"]


@pytest.mark.unit
def test_wazuh_connector_is_registered_in_the_apps_mcp_registry():
    app = create_app()

    connector = app.state.mcp_registry.get("wazuh")

    assert connector.name == "wazuh"
    assert connector.transport == "http"


@pytest.mark.integration
async def test_all_six_consoles_answer_200_and_none_are_left_on_the_bare_base_stub(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A-16 closes out the "5 of 6 consoles are real" milestone (see
    README.md) — this anchor pins that all 6 consoles respond with more
    than just the toggle-backed `_base` fields (id/status/enabled), i.e.
    every console has SOME real-or-honestly-placeholder metrics shape
    behind it, never a completely missing response."""
    await create_user(migrated_session_maker, username="regress_a16_all", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a16_all", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    for console_id in ("perimeter", "ids", "av", "network", "backup", "logs"):
        response = client.get(f"/security/consoles/{console_id}", headers=headers)
        assert response.status_code == 200, console_id
        body = response.json()
        assert body["id"] == console_id
        assert "metrics" in body
