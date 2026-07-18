"""A-10 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task from A-2 on
adds at least one regression test that must stay green through the rest of
Phase 0 (and beyond). This pins the core A-10 contract later tasks (A-11's
real CrowdSec/Osquery/Wazuh/ClamAV data, A-12's real backup engine) must not
break:
  - every /security/* endpoint still requires a bearer token (401 without one);
  - the console toggle still flips a console to "degraded" and the overview
    aggregate still reflects the worst of all 6 consoles;
  - the panel's static assets are still reachable at /panel (StaticFiles
    mount + the "/" -> "/panel/" redirect from app_factory.py), and "/"
    itself is left free for dynamically-registered routes (see
    app_factory.py's comment on why the mount is NOT at "/").
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.services.security_console import CONSOLE_IDS
from tests.common.factories import create_user

_DETAIL_ROUTES = [
    "/security/consoles/perimeter",
    "/security/consoles/ids",
    "/security/consoles/av",
    "/security/consoles/network",
    "/security/consoles/backup",
    "/security/consoles/logs",
]


@pytest.mark.integration
@pytest.mark.parametrize("route", ["/security/overview", *_DETAIL_ROUTES])
def test_every_security_console_endpoint_still_requires_a_token(client: TestClient, route: str):
    response = client.get(route)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
def test_toggle_endpoint_still_requires_a_token(client: TestClient):
    response = client.post("/security/consoles/ids/toggle", json={"enabled": False})

    assert response.status_code == 401


@pytest.mark.integration
async def test_worst_of_all_six_consoles_still_wins_the_overview_aggregate(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="regress_a10", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regress_a10", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    baseline = client.get("/security/overview", headers=headers).json()
    assert baseline["status"] == "ok"
    assert set(baseline["consoles"].keys()) == set(CONSOLE_IDS)

    toggle_response = client.post(
        "/security/consoles/backup/toggle", json={"enabled": False}, headers=headers
    )
    assert toggle_response.json() == {"id": "backup", "status": "degraded", "enabled": False}

    degraded_overview = client.get("/security/overview", headers=headers).json()
    assert degraded_overview["status"] == "degraded"
    assert degraded_overview["consoles"]["backup"] == {"status": "degraded", "enabled": False}


@pytest.mark.integration
def test_panel_static_assets_are_still_served_and_root_still_redirects_there(client: TestClient):
    root_response = client.get("/", follow_redirects=False)
    assert root_response.status_code in (302, 307)
    assert root_response.headers["location"] == "/panel/"

    panel_response = client.get("/panel/")
    assert panel_response.status_code == 200
    assert "Hranix Shield" in panel_response.text
