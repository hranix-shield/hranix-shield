"""A-38 regression anchor.

Pins the core A-38 contract a later task must not break:
  - `GET /security/consoles/perimeter`'s response always carries a
    `network_profile` key with `connector`/`current`/`known` — regardless
    of what this specific machine's real current-network state happens to
    be (same "shape, not values" anchor philosophy
    test_a18_perimeter_regression.py's own anchors already use);
  - `POST /security/consoles/perimeter/network-profile/category` still
    requires a bearer token and never 500s, even on a genuinely-
    undetectable current network (409 `network_not_detected`, never a
    crash);
  - a category written through `set_network_category` is REAL, PERSISTENT
    storage: readable back through a COMPLETELY INDEPENDENT `AsyncSession`
    from the same session maker — the in-process proxy for "survives a
    server restart" (the real restart is exercised live, outside pytest,
    per this task's own DoD), same pattern
    test_a33_scan_history_regression.py's own persistence anchor uses for
    `scan_history`;
  - a scheduler tick (`touch_network_profile`) NEVER overwrites an
    operator's own already-persisted category — the load-bearing safety
    property behind this task's whole "переключение уровня защиты" design
    (see network_profile.py's own docstring).
"""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import NetworkProfile
from app.services.mcp.security_connectors.network_profile import (
    set_network_category,
    touch_network_profile,
)
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_a38_perimeter_get_always_carries_a_network_profile_key(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real detection, whatever this machine's
    actual current-network state is — the point of this anchor is the
    *shape* of the contract, not any one machine's specific values."""
    headers = await _admin_headers(client, migrated_session_maker, "a38_regress_shape")

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert "network_profile" in body
    assert "connector" in body["network_profile"]
    assert "status" in body["network_profile"]["connector"]
    current = body["network_profile"]["current"]
    assert set(current.keys()) == {"network_key", "display_name", "kind", "id_kind", "category"}
    assert isinstance(body["network_profile"]["known"], list)


@pytest.mark.integration
async def test_a38_set_category_endpoint_still_requires_a_token(client: TestClient):
    response = client.post(
        "/security/consoles/perimeter/network-profile/category", json={"category": "trusted"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a38_set_category_endpoint_never_500s_on_an_undetectable_network(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    import app.routers.security_console as security_console_module

    async def _no_network():
        return {
            "connector": {"status": "not_connected"},
            "kind": None,
            "network_key": None,
            "display_name": None,
            "id_kind": None,
            "default_category": None,
        }

    monkeypatch.setattr(security_console_module, "detect_current_network", _no_network)
    headers = await _admin_headers(client, migrated_session_maker, "a38_regress_undetectable")

    response = client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "trusted"},
        headers=headers,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "network_not_detected"}


@pytest.mark.integration
async def test_a38_category_is_real_persistence_not_process_memory(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """The DoD-defining regression anchor: a category written via
    `set_network_category` through one `AsyncSession` must be readable back
    through a COMPLETELY INDEPENDENT one from the same session maker."""
    async with migrated_session_maker() as write_session:
        await set_network_category(
            write_session,
            network_key="wifi:RegressionNet",
            display_name="RegressionNet",
            id_kind="ssid",
            category="trusted",
            now=datetime(2026, 7, 23, 9, 0, 0),
        )

    async with migrated_session_maker() as verify_session:
        rows = (await verify_session.scalars(select(NetworkProfile))).all()
    assert len(rows) == 1
    assert rows[0].network_key == "wifi:RegressionNet"
    assert rows[0].category == "trusted"


@pytest.mark.integration
async def test_a38_a_scheduler_touch_never_overwrites_an_operators_category(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """The load-bearing safety property behind this task's whole
    "переключение уровня защиты" design: `touch_network_profile` (the
    background scheduler's own write path) must NEVER silently revert an
    operator's own explicit category choice back to the connector's
    default — proven here across two completely independent sessions, the
    same "survives being written by different code paths at different
    times" shape as the persistence anchor above."""
    async with migrated_session_maker() as session:
        await set_network_category(
            session,
            network_key="wifi:OperatorChoice",
            display_name="OperatorChoice",
            id_kind="ssid",
            category="trusted",
            now=datetime(2026, 7, 23, 9, 0, 0),
        )

    async with migrated_session_maker() as session:
        await touch_network_profile(
            session,
            network_key="wifi:OperatorChoice",
            display_name="OperatorChoice",
            id_kind="ssid",
            default_category="public",  # what a FIRST sighting would default to
            now=datetime(2026, 7, 23, 9, 30, 0),
        )

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert len(rows) == 1
    assert rows[0].category == "trusted"  # the operator's choice, not the scheduler's default
