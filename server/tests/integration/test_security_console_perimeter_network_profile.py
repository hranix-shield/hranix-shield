"""A-38: `POST /security/consoles/perimeter/network-profile/category`
against the real app wiring (client fixture — real migrated tmp SQLite DB,
real HTTP layer via TestClient), exercising the router's real (non-stub)
persistence path.

`detect_current_network` is patched at TWO separate import sites, not one:
`app.routers.security_console`'s own bare-name import (used by the
endpoint's own direct call, same technique
test_security_console_perimeter_elevated.py already uses for A-36's
elevated actions) AND `network_profile.py`'s own module-global (used
INTERNALLY by `network_profile_payload()`, which the endpoint also calls to
build its response — a second, independent name binding to the same
original function, unaffected by patching the first one alone). Found live
while writing this test: patching only the router's own import left
`network_profile_payload`'s internal re-detection hitting the REAL host,
so the endpoint's response silently disagreed with what it had just
persisted — see `_patch_detection` below for the fix, kept as one shared
helper so this dual-patch requirement is not forgotten in a future test."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
import app.services.mcp.security_connectors.network_profile as network_profile_module
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "network_profile_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _patch_detection(
    monkeypatch: pytest.MonkeyPatch, *, network_key="wifi:CafeWifi", display_name="CafeWifi", id_kind="ssid"
):
    async def _detect():
        return {
            "connector": {"status": "ok"},
            "kind": "wifi",
            "network_key": network_key,
            "display_name": display_name,
            "id_kind": id_kind,
            "default_category": "public",
        }

    monkeypatch.setattr(security_console_module, "detect_current_network", _detect)
    monkeypatch.setattr(network_profile_module, "detect_current_network", _detect)


@pytest.mark.integration
async def test_set_category_endpoint_requires_a_token(client: TestClient):
    response = client.post(
        "/security/consoles/perimeter/network-profile/category", json={"category": "trusted"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_set_category_endpoint_persists_and_returns_the_updated_payload(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    _patch_detection(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "trusted"},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["current"]["network_key"] == "wifi:CafeWifi"
    assert body["current"]["category"] == "trusted"
    assert len(body["known"]) == 1
    assert body["known"][0]["network_key"] == "wifi:CafeWifi"
    assert body["known"][0]["category"] == "trusted"


@pytest.mark.integration
async def test_set_category_endpoint_rejects_an_invalid_category_with_422(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    _patch_detection(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "super-secure"},
        headers=headers,
    )

    assert response.status_code == 422  # FastAPI/pydantic's own Literal validation, never a 500


@pytest.mark.integration
async def test_set_category_endpoint_maps_no_current_network_to_409(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
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
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "trusted"},
        headers=headers,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "network_not_detected"}


@pytest.mark.integration
async def test_set_category_twice_upserts_instead_of_duplicating(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    _patch_detection(monkeypatch)
    headers = await _admin_headers(client, migrated_session_maker)

    client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "trusted"},
        headers=headers,
    )
    response = client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "public"},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert len(body["known"]) == 1  # upsert, not a second row
    assert body["known"][0]["category"] == "public"


@pytest.mark.integration
async def test_category_set_via_the_endpoint_is_reflected_by_the_perimeter_get(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """End-to-end within the router: a category set through the POST
    endpoint is visible on the NEXT `GET /consoles/perimeter` — proving the
    two endpoints share the same real DB row, not two disconnected
    in-memory states."""
    _patch_detection(monkeypatch)

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": False}

    async def _fake_crowdsec(settings=None):
        return {
            "connector": {"status": "not_configured"},
            "metrics": {
                "active_bans": None,
                "active_bans_local": None,
                "active_bans_community": None,
                "banned_24h": None,
                "scenarios": None,
                "last_event_at": None,
            },
            "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
            "recent_attempts": [],
        }

    async def _fake_ports():
        return {"connector": {"status": "ok"}, "open_ports": 0, "ports": []}

    async def _fake_rules():
        return {"connector": {"status": "ok"}, "count": 0}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _fake_crowdsec)
    monkeypatch.setattr(security_console_module, "fetch_listening_ports", _fake_ports)
    monkeypatch.setattr(security_console_module, "fetch_firewall_rules", _fake_rules)
    headers = await _admin_headers(client, migrated_session_maker)

    client.post(
        "/security/consoles/perimeter/network-profile/category",
        json={"category": "trusted"},
        headers=headers,
    )
    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    assert response.json()["network_profile"]["current"]["category"] == "trusted"
