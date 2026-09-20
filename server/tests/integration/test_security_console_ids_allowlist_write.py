"""A-44: `POST/DELETE /security/consoles/ids/crowdsec/allowlist[/...]`
against the real app wiring (client fixture — real HTTP layer via
TestClient) — same "monkeypatch crowdsec.add_to_allowlist/remove_from_
allowlist at their bare names imported into app.routers.security_console"
technique test_security_console_scenario_thresholds.py already uses for
A-43, so none of this needs a real macOS host/real `docker`/a real system
password prompt (that live coverage is this task's own report, done by
hand).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.crowdsec import CrowdSecAllowlistError
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "allowlist_write_admin"
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# POST /security/consoles/ids/crowdsec/allowlist
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_add_to_allowlist_endpoint_requires_a_token(client: TestClient):
    response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", json={"value": "203.0.113.5", "comment": "test"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_add_to_allowlist_endpoint_returns_the_added_item(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_add(value, *, comment=None):
        captured["value"] = value
        captured["comment"] = comment
        return {
            "status": "ok",
            "item": {
                "allowlist_name": "hranix_manual",
                "value": value,
                "comment": comment,
                "expiration": None,
                "created_at": "2026-07-25T08:00:00Z",
            },
        }

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _fake_add)
    headers = await _admin_headers(client, migrated_session_maker)

    response = client.post(
        "/security/consoles/ids/crowdsec/allowlist",
        headers=headers,
        json={"value": "203.0.113.5", "comment": "a real comment"},
    )

    assert response.status_code == 200
    assert captured["value"] == "203.0.113.5"
    assert captured["comment"] == "a real comment"
    assert response.json()["item"]["value"] == "203.0.113.5"


@pytest.mark.integration
async def test_add_to_allowlist_endpoint_accepts_an_omitted_comment(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    captured: dict = {}

    async def _fake_add(value, *, comment=None):
        captured["comment"] = comment
        return {"status": "ok", "item": {"value": value, "comment": comment}}

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _fake_add)
    headers = await _admin_headers(client, migrated_session_maker, username="allowlist_write_no_comment")

    response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )

    assert response.status_code == 200
    assert captured["comment"] is None


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("elevation_cancelled", 409),
        ("elevation_failed", 502),
        ("invalid_value", 422),
        ("allowlist_write_failed", 502),
        ("allowlist_readback_mismatch", 502),
        ("allowlist_readback_unavailable", 502),
    ],
)
async def test_add_to_allowlist_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_add(value, *, comment=None):
        raise CrowdSecAllowlistError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _raising_add)
    headers = await _admin_headers(client, migrated_session_maker, username=f"allowlist_add_{reason}")

    response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


# ---------------------------------------------------------------------------
# DELETE /security/consoles/ids/crowdsec/allowlist/{value}
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_remove_from_allowlist_endpoint_requires_a_token(client: TestClient):
    response = client.delete("/security/consoles/ids/crowdsec/allowlist/203.0.113.5")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_remove_from_allowlist_endpoint_accepts_a_slash_in_a_cidr_value(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A real CIDR value (`203.0.113.0/24`) contains a literal `/` — the
    `:path` converter must let it through (FastAPI's default `{param}`
    converter would 404 on it), same reasoning as A-43's own
    `{scenario_name:path}`."""
    captured: dict = {}

    async def _fake_remove(value):
        captured["value"] = value
        return {"status": "ok", "value": value}

    monkeypatch.setattr(security_console_module, "remove_from_allowlist", _fake_remove)
    headers = await _admin_headers(client, migrated_session_maker, username="allowlist_remove_cidr")

    response = client.delete(
        "/security/consoles/ids/crowdsec/allowlist/203.0.113.0/24", headers=headers
    )

    assert response.status_code == 200
    assert captured["value"] == "203.0.113.0/24"
    assert response.json() == {"status": "ok", "value": "203.0.113.0/24"}


@pytest.mark.integration
@pytest.mark.parametrize(
    "reason,expected_status",
    [
        ("elevation_cancelled", 409),
        ("elevation_failed", 502),
        ("invalid_value", 422),
        ("allowlist_write_failed", 502),
        ("allowlist_readback_mismatch", 502),
        ("allowlist_readback_unavailable", 502),
    ],
)
async def test_remove_from_allowlist_endpoint_maps_every_reason_to_its_own_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    reason: str,
    expected_status: int,
):
    async def _raising_remove(value):
        raise CrowdSecAllowlistError("boom", reason=reason)

    monkeypatch.setattr(security_console_module, "remove_from_allowlist", _raising_remove)
    headers = await _admin_headers(client, migrated_session_maker, username=f"allowlist_remove_{reason}")

    response = client.delete("/security/consoles/ids/crowdsec/allowlist/203.0.113.5", headers=headers)

    assert response.status_code == expected_status
    assert response.json()["detail"] == {"error": reason}


@pytest.mark.integration
async def test_add_and_remove_endpoints_never_collapse_cancelled_and_failed_into_one_status(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _cancelled(value, *, comment=None):
        raise CrowdSecAllowlistError("boom", reason="elevation_cancelled")

    async def _failed(value, *, comment=None):
        raise CrowdSecAllowlistError("boom", reason="elevation_failed")

    headers = await _admin_headers(client, migrated_session_maker)

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _cancelled)
    cancelled_response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )

    monkeypatch.setattr(security_console_module, "add_to_allowlist", _failed)
    failed_response = client.post(
        "/security/consoles/ids/crowdsec/allowlist", headers=headers, json={"value": "203.0.113.5"}
    )

    assert cancelled_response.status_code == 409
    assert failed_response.status_code == 502
    assert cancelled_response.status_code != failed_response.status_code
