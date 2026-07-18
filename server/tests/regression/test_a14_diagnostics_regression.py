"""A-14 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task adds at
least one regression test that must stay green for the rest of the phase
(and beyond, since A-14 closes Phase 0). Pins the core diagnostics contract:
the bundle endpoint stays behind auth, never leaks a plaintext secret from
an already-masked log line (reuses A-5's own masking, does not re-derive
it), and keeps reporting a real (not hardcoded) health/version snapshot.
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.diagnostics as diagnostics_router_module
import app.services.diagnostics as diagnostics_service_module
from app.config import Settings
from app.infra.logger_config import configure_logging
from tests.common.factories import create_user


@pytest.mark.integration
def test_diagnostics_bundle_still_requires_auth(client: TestClient):
    response = client.get("/diagnostics/bundle")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_diagnostics_bundle_still_never_leaks_a_plaintext_secret(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    log_file = tmp_path / "regression.log"
    settings = Settings(_env_file=None, log_file=str(log_file))
    configure_logging(settings)
    try:
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"
        logging.getLogger("app.regression.diagnostics").info(
            "login attempt",
            extra={
                "password": "correct horse battery staple",
                "authorization": f"Bearer {fake_jwt}",
                "email": "alice@example.com",
            },
        )
    finally:
        configure_logging(Settings(_env_file=None))

    monkeypatch.setattr(diagnostics_service_module, "get_settings", lambda: settings)
    monkeypatch.setattr(diagnostics_router_module, "get_settings", lambda: settings)

    await create_user(migrated_session_maker, username="diagregress", password="pw")
    token = client.post(
        "/auth/login", json={"username": "diagregress", "password": "pw"}
    ).json()["access_token"]

    response = client.get("/diagnostics/bundle", headers={"Authorization": f"Bearer {token}"})

    raw = response.text
    assert "correct horse battery staple" not in raw
    assert fake_jwt not in raw
    assert "alice@example.com" not in raw


@pytest.mark.integration
async def test_diagnostics_bundle_still_reports_a_real_health_snapshot_and_version(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="diagregress2", password="pw")
    token = client.post(
        "/auth/login", json={"username": "diagregress2", "password": "pw"}
    ).json()["access_token"]

    response = client.get("/diagnostics/bundle", headers={"Authorization": f"Bearer {token}"})

    body = response.json()
    assert body["health"]["components"]["database"]["status"] == "ok"
    assert body["environment"]["app_version"]
    assert body["environment"]["product"] == "Hranix Shield"
