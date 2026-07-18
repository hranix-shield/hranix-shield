"""A-14: /diagnostics/* against the real app wiring (client fixture — real
migrated tmp SQLite DB, real EventBus, real HealthRegistry, real HTTP layer
via TestClient), mirroring tests/integration/test_notifications_router.py.
"""

from __future__ import annotations

import json
import logging

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.diagnostics as diagnostics_router_module
import app.services.diagnostics as diagnostics_service_module
from app.config import Settings
from app.infra.logger_config import configure_logging
from tests.common.factories import create_user


async def _token(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str = "diag"
) -> str:
    await create_user(session_maker, username=username, password="pw", role="viewer")
    response = client.post("/auth/login", json={"username": username, "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
def test_bundle_without_token_is_401(client: TestClient):
    response = client.get("/diagnostics/bundle")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
def test_logs_without_token_is_401(client: TestClient):
    response = client.get("/diagnostics/logs")

    assert response.status_code == 401


@pytest.mark.integration
async def test_bundle_returns_all_four_sections_with_a_download_header(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _token(client, migrated_session_maker)

    response = client.get("/diagnostics/bundle", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("attachment;")
    assert ".json" in response.headers["content-disposition"]

    body = response.json()
    assert set(body.keys()) == {"generated_at", "environment", "health", "logs", "events"}
    assert body["health"]["status"] in {"ok", "degraded", "down"}
    assert body["environment"]["product"] == "Hranix Shield"
    assert isinstance(body["logs"], list)
    assert isinstance(body["events"], list)


@pytest.mark.integration
async def test_bundle_contains_no_plaintext_secrets_when_the_log_file_has_a_masked_entry(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Live scenario for the A-14 DoD: a real login attempt writes a masked
    line to a real log file (through the real `configure_logging()`
    pipeline, not a hand-built fixture), then the bundle is formed and
    inspected the same way A-5's own regression test does — grepping the
    raw bundle text for the exact secret values that went in.
    """
    log_file = tmp_path / "diagnostics-bundle.log"
    settings = Settings(_env_file=None, log_file=str(log_file))
    configure_logging(settings)
    try:
        logger = logging.getLogger("app.diagnostics_test")
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJib2IifQ.deadbeefsignature"
        logger.info(
            "login attempt",
            extra={
                "username": "bob",
                "password": "super-secret-password",
                "authorization": f"Bearer {fake_jwt}",
                "email": "bob@example.com",
            },
        )
    finally:
        configure_logging(Settings(_env_file=None))

    monkeypatch.setattr(diagnostics_service_module, "get_settings", lambda: settings)
    monkeypatch.setattr(diagnostics_router_module, "get_settings", lambda: settings)

    token = await _token(client, migrated_session_maker)
    response = client.get("/diagnostics/bundle", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    raw = response.text
    assert "super-secret-password" not in raw
    assert fake_jwt not in raw
    assert "bob@example.com" not in raw

    log_entries = response.json()["logs"]
    masked = next(e for e in log_entries if e.get("message") == "login attempt")
    assert masked["password"] == "***MASKED***"
    assert masked["authorization"] == "***MASKED***"
    assert masked["email"] == "***@example.com"
    assert masked["username"] == "bob"


@pytest.mark.integration
async def test_logs_endpoint_filters_by_level(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    log_file = tmp_path / "diagnostics-logs.log"
    log_file.write_text(
        "\n".join(
            [
                json.dumps({"level": "INFO", "logger": "a", "message": "info line"}),
                json.dumps({"level": "ERROR", "logger": "b", "message": "error line"}),
            ]
        )
        + "\n"
    )
    settings = Settings(_env_file=None, log_file=str(log_file))
    monkeypatch.setattr(diagnostics_router_module, "get_settings", lambda: settings)

    token = await _token(client, migrated_session_maker)
    response = client.get(
        "/diagnostics/logs", params={"level": "ERROR"}, headers={"Authorization": f"Bearer {token}"}
    )

    assert response.status_code == 200
    entries = response.json()["entries"]
    assert len(entries) == 1
    assert entries[0]["message"] == "error line"


@pytest.mark.integration
async def test_bundle_health_reflects_a_real_broken_database(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD live-failure scenario, same technique as A-6/A-12's own accepted
    verification method (see test_a6_health_regression.py): point the
    database health check at a real broken engine, then confirm the bundle
    (not just /health/detailed) reflects the degraded status — proving the
    bundle is built from a live registry run, not a stale/mocked snapshot.
    """
    import app.services.health.checks as health_checks_module
    from sqlalchemy.ext.asyncio import async_sessionmaker as _async_sessionmaker
    from sqlalchemy.ext.asyncio import create_async_engine

    token = await _token(client, migrated_session_maker)

    broken_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'missing-dir' / 'broken.db'}"
    )
    monkeypatch.setattr(
        health_checks_module,
        "async_session_maker",
        _async_sessionmaker(broken_engine, expire_on_commit=False),
    )

    response = client.get("/diagnostics/bundle", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    body = response.json()
    assert body["health"]["status"] == "degraded"
    assert body["health"]["components"]["database"]["status"] == "degraded"

    await broken_engine.dispose()
