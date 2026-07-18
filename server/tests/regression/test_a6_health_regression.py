"""A-6 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task from A-2 on
adds at least one regression test that must stay green through the rest of
Phase 0 (and beyond). This pins the core health-check contract other tasks
(A-11's CrowdSec/Osquery/Wazuh/ClamAV connectors, A-14's diagnostics panel)
must not break: `/health/detailed` aggregates to the worst subsystem status,
a broken DB never turns the endpoint into a 500, and a genuine status
transition — and only a transition, not a repeat poll — publishes
`health.changed` to the `events` table.
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.health.checks as health_checks_module
from app.db.models import Event
from app.services.event_bus import EventBus, Topic
from app.services.health.registry import CheckResult, HealthRegistry, Status


@pytest.mark.integration
def test_health_detailed_still_returns_200_ok_when_the_db_is_healthy(client: TestClient):
    response = client.get("/health/detailed")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


@pytest.mark.integration
def test_health_detailed_still_degrades_gracefully_never_500_when_db_is_broken(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    broken_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'missing-dir' / 'broken.db'}"
    )
    monkeypatch.setattr(
        health_checks_module,
        "async_session_maker",
        async_sessionmaker(broken_engine, expire_on_commit=False),
    )

    response = client.get("/health/detailed")

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"


@pytest.mark.integration
async def test_health_changed_still_logs_exactly_once_per_real_transition(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    client.get("/health/detailed")  # baseline: ok

    broken_engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'missing-dir' / 'broken.db'}"
    )
    monkeypatch.setattr(
        health_checks_module,
        "async_session_maker",
        async_sessionmaker(broken_engine, expire_on_commit=False),
    )

    client.get("/health/detailed")  # ok -> degraded: publishes once
    client.get("/health/detailed")  # still degraded: must not publish again

    async with migrated_session_maker() as session:
        events = (
            await session.scalars(
                select(Event).where(Event.topic == Topic.HEALTH_CHANGED.value)
            )
        ).all()

    assert len(events) == 1
    await broken_engine.dispose()


@pytest.mark.unit
async def test_worst_of_all_registered_checks_still_wins_the_aggregate():
    registry = HealthRegistry()
    bus = EventBus()

    async def ok_check() -> CheckResult:
        return CheckResult(status=Status.OK)

    async def down_check() -> CheckResult:
        return CheckResult(status=Status.DOWN)

    registry.register("a", ok_check)
    registry.register("b", down_check)

    result = await registry.run_all(event_bus=bus)

    assert result["status"] == "down"
