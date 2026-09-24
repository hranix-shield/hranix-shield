"""A-6: /health/detailed against the real app wiring (client fixture — real
migrated tmp SQLite DB, real EventBus, real HTTP layer via TestClient), not
a unit-level HealthRegistry in isolation (see test_health_registry.py /
test_health_checks.py for that).
"""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

import app.services.health.checks as health_checks_module
import app.services.health.system as health_system_module
from app.db.models import Event
from app.services.event_bus import Topic


@pytest.mark.integration
def test_health_detailed_returns_ok_for_all_subsystems_on_a_healthy_db(client: TestClient):
    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["components"]["database"] == {"status": "ok"}
    assert body["components"]["event_bus"] == {"status": "ok"}


@pytest.mark.integration
def test_health_detailed_shows_degraded_when_the_db_dependency_is_broken(
    client: TestClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """DoD scenario: break the DB dependency for real (engine pointed at a
    nonexistent directory, not a mock) — the endpoint must still answer 200
    with a `degraded` database component and `degraded` aggregate status,
    never a 500."""
    broken_db_path = tmp_path / "no-such-directory" / "broken.db"
    broken_engine = create_async_engine(f"sqlite+aiosqlite:///{broken_db_path}")
    broken_maker = async_sessionmaker(broken_engine, expire_on_commit=False)
    monkeypatch.setattr(health_checks_module, "async_session_maker", broken_maker)

    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "degraded"
    assert body["components"]["database"]["status"] == "degraded"
    assert "error" in body["components"]["database"]


@pytest.mark.integration
async def test_health_changed_is_logged_to_events_table_on_transition_and_not_on_repeat(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    # Baseline call: DB healthy -> "ok", first observation, no event yet.
    first = client.get("/health/detailed")
    assert first.json()["status"] == "ok"

    # Break the DB dependency for real, then poll again: ok -> degraded.
    broken_db_path = tmp_path / "no-such-directory" / "broken.db"
    broken_engine = create_async_engine(f"sqlite+aiosqlite:///{broken_db_path}")
    broken_maker = async_sessionmaker(broken_engine, expire_on_commit=False)
    monkeypatch.setattr(health_checks_module, "async_session_maker", broken_maker)

    second = client.get("/health/detailed")
    assert second.json()["components"]["database"]["status"] == "degraded"

    # Repeat poll, still broken: same status, must NOT publish again.
    third = client.get("/health/detailed")
    assert third.json()["components"]["database"]["status"] == "degraded"

    async with migrated_session_maker() as session:
        events = (
            await session.scalars(
                select(Event).where(Event.topic == Topic.HEALTH_CHANGED.value)
            )
        ).all()

    assert len(events) == 1
    assert events[0].payload["component"] == "database"
    assert events[0].payload["previous_status"] == "ok"
    assert events[0].payload["status"] == "degraded"

    await broken_engine.dispose()


@pytest.mark.integration
def test_health_detailed_aggregate_is_down_when_docker_stack_is_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """A-65-2, суть инцидента 2026-09-23: пилюля/агрегат обязаны упасть в
    down, когда лежит Docker-стек, даже если внутренние подсистемы процесса
    (database/event_bus) здоровы."""
    import urllib.error

    async def engine_down(*args: str, timeout: float = 5.0):
        if "info" in " ".join(args):
            return (1, "", "Cannot connect to the Docker daemon")
        return (0, "", "")

    async def refused(url: str, *, timeout: float = 3.0):
        raise urllib.error.URLError(ConnectionRefusedError(111))

    async def clamd_down(host: str, port: int):
        raise RuntimeError("clamd unreachable")

    monkeypatch.setattr(health_system_module, "run_local_command", engine_down)
    monkeypatch.setattr(health_system_module, "_probe_http", refused)
    monkeypatch.setattr(health_system_module, "_probe_clamd", clamd_down)

    response = client.get("/health/detailed")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "down"
    system_stack = body["components"]["system_stack"]
    assert system_stack["status"] == "down"
    matrix_ids = [component["id"] for component in system_stack["components"]]
    assert "docker_engine" in matrix_ids
    # Внутренние подсистемы по-прежнему честно ok — падает агрегат.
    assert body["components"]["database"]["status"] == "ok"
    assert body["components"]["event_bus"]["status"] == "ok"
