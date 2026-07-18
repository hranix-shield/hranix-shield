from pathlib import Path

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.services.health.checks as health_checks_module
from app.services.event_bus import EventBus
from app.services.health.checks import check_database, register_default_checks
from app.services.health.registry import HealthRegistry, Status


@pytest.mark.unit
async def test_check_database_reports_ok_against_a_working_db(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(health_checks_module, "async_session_maker", migrated_session_maker)

    result = await check_database()

    assert result.status == Status.OK
    assert result.details == {}


@pytest.mark.unit
async def test_check_database_reports_degraded_when_the_engine_cannot_connect(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Per A-6's DoD: point the engine at a nonexistent directory — a real
    (not mocked) connection failure — and confirm the check reports
    DEGRADED, never raises."""
    broken_db_path = tmp_path / "no-such-directory" / "broken.db"
    broken_engine = create_async_engine(f"sqlite+aiosqlite:///{broken_db_path}")
    broken_maker = async_sessionmaker(broken_engine, expire_on_commit=False)
    monkeypatch.setattr(health_checks_module, "async_session_maker", broken_maker)

    result = await check_database()

    assert result.status == Status.DEGRADED
    assert "error" in result.details

    await broken_engine.dispose()


@pytest.mark.unit
async def test_register_default_checks_wires_database_and_event_bus():
    registry = HealthRegistry()
    bus = EventBus()

    register_default_checks(registry, event_bus=bus)

    assert set(registry._checks.keys()) == {"database", "event_bus"}


@pytest.mark.unit
async def test_event_bus_check_reports_ok_for_a_real_event_bus():
    registry = HealthRegistry()
    bus = EventBus()
    register_default_checks(registry, event_bus=bus)

    result = await registry._checks["event_bus"]()

    assert result.status == Status.OK
