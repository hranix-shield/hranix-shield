"""A-14 unit coverage for the diagnostic-bundle assembly helpers, exercised
in isolation from HTTP/DB fixtures (see tests/integration/test_diagnostics_router.py
for the real-app-wiring version)."""

from __future__ import annotations

import json

import pytest

from app.config import Settings
from app.services.diagnostics import (
    MAX_EVENT_ROWS,
    MAX_LOG_LINES,
    _parse_log_line,
    _tail_lines,
    build_diagnostic_bundle,
    environment_info,
    read_recent_events,
    read_recent_logs,
)
from app.services.event_bus import EventBus
from app.services.health.registry import CheckResult, HealthRegistry, Status


@pytest.mark.unit
def test_tail_lines_returns_only_the_last_n_non_blank_lines(tmp_path):
    log_file = tmp_path / "app.log"
    log_file.write_text("one\ntwo\n\nthree\nfour\n")

    assert _tail_lines(log_file, 2) == ["three", "four"]


@pytest.mark.unit
def test_tail_lines_on_a_missing_file_returns_empty_list(tmp_path):
    assert _tail_lines(tmp_path / "does-not-exist.log", 10) == []


@pytest.mark.unit
def test_parse_log_line_decodes_a_real_json_formatter_record():
    raw = json.dumps(
        {"timestamp": "2026-07-15T00:00:00+0000", "level": "INFO", "logger": "app.x", "message": "hi"}
    )

    parsed = _parse_log_line(raw)

    assert parsed["level"] == "INFO"
    assert parsed["message"] == "hi"


@pytest.mark.unit
def test_parse_log_line_degrades_gracefully_for_non_json_text():
    parsed = _parse_log_line("not actually json {{{")

    assert parsed["message"] == "not actually json {{{"
    assert parsed["level"] is None


@pytest.mark.unit
def test_read_recent_logs_reads_and_parses_the_configured_file(tmp_path):
    log_file = tmp_path / "assistant.log"
    lines = [
        json.dumps({"level": "INFO", "logger": "a", "message": "first"}),
        json.dumps({"level": "ERROR", "logger": "b", "message": "second"}),
    ]
    log_file.write_text("\n".join(lines) + "\n")
    settings = Settings(_env_file=None, log_file=str(log_file))

    entries = read_recent_logs(settings, limit=10)

    assert [e["message"] for e in entries] == ["first", "second"]


@pytest.mark.unit
def test_read_recent_logs_returns_empty_list_when_file_logging_disabled():
    settings = Settings(_env_file=None, log_file="")

    assert read_recent_logs(settings) == []


@pytest.mark.unit
def test_read_recent_logs_clamps_an_out_of_range_limit(tmp_path):
    log_file = tmp_path / "assistant.log"
    log_file.write_text(json.dumps({"level": "INFO", "message": "x"}) + "\n")
    settings = Settings(_env_file=None, log_file=str(log_file))

    # A caller asking for more than MAX_LOG_LINES must not blow past the cap
    # (see module docstring) — exercised here via a below-1 value too, which
    # would otherwise slice the list backwards (`lines[-0:]` bug class).
    assert read_recent_logs(settings, limit=MAX_LOG_LINES + 500) is not None
    assert read_recent_logs(settings, limit=0) == read_recent_logs(settings, limit=1)


@pytest.mark.unit
async def test_read_recent_events_orders_oldest_first(migrated_session_maker):
    from app.db.models import Event

    async with migrated_session_maker() as session:
        session.add(Event(topic="a", payload={"n": 1}))
        session.add(Event(topic="b", payload={"n": 2}))
        session.add(Event(topic="c", payload={"n": 3}))
        await session.commit()

    async with migrated_session_maker() as session:
        events = await read_recent_events(session, limit=2)

    # limit=2 keeps only the 2 MOST RECENT rows (b, c), then presents them
    # oldest-first within that window.
    assert [e["topic"] for e in events] == ["b", "c"]


@pytest.mark.unit
async def test_read_recent_events_clamps_an_out_of_range_limit(migrated_session_maker):
    async with migrated_session_maker() as session:
        events = await read_recent_events(session, limit=MAX_EVENT_ROWS + 1000)

    assert events == []  # just proves it didn't raise on the oversized limit


@pytest.mark.unit
def test_environment_info_reports_version_and_ai_flag():
    settings = Settings(_env_file=None, ai_enabled=False)

    info = environment_info(settings)

    assert info["product"] == "Hranix Shield"
    assert info["ai_enabled"] is False
    assert "app_version" in info
    assert "python_version" in info


@pytest.mark.unit
async def test_build_diagnostic_bundle_assembles_all_four_sections(tmp_path, migrated_session_maker):
    log_file = tmp_path / "assistant.log"
    log_file.write_text(json.dumps({"level": "INFO", "message": "hello"}) + "\n")
    settings = Settings(_env_file=None, log_file=str(log_file))

    registry = HealthRegistry()

    async def ok_check() -> CheckResult:
        return CheckResult(status=Status.OK)

    registry.register("database", ok_check)
    bus = EventBus()

    async with migrated_session_maker() as session:
        bundle = await build_diagnostic_bundle(
            session=session,
            health_registry=registry,
            event_bus=bus,
            settings=settings,
        )

    assert bundle["health"]["status"] == "ok"
    assert bundle["logs"][0]["message"] == "hello"
    assert bundle["events"] == []
    assert bundle["environment"]["product"] == "Hranix Shield"
    assert "generated_at" in bundle


@pytest.mark.unit
async def test_build_diagnostic_bundle_reflects_a_down_subsystem():
    """Proves the DOWN path flows all the way through the bundle, even
    though Phase 0's two REAL registered checks (database/event_bus, see
    services/health/checks.py) never realistically produce DOWN themselves
    — see the A-14 task report for why that's a deliberate A-6 choice, and
    why this test uses a synthetic check to cover the DOWN branch anyway."""
    registry = HealthRegistry()

    async def down_check() -> CheckResult:
        return CheckResult(status=Status.DOWN, details={"error": "simulated critical failure"})

    registry.register("simulated_subsystem", down_check)
    bus = EventBus()

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.models import Base

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async with maker() as session:
        bundle = await build_diagnostic_bundle(
            session=session,
            health_registry=registry,
            event_bus=bus,
            settings=Settings(_env_file=None, log_file=""),
        )

    assert bundle["health"]["status"] == "down"
    assert bundle["health"]["components"]["simulated_subsystem"]["status"] == "down"
    await engine.dispose()
