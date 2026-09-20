"""A-26: `create_default_metrics_scheduler` — the layer that reads real
`Settings` and assembles the periodic sampler the same way
services/backup/wiring.py's `create_default_scheduler` does for backups
(see that file's own wiring tests, test_backup_wiring.py, for the sibling
pattern this mirrors).

Also drives `MetricsSampleScheduler` through several real ticks with a
fake (non-wall-clock) sleep against a real migrated tmp DB — this is the
"тест с замоканным clock" half of A-26's DoD (see the task brief: either a
mocked-clock test driving several iterations, or a live, wall-clock wait —
this file is the former).
"""

import asyncio
from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.metrics.sampler as sampler_module
from app.config import Settings
from app.db.models import MetricSample
from app.services.metrics import create_default_metrics_scheduler
from app.services.metrics.sampler import MetricsSampleScheduler


@pytest.mark.integration
def test_create_default_metrics_scheduler_uses_the_configured_interval():
    settings = Settings(_env_file=None, metrics_sample_interval_seconds=123)

    scheduler = create_default_metrics_scheduler(settings=settings)

    assert scheduler is not None
    assert scheduler._interval_seconds == 123


@pytest.mark.integration
def test_create_default_metrics_scheduler_defaults_to_15_minutes():
    settings = Settings(_env_file=None)

    scheduler = create_default_metrics_scheduler(settings=settings)

    assert scheduler._interval_seconds == 900


@pytest.mark.integration
async def test_create_default_metrics_schedulers_run_once_writes_real_samples(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`create_default_metrics_scheduler`'s own `_run_once` closure calls
    `run_metrics_sample_sweep()` with no explicit session_maker — redirect
    the module-global the same way test_backup_wiring.py/conftest.py
    already do for their own module-globals, so this never touches the
    real data/assistant.db."""
    monkeypatch.setattr(sampler_module, "async_session_maker", migrated_session_maker)

    async def _fake_ids(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {
                "active_bans": 2,
                "active_bans_local": 1,
                "active_bans_community": 1,
                "banned_24h": None,
                "scenarios": 1,
                "last_event_at": None,
            },
            "recent_attempts": [],
        }

    async def _fake_clamav(settings=None, *, job_registry=None):
        return {
            "connector": {"status": "ok"},
            "engine_version": None,
            "database_version": None,
            "databases_updated_at": None,
            "quarantine_count": 0,
            "last_scan_at": None,
            "clean": True,
        }

    async def _fake_network():
        return {
            "connector": {"status": "ok"},
            "connections": [],
            "listening_ports": [],
            "active_connections": 4,
        }

    async def _fake_logs(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {
                "events_24h": 9,
                "warnings_24h": None,
                "security_errors_24h": None,
                "sources": 1,
            },
            "entries": [],
        }

    monkeypatch.setattr(sampler_module, "fetch_ids_console_data", _fake_ids)
    monkeypatch.setattr(sampler_module, "fetch_av_clamav_data", _fake_clamav)
    monkeypatch.setattr(sampler_module, "fetch_network_console_data", _fake_network)
    monkeypatch.setattr(sampler_module, "fetch_logs_console_data", _fake_logs)

    scheduler = create_default_metrics_scheduler(settings=Settings(_env_file=None))
    assert scheduler is not None

    await scheduler._run_once()

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(MetricSample))).all()

    assert len(rows) == 5
    by_key = {(row.console_id, row.metric): row.value for row in rows}
    assert by_key[("ids", "active_bans_local")] == 1.0
    assert by_key[("perimeter", "active_bans_community")] == 1.0
    assert by_key[("av", "quarantine_count")] == 0.0
    assert by_key[("network", "active_connections")] == 4.0
    assert by_key[("logs", "events_24h")] == 9.0


@pytest.mark.integration
async def test_scheduler_accumulates_real_rows_over_several_fake_intervals(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Drives the real `MetricsSampleScheduler` loop (not just `_run_once`
    directly) through several ticks with a fake, instant `sleep` — the
    "прогони несколько итераций планировщика ... с замоканным clock" DoD
    item. Each tick is timestamped by a fake, advancing clock so the 5
    rows per round land on 3 distinct calendar days, same shape a real
    multi-day deployment would eventually accumulate."""
    monkeypatch.setattr(sampler_module, "async_session_maker", migrated_session_maker)

    async def _fake_ids(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {
                "active_bans": 1,
                "active_bans_local": 1,
                "active_bans_community": 0,
                "banned_24h": None,
                "scenarios": 1,
                "last_event_at": None,
            },
            "recent_attempts": [],
        }

    async def _fake_clamav(settings=None, *, job_registry=None):
        return {
            "connector": {"status": "ok"},
            "engine_version": None,
            "database_version": None,
            "databases_updated_at": None,
            "quarantine_count": 1,
            "last_scan_at": None,
            "clean": False,
        }

    async def _fake_network():
        return {
            "connector": {"status": "ok"},
            "connections": [],
            "listening_ports": [],
            "active_connections": 1,
        }

    async def _fake_logs(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {"events_24h": 1, "warnings_24h": None, "security_errors_24h": None, "sources": 1},
            "entries": [],
        }

    monkeypatch.setattr(sampler_module, "fetch_ids_console_data", _fake_ids)
    monkeypatch.setattr(sampler_module, "fetch_av_clamav_data", _fake_clamav)
    monkeypatch.setattr(sampler_module, "fetch_network_console_data", _fake_network)
    monkeypatch.setattr(sampler_module, "fetch_logs_console_data", _fake_logs)

    clock_days = iter([datetime(2026, 7, 17, 9, 0), datetime(2026, 7, 18, 9, 0), datetime(2026, 7, 19, 9, 0)])

    completed: list[int] = []

    async def _run_once() -> None:
        await sampler_module.run_metrics_sample_sweep(migrated_session_maker, now=next(clock_days))
        # Recorded AFTER the sweep actually finishes writing — unlike
        # `delays` below (appended when `sleep` is entered, i.e. BEFORE
        # that round's `run_once` has necessarily completed), this is the
        # correct signal to wait on: stopping the scheduler as soon as
        # `len(delays) >= 3` would risk cancelling the 3rd sweep mid-write
        # (found live while writing this test — it under-counted rows).
        completed.append(1)

    delays: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        delays.append(delay)
        await asyncio.sleep(0)

    scheduler = MetricsSampleScheduler(interval_seconds=900, run_once=_run_once, sleep=_fake_sleep)
    scheduler.start()
    try:
        # Ждём фактического завершения трёх свипов с настенным дедлайном, а не
        # фиксированного бюджета yield'ов: `asyncio.sleep(0)` крутится быстрее,
        # чем aiosqlite успевает провести потоковые записи на холодной ФС, и
        # бюджет сгорал до первого completed (ловилось в linux-контейнере:
        # 0 из 500 yield'ов при живом, ещё не завершённом первом свипе).
        async def _wait_three_completed() -> None:
            while len(completed) < 3:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(_wait_three_completed(), timeout=30)
    finally:
        await scheduler.stop()

    assert len(completed) >= 3
    assert delays[:3] == [900, 900, 900]

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(MetricSample))).all()

    # 3 real ticks x 5 samples/tick = 15 rows, spread across 3 distinct
    # calendar days — exactly the "history accumulates over several
    # intervals" behaviour A-26's DoD asks to demonstrate.
    assert len(rows) == 15
    distinct_days = {row.sampled_at.date() for row in rows}
    assert len(distinct_days) == 3
