"""A-26: `collect_current_metric_samples`/`run_metrics_sample_sweep` — the
write side of the metric-history mechanism. The four connector calls
(`fetch_ids_console_data`/`fetch_av_clamav_data`/`fetch_network_console_data`/
`fetch_logs_console_data`) are monkeypatched at their bare names imported
into `app.services.metrics.sampler`, same technique
tests/unit/test_crowdsec_ids_console_data.py's sibling router tests already
use for connector functions — so this file needs no real CrowdSec/ClamAV/
osquery/Wazuh.
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import select

import app.services.metrics.sampler as sampler_module
from app.db.models import MetricSample
from app.services.metrics.sampler import (
    collect_current_metric_samples,
    run_metrics_sample_sweep,
)

_NOW = datetime(2026, 7, 19, 12, 0)


def _ids_data(*, active_bans_local=None, active_bans_community=None):
    async def _fake(settings=None):
        return {
            "connector": {"status": "ok" if active_bans_local is not None else "not_configured"},
            "metrics": {
                "active_bans": None,
                "active_bans_local": active_bans_local,
                "active_bans_community": active_bans_community,
                "banned_24h": None,
                "scenarios": None,
                "last_event_at": None,
            },
            "recent_attempts": [],
        }

    return _fake


def _clamav_data(*, quarantine_count=None):
    async def _fake(settings=None, *, job_registry=None):
        return {
            "connector": {"status": "ok" if quarantine_count is not None else "not_configured"},
            "engine_version": None,
            "database_version": None,
            "databases_updated_at": None,
            "quarantine_count": quarantine_count,
            "last_scan_at": None,
            "clean": None,
        }

    return _fake


def _network_data(*, active_connections=None):
    async def _fake():
        return {
            "connector": {"status": "ok" if active_connections is not None else "not_configured"},
            "connections": [],
            "listening_ports": [],
            "active_connections": active_connections,
        }

    return _fake


def _logs_data(*, events_24h=None):
    async def _fake(settings=None):
        return {
            "connector": {"status": "ok" if events_24h is not None else "not_configured"},
            "metrics": {
                "events_24h": events_24h,
                "warnings_24h": None,
                "security_errors_24h": None,
                "sources": None,
            },
            "entries": [],
        }

    return _fake


def _patch_all_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        sampler_module, "fetch_ids_console_data", _ids_data(active_bans_local=3, active_bans_community=5)
    )
    monkeypatch.setattr(sampler_module, "fetch_av_clamav_data", _clamav_data(quarantine_count=2))
    monkeypatch.setattr(
        sampler_module, "fetch_network_console_data", _network_data(active_connections=7)
    )
    monkeypatch.setattr(sampler_module, "fetch_logs_console_data", _logs_data(events_24h=11))


def _patch_all_unconfigured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(sampler_module, "fetch_ids_console_data", _ids_data())
    monkeypatch.setattr(sampler_module, "fetch_av_clamav_data", _clamav_data())
    monkeypatch.setattr(sampler_module, "fetch_network_console_data", _network_data())
    monkeypatch.setattr(sampler_module, "fetch_logs_console_data", _logs_data())


@pytest.mark.unit
async def test_collect_reads_the_documented_field_from_each_connector(monkeypatch: pytest.MonkeyPatch):
    _patch_all_ok(monkeypatch)

    samples = await collect_current_metric_samples()

    assert ("ids", "active_bans_local", 3.0) in samples
    assert ("perimeter", "active_bans_community", 5.0) in samples
    assert ("av", "quarantine_count", 2.0) in samples
    assert ("network", "active_connections", 7.0) in samples
    assert ("logs", "events_24h", 11.0) in samples
    assert len(samples) == 5


@pytest.mark.unit
async def test_collect_skips_every_none_field_instead_of_fabricating_a_zero(
    monkeypatch: pytest.MonkeyPatch,
):
    """A console with no tool configured yet must never accumulate a
    fabricated `0` sample — that would silently manufacture a "genuinely
    flat, all-real-zero week" chart instead of the honest "insufficient
    history" state (see test_metrics_chart.py's own test for that
    distinction)."""
    _patch_all_unconfigured(monkeypatch)

    samples = await collect_current_metric_samples()

    assert samples == []


@pytest.mark.unit
async def test_collect_handles_a_mix_of_configured_and_unconfigured_sources(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        sampler_module, "fetch_ids_console_data", _ids_data(active_bans_local=1, active_bans_community=1)
    )
    monkeypatch.setattr(sampler_module, "fetch_av_clamav_data", _clamav_data())  # not configured
    monkeypatch.setattr(
        sampler_module, "fetch_network_console_data", _network_data(active_connections=0)
    )
    monkeypatch.setattr(sampler_module, "fetch_logs_console_data", _logs_data())  # not configured

    samples = await collect_current_metric_samples()

    assert ("ids", "active_bans_local", 1.0) in samples
    assert ("perimeter", "active_bans_community", 1.0) in samples
    # A real, queried zero IS recorded (unlike None) — "0 active connections"
    # is a genuine answer, not a missing one.
    assert ("network", "active_connections", 0.0) in samples
    assert len(samples) == 3


@pytest.mark.unit
async def test_run_sweep_writes_one_row_per_sample_with_the_given_timestamp(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    _patch_all_ok(monkeypatch)

    written = await run_metrics_sample_sweep(migrated_session_maker, now=_NOW)

    assert written == 5
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(MetricSample))).all()
    assert len(rows) == 5
    assert all(row.sampled_at == _NOW for row in rows)
    by_key = {(row.console_id, row.metric): row.value for row in rows}
    assert by_key[("ids", "active_bans_local")] == 3.0
    assert by_key[("av", "quarantine_count")] == 2.0


@pytest.mark.unit
async def test_run_sweep_writes_nothing_and_returns_0_when_every_source_is_unconfigured(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    _patch_all_unconfigured(monkeypatch)

    written = await run_metrics_sample_sweep(migrated_session_maker, now=_NOW)

    assert written == 0
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(MetricSample))).all()
    assert rows == []


@pytest.mark.unit
async def test_run_sweep_defaults_now_to_the_real_clock_when_not_given(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    _patch_all_ok(monkeypatch)
    before = datetime.now(timezone.utc).replace(tzinfo=None)

    await run_metrics_sample_sweep(migrated_session_maker)

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(MetricSample))).all()
    after = datetime.now(timezone.utc).replace(tzinfo=None)
    assert all(before <= row.sampled_at <= after for row in rows)
