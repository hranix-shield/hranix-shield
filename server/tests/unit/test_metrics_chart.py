"""A-26: `chart_values_7d` against a real (tmp, migrated) SQLite DB — same
"unit test, real tmp DB" shape as tests/unit/test_notifications_escalation_sweep.py.
Exercises the read side of the metric-history mechanism directly, without
going through any router/connector.
"""

from datetime import datetime, timedelta

import pytest

from app.db.models import MetricSample
from app.services.metrics.chart import CHART_DAYS, MIN_HISTORY_DAYS, chart_values_7d

_NOW = datetime(2026, 7, 19, 12, 0)


async def _insert(maker, *, console_id: str, metric: str, value: float, sampled_at: datetime) -> None:
    async with maker() as session:
        session.add(
            MetricSample(console_id=console_id, metric=metric, value=value, sampled_at=sampled_at)
        )
        await session.commit()


@pytest.mark.unit
async def test_no_samples_at_all_is_insufficient_history(migrated_session_maker):
    async with migrated_session_maker() as session:
        values = await chart_values_7d(session, console_id="ids", metric="active_bans_local", now=_NOW)

    assert values == []


@pytest.mark.unit
async def test_a_single_days_worth_of_samples_is_still_insufficient_history(migrated_session_maker):
    """MIN_HISTORY_DAYS (2) distinct days are required — one lone day's
    worth of real samples cannot honestly show a "last 7 days" trend (see
    chart.py's own docstring for why)."""
    assert MIN_HISTORY_DAYS == 2
    await _insert(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        value=3,
        sampled_at=_NOW,
    )
    await _insert(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        value=5,
        sampled_at=_NOW - timedelta(hours=2),
    )

    async with migrated_session_maker() as session:
        values = await chart_values_7d(session, console_id="ids", metric="active_bans_local", now=_NOW)

    assert values == []


@pytest.mark.unit
async def test_two_distinct_days_is_enough_to_render_a_real_chart(migrated_session_maker):
    today = _NOW
    yesterday = _NOW - timedelta(days=1)
    await _insert(
        migrated_session_maker, console_id="ids", metric="active_bans_local", value=4, sampled_at=today
    )
    await _insert(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        value=2,
        sampled_at=yesterday,
    )

    async with migrated_session_maker() as session:
        values = await chart_values_7d(session, console_id="ids", metric="active_bans_local", now=_NOW)

    assert len(values) == CHART_DAYS
    assert values[-1] == 4.0  # today is the last (rightmost) bucket
    assert values[-2] == 2.0  # yesterday, one bucket to the left
    # Every day further back than yesterday genuinely has no sample yet —
    # zero-filled, same accepted convention as
    # services/backup/wiring.py._size_chart_7d.
    assert values[:-2] == [0.0] * (CHART_DAYS - 2)


@pytest.mark.unit
async def test_multiple_samples_on_the_same_day_are_averaged(migrated_session_maker):
    today = _NOW
    yesterday = _NOW - timedelta(days=1)
    for value in (2, 4, 6):
        await _insert(
            migrated_session_maker,
            console_id="network",
            metric="active_connections",
            value=value,
            sampled_at=today - timedelta(hours=value),
        )
    await _insert(
        migrated_session_maker,
        console_id="network",
        metric="active_connections",
        value=10,
        sampled_at=yesterday,
    )

    async with migrated_session_maker() as session:
        values = await chart_values_7d(
            session, console_id="network", metric="active_connections", now=_NOW
        )

    assert values[-1] == 4.0  # average of 2, 4, 6
    assert values[-2] == 10.0


@pytest.mark.unit
async def test_a_genuinely_flat_all_zero_week_is_a_real_chart_not_insufficient_history(
    migrated_session_maker,
):
    """Distinguishes "no history at all" (empty list) from "real history,
    every day happened to be zero" (a full 7-element list of literal
    0.0s) — collapsing the two would misreport a quiet-but-monitored
    machine as "insufficient history"."""
    for offset in range(3):
        await _insert(
            migrated_session_maker,
            console_id="av",
            metric="quarantine_count",
            value=0,
            sampled_at=_NOW - timedelta(days=offset),
        )

    async with migrated_session_maker() as session:
        values = await chart_values_7d(session, console_id="av", metric="quarantine_count", now=_NOW)

    assert values == [0.0] * CHART_DAYS


@pytest.mark.unit
async def test_samples_outside_the_7_day_window_are_excluded(migrated_session_maker):
    await _insert(
        migrated_session_maker,
        console_id="logs",
        metric="events_24h",
        value=99,
        sampled_at=_NOW - timedelta(days=30),
    )
    await _insert(
        migrated_session_maker,
        console_id="logs",
        metric="events_24h",
        value=1,
        sampled_at=_NOW,
    )
    await _insert(
        migrated_session_maker,
        console_id="logs",
        metric="events_24h",
        value=2,
        sampled_at=_NOW - timedelta(days=1),
    )

    async with migrated_session_maker() as session:
        values = await chart_values_7d(session, console_id="logs", metric="events_24h", now=_NOW)

    assert sum(values) == 3  # the 30-day-old sample never contributes


@pytest.mark.unit
async def test_a_different_consoles_samples_never_leak_into_this_ones_chart(migrated_session_maker):
    today = _NOW
    yesterday = _NOW - timedelta(days=1)
    await _insert(
        migrated_session_maker, console_id="perimeter", metric="active_bans_community", value=7, sampled_at=today
    )
    await _insert(
        migrated_session_maker,
        console_id="perimeter",
        metric="active_bans_community",
        value=7,
        sampled_at=yesterday,
    )
    # Same metric name, different console — must not count towards
    # `ids`'s own history, and must not appear in its own averages either.
    await _insert(
        migrated_session_maker, console_id="ids", metric="active_bans_community", value=999, sampled_at=today
    )

    async with migrated_session_maker() as session:
        ids_values = await chart_values_7d(
            session, console_id="ids", metric="active_bans_community", now=_NOW
        )
        perimeter_values = await chart_values_7d(
            session, console_id="perimeter", metric="active_bans_community", now=_NOW
        )

    assert ids_values == []  # only one distinct day for `ids` -> insufficient history
    assert perimeter_values[-1] == 7.0
