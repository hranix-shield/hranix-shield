"""A-26: reads `MetricSample` rows back out as a per-console, per-metric
"last 7 days" chart — the read side of services/metrics/sampler.py's write
side. Same per-calendar-day bucketing idea as
services/backup/wiring.py._size_chart_7d (that function is this one's
style reference, cited in the A-26 task brief), adapted for a
keep-sampling-forever *gauge* metric rather than a one-shot completed-job
event:

  - `_size_chart_7d` SUMs `size_bytes` per day — correct for its metric
    (bytes backed up that day is a genuine total), and a day with no
    successful backup legitimately sums to `0`.
  - This module AVERAGEs samples per day instead — these metrics
    (`active_connections`, `quarantine_count`, `active_bans_local`, ...)
    are point-in-time readings taken every `metrics_sample_interval_seconds`,
    not discrete completed-job events, so "the typical level that day" is
    the honest daily figure, not a sum that would scale with how often the
    sampler happened to run.

Honest empty-history handling (A-26 DoD: "недостаточно истории" must be a
*different* signal than the old, now-removed "chart not implemented"
placeholder, not just relabelled) — see MIN_HISTORY_DAYS below.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import MetricSample

CHART_DAYS = 7

# At least this many DISTINCT calendar days must already have at least one
# real sample before any chart is drawn at all. One lone day's worth of
# samples cannot honestly stand in for a "last 7 days" trend — a chart with
# 1 real day of data and 6 zero-filled placeholder days on either side
# would visually read as "activity fell off a cliff", which is not what
# "the sampler only started running yesterday" means. 2 is the smallest
# number that can show an actual trend (a real comparison between two real
# days) — matches the A-26 spec's own wording, "исчезает по мере накопления
# данных за НЕСКОЛЬКО дней" (a few days), not "only after a full 7-day
# week", which would make a fresh install wait a literal week to see any
# chart at all.
MIN_HISTORY_DAYS = 2


def _today(now: datetime | None) -> date:
    reference = now if now is not None else datetime.now(timezone.utc).replace(tzinfo=None)
    return reference.date()


async def chart_values_7d(
    session: AsyncSession,
    *,
    console_id: str,
    metric: str,
    now: datetime | None = None,
) -> list[float]:
    """The last `CHART_DAYS` days of `(console_id, metric)`, bucketed by
    calendar day (day-average of every sample recorded that day), oldest
    first, today last.

    Returns an EMPTY list — not a 7-element list of zeros — when fewer than
    `MIN_HISTORY_DAYS` distinct days have any real sample yet: the specific,
    intentional "недостаточно истории" signal
    routers/security_console.py's payload functions and app.js's chart
    renderer both key off of. This is unambiguous from a genuinely flat,
    all-real-zero week (e.g. a machine with zero active bans for 7 straight
    days) — that case has `MIN_HISTORY_DAYS`+ real days on record and
    returns a full 7-element `[0.0, 0.0, ...]`, not an empty list. The two
    only look the same if you don't check the length, which is exactly why
    callers must render off "is `values` empty" rather than "are all
    `values` falsy".
    """
    today = _today(now)
    window_start = today - timedelta(days=CHART_DAYS - 1)
    window_start_dt = datetime.combine(window_start, datetime.min.time())

    rows = (
        await session.execute(
            select(MetricSample.sampled_at, MetricSample.value).where(
                MetricSample.console_id == console_id,
                MetricSample.metric == metric,
                MetricSample.sampled_at >= window_start_dt,
            )
        )
    ).all()

    by_day: dict[date, list[float]] = {}
    for sampled_at, value in rows:
        day = sampled_at.date()
        if window_start <= day <= today:
            by_day.setdefault(day, []).append(value)

    if len(by_day) < MIN_HISTORY_DAYS:
        return []

    buckets = {window_start + timedelta(days=offset): 0.0 for offset in range(CHART_DAYS)}
    for day, values in by_day.items():
        buckets[day] = sum(values) / len(values)

    return [buckets[day] for day in sorted(buckets)]
