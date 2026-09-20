"""A-26: the write side of this project's first metric-history mechanism
(see chart.py for the read side, and
docs/план-спецификация-фаза-0-реальные-функции-панели-2026-07-19.md's
"Технический аудит" for why one never existed before — every console's
`chart.values` was a hardcoded `[]`, even where a connector already
computed a real number).

`collect_current_metric_samples()` is the pure, directly-testable piece
(one round of connector calls -> a list of `(console_id, metric, value)`
tuples, no DB, no waiting); `run_metrics_sample_sweep()` writes that round
to `MetricSample` rows with an injectable `now` (mirrors
services/notifications/escalation.py's `run_escalation_sweep`);
`MetricsSampleScheduler` is the periodic background loop that calls it in
production — same "asyncio background task, injectable clock/sleep, always
sleeps before the first run" idiom as `EscalationScheduler`, kept as its
own small class here rather than imported from services/notifications/:
every recurring background loop in this codebase so far documents+mirrors
the previous one instead of sharing a base class (`EscalationScheduler`'s
own docstring cites `BackupScheduler` the exact same way, despite the two
being structurally almost identical) — this keeps that same convention,
and keeps services/metrics/ from depending on services/notifications/.

Which metric, per console, and why
-----------------------------------
Only fields a connector ALREADY computes for real today are sampled — this
task's own brief is explicit that inventing a number belongs nowhere near
this project (the same discipline that made A-23 split CrowdSec's
`active_bans` in the first place). `perimeter`'s `open_ports`/
`firewall_rules` are deliberately NOT sampled: both are still a hardcoded
`0` in `_perimeter_payload` pending A-28's real osquery wiring, and
sampling a constant into a "history" table would manufacture a fake trend
line, worse than no chart at all.

  - `ids` + `perimeter` share ONE `fetch_ids_console_data()` call (exactly
    like `_perimeter_payload` itself reuses A-11's CrowdSec connector
    rather than re-implementing it): `ids` samples `active_bans_local`
    (real local-attempt count, the same field A-23 already carved out as
    "what actually happened here" — matches the task brief's own example);
    `perimeter` samples `active_bans_community` (the global CrowdSec
    community-blocklist count). Post-merge user question (2026-07-31): the
    perimeter chart used to plot local+community summed into one number/one
    bar, which reads as "this many things happened on MY machine" when in
    fact almost all of it is CrowdSec's shared worldwide blocklist, not
    local activity — same "real number, misleading label" class of problem
    A-23 already fixed for `ids`'s own tiles. `_perimeter_payload` now
    charts TWO series side by side instead: this `active_bans_community`
    sample (perimeter-scoped) plus `ids`'s own already-sampled
    `active_bans_local` history, READ (not re-sampled) — the exact same
    real number `ids`'s own chart already accumulates, no second, duplicate
    sample of the same fact under a second console_id.
  - `av` samples ClamAV's `quarantine_count` — a real, disk-backed count
    (`clamav._count_quarantined_files`) available whenever clamd answers
    "ok", regardless of whether a scan ran recently. Deliberately NOT
    "files scanned" (`ScanJob.scanned_count`, in
    `ClamAvScanJobRegistry`): that history is process-memory-only and
    reset by every restart (see that registry's own docstring), so it
    would silently go quiet — and this task's history is meant to survive
    restarts, same as the DB itself does.
  - `network` samples osquery's `active_connections`.
  - `logs` samples Wazuh's `events_24h` (FIM findings in the last 24h).

Every value a connector reports as `None` (not configured / unreachable —
see that connector's own docstring for what its states mean) is skipped
entirely, never recorded as a fabricated `0`: a console with no tool
configured yet should keep showing "insufficient history", not a flat,
lying zero line that looks like real, sampled quiet.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.db.models import MetricSample
from app.db.session import async_session_maker
from app.services.mcp.security_connectors import (
    fetch_av_clamav_data,
    fetch_ids_console_data,
    fetch_logs_console_data,
    fetch_network_console_data,
)

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]

# Console/metric name constants — the single source of truth shared with
# routers/security_console.py's payload functions, which query
# chart.chart_values_7d() for these exact same (console_id, metric) pairs.
# Kept here (the write side) rather than duplicated as string literals at
# each read call site, so a typo in either place fails loudly (an unknown
# metric name just never accumulates any history) rather than silently
# mismatching.
PERIMETER_CONSOLE_ID = "perimeter"
IDS_CONSOLE_ID = "ids"
AV_CONSOLE_ID = "av"
NETWORK_CONSOLE_ID = "network"
LOGS_CONSOLE_ID = "logs"

METRIC_ACTIVE_BANS_LOCAL = "active_bans_local"
METRIC_ACTIVE_BANS_COMMUNITY = "active_bans_community"
METRIC_QUARANTINE_COUNT = "quarantine_count"
METRIC_ACTIVE_CONNECTIONS = "active_connections"
METRIC_EVENTS_24H = "events_24h"


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def collect_current_metric_samples() -> list[tuple[str, str, float]]:
    """One point-in-time reading across the 5 non-backup consoles — see
    this module's docstring for exactly which field, per console, and why.
    Never raises: every connector call already has its own honest
    unreachable/not-configured handling (returns `None` fields, not an
    exception), and this function simply skips any `None` it sees."""
    samples: list[tuple[str, str, float]] = []

    ids_data = await fetch_ids_console_data()
    active_bans_local = ids_data["metrics"].get("active_bans_local")
    if active_bans_local is not None:
        samples.append((IDS_CONSOLE_ID, METRIC_ACTIVE_BANS_LOCAL, float(active_bans_local)))
    active_bans_community = ids_data["metrics"].get("active_bans_community")
    if active_bans_community is not None:
        samples.append((PERIMETER_CONSOLE_ID, METRIC_ACTIVE_BANS_COMMUNITY, float(active_bans_community)))

    clamav_data = await fetch_av_clamav_data()
    quarantine_count = clamav_data.get("quarantine_count")
    if quarantine_count is not None:
        samples.append((AV_CONSOLE_ID, METRIC_QUARANTINE_COUNT, float(quarantine_count)))

    network_data = await fetch_network_console_data()
    active_connections = network_data.get("active_connections")
    if active_connections is not None:
        samples.append((NETWORK_CONSOLE_ID, METRIC_ACTIVE_CONNECTIONS, float(active_connections)))

    logs_data = await fetch_logs_console_data()
    events_24h = logs_data["metrics"].get("events_24h")
    if events_24h is not None:
        samples.append((LOGS_CONSOLE_ID, METRIC_EVENTS_24H, float(events_24h)))

    return samples


async def run_metrics_sample_sweep(
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    *,
    now: datetime | None = None,
) -> int:
    """Collects one round of samples and inserts them as `MetricSample`
    rows timestamped `now` (injectable for tests, same convention as
    services/notifications/escalation.run_escalation_sweep). Returns how
    many rows were written — `0` is a legitimate, honest result (every
    source was unconfigured/unreachable this round), not an error."""
    maker = session_maker or async_session_maker
    sampled_at = now if now is not None else _default_clock()

    samples = await collect_current_metric_samples()
    if not samples:
        return 0

    async with maker() as session:
        for console_id, metric, value in samples:
            session.add(
                MetricSample(
                    console_id=console_id, metric=metric, value=value, sampled_at=sampled_at
                )
            )
        await session.commit()

    return len(samples)


class MetricsSampleScheduler:
    """Runs `run_once` every `interval_seconds`, forever, until `stop()` —
    see this module's docstring for why this mirrors (rather than reuses)
    `EscalationScheduler`.

    Always sleeps BEFORE the first run: a short-lived lifespan in a test
    that spins up the real app (`with TestClient(app): pass`) gets
    cancelled mid-sleep, never reaching a real DB query, unless the test
    explicitly drives `sleep`/`run_once` itself — same reasoning
    `EscalationScheduler`'s own docstring documents.
    """

    def __init__(
        self,
        *,
        interval_seconds: float,
        run_once: Callable[[], Awaitable[None]],
        sleep: Sleeper | None = None,
    ) -> None:
        self._interval_seconds = interval_seconds
        self._run_once = run_once
        self._sleep = sleep or asyncio.sleep
        self._task: asyncio.Task | None = None

    async def _loop(self) -> None:
        while True:
            await self._sleep(self._interval_seconds)
            try:
                await self._run_once()
            except Exception:
                # One bad sweep must never kill the loop, or every
                # subsequent sample silently stops being collected — same
                # isolation EscalationScheduler/BackupScheduler both apply.
                logger.error("metrics: sample sweep raised", exc_info=True)

    def start(self) -> None:
        """Idempotent: calling start() while already running is a no-op,
        not a second concurrent loop."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()


def create_default_metrics_scheduler(*, settings: Settings | None = None) -> MetricsSampleScheduler:
    """A `MetricsSampleScheduler` wired to real Settings — used by
    app_factory's lifespan, mirrors
    services/notifications/create_default_escalation_scheduler."""
    settings = settings or get_settings()

    async def _run_once() -> None:
        await run_metrics_sample_sweep()

    return MetricsSampleScheduler(
        interval_seconds=settings.metrics_sample_interval_seconds, run_once=_run_once
    )
