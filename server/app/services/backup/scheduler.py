"""The daily automatic-backup schedule (default 04:00, see A-12 spec §7.1).

Judgment call (see A-12 task report): a plain asyncio background task, not
a scheduler library (APScheduler/etc.). Phase 0 needs exactly one recurring
job — "run this once a day at HH:MM" — and stdlib `asyncio.sleep` computed
against "how long until the next HH:MM" covers that completely, including
surviving process restarts (the next run is always recomputed from the
current wall-clock time, never from a stored "last scheduled for" value)
without adding a dependency (and its license) for a single cron line's
worth of behavior.

Timestamps here are naive UTC, matching every other stored timestamp in
this codebase (see services.auth._now_utc_naive, services.backup.service._now)
— deliberately NOT the user's local time. That sidesteps DST-transition
ambiguity entirely (UTC never has one), at the cost of "04:00" meaning
04:00 UTC rather than 4am on the user's laptop. Flagged in the task report
as a scoped simplification / candidate follow-up (a later phase can make
this timezone-aware once the panel has a place to configure the user's
timezone at all).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def next_daily_run(hour: int, minute: int, *, now: datetime | None = None) -> datetime:
    """The next `hour:minute` at or after `now` (defaults to the live UTC
    clock): today if that time hasn't passed yet, otherwise tomorrow.

    A module-level pure function (not just `BackupScheduler.next_run_at`)
    so callers that want "when is the next automatic run" — e.g. the
    backup console's `next_scheduled_at` field, see
    services/backup/wiring.py — don't need a live `BackupScheduler`
    instance to ask the question.
    """
    now = now if now is not None else _default_clock()
    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if candidate <= now:
        candidate += timedelta(days=1)
    return candidate


class BackupScheduler:
    """Runs `run_once` once a day at `hour:minute`, forever, until `stop()`.

    `clock`/`sleep` are injectable so tests can drive the loop without
    waiting real wall-clock time (a fake clock reporting times close to the
    target, paired with a fake `sleep` that returns instantly regardless of
    the requested delay) — see tests/unit/test_backup_scheduler.py. The
    production path (no args given) uses the real clock and `asyncio.sleep`.
    """

    def __init__(
        self,
        *,
        hour: int,
        minute: int,
        run_once: Callable[[], Awaitable[None]],
        clock: Clock | None = None,
        sleep: Sleeper | None = None,
    ) -> None:
        self._hour = hour
        self._minute = minute
        self._run_once = run_once
        self._clock = clock or _default_clock
        self._sleep = sleep or asyncio.sleep
        self._task: asyncio.Task | None = None

    def next_run_at(self, *, now: datetime | None = None) -> datetime:
        """The next HH:MM at or after `now` (defaults to this scheduler's
        own clock, which tests may have replaced with a fake one)."""
        now = now if now is not None else self._clock()
        return next_daily_run(self._hour, self._minute, now=now)

    async def _loop(self) -> None:
        while True:
            now = self._clock()
            target = self.next_run_at(now=now)
            delay = (target - now).total_seconds()
            if delay > 0:
                await self._sleep(delay)
            try:
                await self._run_once()
            except Exception:
                # Isolated the same way EventBus.publish isolates a failing
                # subscriber (see event_bus.py): one bad scheduled run must
                # never kill the loop, or every subsequent day's automatic
                # backup silently stops happening.
                logger.error("backup: scheduled run raised", exc_info=True)

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
