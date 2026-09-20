"""Post-merge user request (2026-08-02): a REAL daily full-scan schedule —
the console used to display "daily_06:00" with zero background enforcement
(no scheduler ever read that string, see `AvSettings`'s own docstring in
app/db/models.py). This is genuine enforcement, but a different SHAPE than
`services/backup/scheduler.py`'s `BackupScheduler`, deliberately: backup's
hour/minute are fixed at construction (read once from `Settings`/.env,
immutable for the process's life — see that module's own docstring), which
is wrong here on purpose, because the whole point of this task is a
schedule the operator can edit at runtime from the console UI without a
restart. So `AvScanScheduler` POLLS `av_settings` on every tick instead of
being told a fixed hour/minute once — a change the operator makes mid-day
takes effect on this scheduler's very next poll, not "after the next
restart".

Unconditional in `app_factory.py`'s lifespan (not gated behind a settings
flag) — same reasoning `MetricsSampleScheduler`/`NetworkProfileScheduler`
already document: this scheduler's own tick is a harmless no-op DB read
whenever `full_scan_schedule_enabled` is off (the honest default for a
fresh install, see settings.py), so every deployment can safely always run
it rather than needing yet another env flag.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from app.services.av.settings import AvScheduleSettings

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]

# How often this scheduler wakes up to re-check `av_settings` and the
# current time — short enough that an operator's edit (enable/disable,
# change the time) takes effect promptly, long enough that idle polling
# never shows up as meaningful load. Also doubles as the "how late is still
# close enough to fire" window in `_tick` below.
_DEFAULT_POLL_INTERVAL_SECONDS = 60.0


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class AvScanScheduler:
    """Runs `run_full_scan` once a day at whatever `load_settings()`
    currently reports as `full_scan_hour`:`full_scan_minute`, for as long as
    `full_scan_schedule_enabled` is `True` at poll time — forever, until
    `stop()`.

    `load_settings`/`run_full_scan`/`clock`/`sleep` are all injectable (same
    convention every other scheduler in this codebase already uses — see
    `BackupScheduler`/`MetricsSampleScheduler`) so tests can drive this
    without a real DB or real wall-clock waits.
    """

    def __init__(
        self,
        *,
        load_settings: Callable[[], Awaitable[AvScheduleSettings]],
        run_full_scan: Callable[[], Awaitable[None]],
        clock: Clock | None = None,
        sleep: Sleeper | None = None,
        poll_interval_seconds: float = _DEFAULT_POLL_INTERVAL_SECONDS,
    ) -> None:
        self._load_settings = load_settings
        self._run_full_scan = run_full_scan
        self._clock = clock or _default_clock
        self._sleep = sleep or asyncio.sleep
        self._poll_interval_seconds = poll_interval_seconds
        # The exact datetime "slot" (today's target hour:minute) already
        # fired for — compared by VALUE, not just a date, so a same-day
        # reschedule (operator moves the time earlier/later) is correctly
        # treated as a NEW, not-yet-fired slot even though the date is
        # unchanged.
        self._last_fired_slot: datetime | None = None
        self._task: asyncio.Task | None = None

    async def _tick(self) -> None:
        settings = await self._load_settings()
        if not settings.full_scan_schedule_enabled:
            return
        now = self._clock()
        # Post-merge user request (2026-08-02): day-of-week selection —
        # `now.weekday()` matches `full_scan_days`'s own documented
        # convention (0=Monday...6=Sunday, see AvSettings.full_scan_days).
        if now.weekday() not in settings.full_scan_days:
            return
        slot = now.replace(
            hour=settings.full_scan_hour, minute=settings.full_scan_minute, second=0, microsecond=0
        )
        if slot > now:
            return  # today's slot hasn't arrived yet
        if self._last_fired_slot == slot:
            return  # already fired for this exact slot
        # More than one poll window late: this process was almost certainly
        # asleep/just-started well after today's slot passed — treat it as
        # MISSED rather than firing a "catch-up" scan hours late, and wait
        # for tomorrow's slot instead. Marking it fired (without running)
        # prevents this same stale slot from re-triggering the check above
        # on every subsequent tick for the rest of the day.
        if (now - slot).total_seconds() > self._poll_interval_seconds * 2:
            self._last_fired_slot = slot
            return
        self._last_fired_slot = slot
        await self._run_full_scan()

    async def _loop(self) -> None:
        while True:
            await self._sleep(self._poll_interval_seconds)
            try:
                await self._tick()
            except Exception:
                # One bad tick must never kill the loop, or every subsequent
                # day's automatic scan silently stops happening — same
                # isolation every other scheduler in this codebase applies.
                logger.error("av: scheduled full-scan tick raised", exc_info=True)

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
