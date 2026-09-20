"""Post-merge user request (2026-08-02): `AvScanScheduler` — a real, but
runtime-editable (unlike `BackupScheduler`'s fixed-at-construction shape)
daily full-scan schedule. `load_settings`/`run_full_scan`/`clock`/`sleep`
are all injected fakes here (same convention `test_backup_scheduler.py`/
`test_metrics_sampler.py` already use for their own schedulers) — no real
DB, no real wall-clock waits, no real scan ever runs.
"""

from datetime import datetime, timedelta

import pytest

from app.services.av.scheduler import AvScanScheduler
from app.services.av.settings import AvScheduleSettings


def _settings(
    *, enabled: bool, hour: int = 6, minute: int = 0, days: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6)
) -> AvScheduleSettings:
    return AvScheduleSettings(
        full_scan_schedule_enabled=enabled,
        full_scan_hour=hour,
        full_scan_minute=minute,
        full_scan_days=days,
        updated_at=None,
    )


class _FakeClock:
    def __init__(self, start: datetime):
        self.now = start

    def __call__(self) -> datetime:
        return self.now


def _noop_sleep_factory():
    async def _sleep(_delay: float) -> None:
        return None

    return _sleep


@pytest.mark.unit
async def test_tick_does_nothing_when_schedule_disabled():
    clock = _FakeClock(datetime(2026, 8, 2, 6, 0))
    calls = []

    async def load_settings():
        return _settings(enabled=False)

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()

    assert calls == []


@pytest.mark.unit
async def test_tick_fires_exactly_once_at_the_scheduled_slot():
    clock = _FakeClock(datetime(2026, 8, 2, 6, 0, 30))  # 30s past the 06:00 slot
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0)

    async def run_full_scan():
        calls.append(clock.now)

    scheduler = AvScanScheduler(
        load_settings=load_settings, run_full_scan=run_full_scan, clock=clock, poll_interval_seconds=60.0
    )
    await scheduler._tick()
    assert len(calls) == 1

    # A second tick moments later, still the same slot — must NOT fire again.
    clock.now = clock.now + timedelta(seconds=30)
    await scheduler._tick()
    assert len(calls) == 1


@pytest.mark.unit
async def test_tick_does_not_fire_before_the_slot_arrives():
    clock = _FakeClock(datetime(2026, 8, 2, 5, 59))
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0)

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()

    assert calls == []


@pytest.mark.unit
async def test_tick_does_not_fire_on_a_day_not_in_full_scan_days():
    """Post-merge user request (2026-08-02): day-of-week selection — 2026-08-02
    is a Sunday (`datetime.weekday() == 6`); a schedule selecting only
    weekdays (0-4, Mon-Fri) must not fire today even though the time slot
    has arrived."""
    clock = _FakeClock(datetime(2026, 8, 2, 6, 0, 30))  # Sunday, just past 06:00
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0, days=(0, 1, 2, 3, 4))  # Mon-Fri only

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()

    assert calls == []


@pytest.mark.unit
async def test_tick_fires_on_a_day_that_is_in_full_scan_days():
    """Same schedule as above, but ticking on a day that IS selected
    (2026-08-03 is a Monday, `weekday() == 0`) — must fire normally."""
    clock = _FakeClock(datetime(2026, 8, 3, 6, 0, 30))  # Monday
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0, days=(0, 1, 2, 3, 4))  # Mon-Fri

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()

    assert calls == [1]


@pytest.mark.unit
async def test_tick_does_not_fire_when_no_days_selected_at_all():
    clock = _FakeClock(datetime(2026, 8, 2, 6, 0, 30))
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0, days=())

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()

    assert calls == []


@pytest.mark.unit
async def test_tick_does_not_retroactively_fire_a_slot_missed_hours_ago():
    """The process started (or woke up) well after today's slot passed —
    must wait for tomorrow's slot instead of firing a surprise "catch-up"
    scan, same reasoning `next_daily_run` (BackupScheduler) already applies
    by only ever computing a FUTURE occurrence."""
    clock = _FakeClock(datetime(2026, 8, 2, 14, 0))  # 8 hours after 06:00
    calls = []

    async def load_settings():
        return _settings(enabled=True, hour=6, minute=0)

    async def run_full_scan():
        calls.append(1)

    scheduler = AvScanScheduler(
        load_settings=load_settings, run_full_scan=run_full_scan, clock=clock, poll_interval_seconds=60.0
    )
    await scheduler._tick()

    assert calls == []


@pytest.mark.unit
async def test_tick_fires_again_the_next_day_at_the_new_slot():
    calls = []
    hour_holder = {"hour": 6}

    async def load_settings():
        return _settings(enabled=True, hour=hour_holder["hour"], minute=0)

    async def run_full_scan():
        calls.append(1)

    clock = _FakeClock(datetime(2026, 8, 2, 6, 0))
    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()
    assert len(calls) == 1

    clock.now = datetime(2026, 8, 3, 6, 0)
    await scheduler._tick()
    assert len(calls) == 2


@pytest.mark.unit
async def test_tick_fires_again_same_day_after_a_live_reschedule_to_a_later_time():
    """An operator moving the time LATER today (a live edit, mid-day) must
    be picked up on the very next poll — the whole point of this scheduler
    polling `av_settings` instead of BackupScheduler's fixed-at-startup
    shape."""
    calls = []
    settings_holder = {"hour": 6, "minute": 0}

    async def load_settings():
        return _settings(enabled=True, hour=settings_holder["hour"], minute=settings_holder["minute"])

    async def run_full_scan():
        calls.append(1)

    clock = _FakeClock(datetime(2026, 8, 2, 6, 0))
    scheduler = AvScanScheduler(load_settings=load_settings, run_full_scan=run_full_scan, clock=clock)
    await scheduler._tick()
    assert len(calls) == 1

    # Reschedule to 06:05 later today, then arrive at that new slot.
    settings_holder["minute"] = 5
    clock.now = datetime(2026, 8, 2, 6, 5)
    await scheduler._tick()
    assert len(calls) == 2


@pytest.mark.unit
async def test_one_bad_tick_never_kills_the_loop():
    """Same isolation every other scheduler in this codebase applies — a
    tick that raises (here: `load_settings` always fails) must not stop
    subsequent ticks from happening, same "real, driven loop" technique
    test_metrics_wiring.py's own scheduler-accumulation test already uses
    (a fake, instant `sleep` counted across several real loop iterations)."""
    import asyncio

    calls = []

    async def load_settings():
        raise RuntimeError("boom")

    async def run_full_scan():
        calls.append(1)

    sleeps = []

    async def fake_sleep(delay):
        sleeps.append(delay)
        await asyncio.sleep(0)

    scheduler = AvScanScheduler(
        load_settings=load_settings, run_full_scan=run_full_scan, sleep=fake_sleep, poll_interval_seconds=1.0
    )
    scheduler.start()
    try:
        for _ in range(500):
            if len(sleeps) >= 3:
                break
            await asyncio.sleep(0)
    finally:
        await scheduler.stop()

    # The loop survived at least 3 ticks despite load_settings always
    # raising — proof the exception isolation works.
    assert len(sleeps) >= 3
    assert calls == []


@pytest.mark.unit
async def test_start_is_idempotent_and_stop_cancels_cleanly():
    async def load_settings():
        return _settings(enabled=False)

    async def run_full_scan():
        pass

    scheduler = AvScanScheduler(
        load_settings=load_settings, run_full_scan=run_full_scan, sleep=_noop_sleep_factory()
    )
    scheduler.start()
    first_task = scheduler._task
    scheduler.start()
    assert scheduler._task is first_task
    assert scheduler.is_running

    await scheduler.stop()
    assert not scheduler.is_running
    await scheduler.stop()  # a second stop() is a safe no-op
