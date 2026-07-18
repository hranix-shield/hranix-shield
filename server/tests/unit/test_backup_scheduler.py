"""A-12: BackupScheduler — pure logic + an injected fake clock/sleep, no
real restic/DB I/O involved (that's exercised end-to-end in
tests/integration/test_backup_service.py and the e2e restore scenario).

The fake `sleep` below always does a real `await asyncio.sleep(0)` — a true
(if minimal) suspension point — so the scheduler's background task
genuinely interleaves with the test coroutine's own polling loop one loop
iteration at a time, rather than this test's assumptions depending on
exactly how many Python statements happen to run before control returns to
the event loop.
"""

import asyncio
from datetime import datetime, timedelta

import pytest

from app.services.backup.scheduler import BackupScheduler, next_daily_run


@pytest.mark.unit
def test_next_daily_run_is_today_when_target_time_has_not_passed_yet():
    now = datetime(2026, 7, 14, 2, 0, 0)

    result = next_daily_run(4, 0, now=now)

    assert result == datetime(2026, 7, 14, 4, 0, 0)


@pytest.mark.unit
def test_next_daily_run_is_tomorrow_when_target_time_has_already_passed():
    now = datetime(2026, 7, 14, 5, 0, 0)

    result = next_daily_run(4, 0, now=now)

    assert result == datetime(2026, 7, 15, 4, 0, 0)


@pytest.mark.unit
def test_next_daily_run_at_exactly_the_target_time_rolls_to_tomorrow():
    """`<=` in the comparison (not `<`): a run firing exactly at 04:00:00.000
    must not compute "today at 04:00" again as its own next run — that would
    be an instant repeat, not a once-a-day schedule."""
    now = datetime(2026, 7, 14, 4, 0, 0)

    result = next_daily_run(4, 0, now=now)

    assert result == datetime(2026, 7, 15, 4, 0, 0)


async def _noop() -> None:
    return None


@pytest.mark.unit
def test_scheduler_next_run_at_uses_its_own_injected_clock():
    scheduler = BackupScheduler(
        hour=4,
        minute=0,
        run_once=_noop,
        clock=lambda: datetime(2026, 7, 14, 1, 0, 0),
    )

    assert scheduler.next_run_at() == datetime(2026, 7, 14, 4, 0, 0)


def _fake_clock_and_sleep(start: datetime):
    """A clock/sleep pair sharing one mutable "now": `sleep(delay)` advances
    the fake clock by `delay` seconds and yields control once (a real
    `await asyncio.sleep(0)`) before returning — so a driving test's own
    `await asyncio.sleep(0)` polling loop reliably interleaves with the
    scheduler's background task one iteration at a time, and the fake clock
    never runs out of values (unlike a finite iterator)."""
    box = {"now": start}
    sleep_delays: list[float] = []

    def clock() -> datetime:
        return box["now"]

    async def sleep(delay: float) -> None:
        sleep_delays.append(delay)
        box["now"] += timedelta(seconds=delay)
        await asyncio.sleep(0)

    return clock, sleep, sleep_delays


async def _run_until(predicate, *, max_ticks: int = 500) -> None:
    for _ in range(max_ticks):
        await asyncio.sleep(0)
        if predicate():
            return
    raise AssertionError(f"predicate did not become true within {max_ticks} ticks")


@pytest.mark.unit
async def test_scheduler_loop_sleeps_then_runs_then_computes_the_next_days_target():
    calls: list[str] = []
    clock, sleep, sleep_delays = _fake_clock_and_sleep(datetime(2026, 7, 14, 3, 59, 0))

    async def run_once() -> None:
        calls.append("ran")

    scheduler = BackupScheduler(hour=4, minute=0, run_once=run_once, clock=clock, sleep=sleep)

    scheduler.start()
    try:
        await _run_until(lambda: len(calls) >= 2)
    finally:
        await scheduler.stop()

    assert calls == ["ran", "ran"]
    assert sleep_delays[0] == 60.0  # 03:59 -> 04:00 the same day
    assert sleep_delays[1] == 86400.0  # exactly at target -> rolls to the next day


@pytest.mark.unit
async def test_a_run_once_that_raises_does_not_kill_the_loop():
    calls: list[int] = []
    clock, sleep, _ = _fake_clock_and_sleep(datetime(2026, 7, 14, 4, 0, 0))

    async def flaky_run_once() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    scheduler = BackupScheduler(
        hour=4, minute=0, run_once=flaky_run_once, clock=clock, sleep=sleep
    )

    scheduler.start()
    try:
        await _run_until(lambda: len(calls) >= 2)
    finally:
        await scheduler.stop()

    assert len(calls) == 2  # the loop survived the first run raising and ran again


@pytest.mark.unit
async def test_start_is_idempotent_and_stop_cancels_cleanly():
    """Uses the REAL clock/sleep (no fakes) with a target hour picked far
    enough in the future that it cannot possibly fire before this test's
    own assertions run — proving start()/stop() are safe on the actual
    production defaults, not just against the fakes used above."""
    ran = asyncio.Event()

    async def run_once() -> None:
        ran.set()

    far_future_hour = (datetime.now().hour + 2) % 24
    scheduler = BackupScheduler(hour=far_future_hour, minute=0, run_once=run_once)

    scheduler.start()
    first_task = scheduler._task
    scheduler.start()  # calling start() again while already running: no-op
    assert scheduler._task is first_task
    assert scheduler.is_running is True

    await scheduler.stop()

    assert scheduler.is_running is False
    assert not ran.is_set()
