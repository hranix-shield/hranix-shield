"""NetworkProfileScheduler — pure logic + an injected fake sleep, no real
subprocess/DB involved. Mirrors
tests/unit/test_metrics_sample_scheduler.py's fake-sleep idiom exactly
(NetworkProfileScheduler is deliberately a near-identical class, see
network_profile.py's own docstring for why it isn't literally reused
instead of mirrored — same project convention every recurring background
loop in this codebase already follows).
"""

import asyncio

import pytest

from app.services.mcp.security_connectors.network_profile import NetworkProfileScheduler


async def _noop() -> None:
    return None


def _fake_sleep(delays: list[float]):
    async def sleep(delay: float) -> None:
        delays.append(delay)
        await asyncio.sleep(0)

    return sleep


async def _run_until(predicate, *, max_ticks: int = 500) -> None:
    for _ in range(max_ticks):
        await asyncio.sleep(0)
        if predicate():
            return
    raise AssertionError(f"predicate did not become true within {max_ticks} ticks")


@pytest.mark.unit
async def test_loop_always_sleeps_before_the_first_run():
    calls: list[str] = []
    delays: list[float] = []

    async def run_once() -> None:
        calls.append("ran")

    scheduler = NetworkProfileScheduler(
        interval_seconds=30, run_once=run_once, sleep=_fake_sleep(delays)
    )

    scheduler.start()
    try:
        await _run_until(lambda: len(calls) >= 1)
    finally:
        await scheduler.stop()

    assert delays[0] == 30
    assert calls == ["ran"]


@pytest.mark.unit
async def test_loop_reruns_on_the_same_fixed_interval():
    calls: list[str] = []
    delays: list[float] = []

    async def run_once() -> None:
        calls.append("ran")

    scheduler = NetworkProfileScheduler(
        interval_seconds=10, run_once=run_once, sleep=_fake_sleep(delays)
    )

    scheduler.start()
    try:
        await _run_until(lambda: len(calls) >= 3)
    finally:
        await scheduler.stop()

    assert delays[:3] == [10, 10, 10]


@pytest.mark.unit
async def test_a_run_once_that_raises_does_not_kill_the_loop():
    calls: list[int] = []
    delays: list[float] = []

    async def flaky_run_once() -> None:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("boom")

    scheduler = NetworkProfileScheduler(
        interval_seconds=5, run_once=flaky_run_once, sleep=_fake_sleep(delays)
    )

    scheduler.start()
    try:
        await _run_until(lambda: len(calls) >= 2)
    finally:
        await scheduler.stop()

    assert len(calls) == 2  # the loop survived the first run raising and ran again


@pytest.mark.unit
async def test_start_is_idempotent_and_stop_cancels_cleanly():
    ran = asyncio.Event()

    async def run_once() -> None:
        ran.set()

    scheduler = NetworkProfileScheduler(interval_seconds=999, run_once=run_once)

    scheduler.start()
    first_task = scheduler._task
    scheduler.start()  # calling start() again while already running: no-op
    assert scheduler._task is first_task
    assert scheduler.is_running is True

    await scheduler.stop()

    assert scheduler.is_running is False
    assert not ran.is_set()


@pytest.mark.unit
async def test_stop_before_start_is_a_safe_no_op():
    scheduler = NetworkProfileScheduler(interval_seconds=30, run_once=_noop)

    await scheduler.stop()  # must not raise

    assert scheduler.is_running is False
