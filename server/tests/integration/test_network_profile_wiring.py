"""A-38: `create_default_network_profile_scheduler` — the layer that reads
real `Settings` and assembles the periodic monitor, same shape
`services/metrics/wiring.py`'s `create_default_metrics_scheduler` already
has its own sibling wiring tests for (test_metrics_wiring.py, mirrored
here) — see that file's own docstring for the pattern this repeats:
`_run_once` driven directly (no real wall-clock wait), `previous_key`
threaded across ticks via the scheduler's own closure state.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.mcp.security_connectors.network_profile as network_profile_module
from app.config import Settings
from app.db.models import NetworkProfile
from app.services.event_bus import EventBus, Topic
from app.services.mcp.security_connectors.network_profile import (
    create_default_network_profile_scheduler,
)

_MACOS_ONE_PORT = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb\n"


def _fake_run(handlers: dict[tuple, tuple[int, str, str]]):
    async def _run(*args: str, timeout: float = 5.0):
        return handlers[args]

    return _run


@pytest.mark.integration
def test_create_default_scheduler_uses_the_configured_interval():
    settings = Settings(_env_file=None, network_profile_poll_interval_seconds=17)

    scheduler = create_default_network_profile_scheduler(settings=settings)

    assert scheduler is not None
    assert scheduler._interval_seconds == 17


@pytest.mark.integration
def test_create_default_scheduler_defaults_to_30_seconds():
    settings = Settings(_env_file=None)

    scheduler = create_default_network_profile_scheduler(settings=settings)

    assert scheduler._interval_seconds == 30


@pytest.mark.integration
async def test_run_once_persists_a_real_sighting_and_threads_previous_key(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """`create_default_network_profile_scheduler`'s own `_run_once` closure
    calls `run_network_profile_sweep()` with no explicit session_maker —
    redirected the same way test_metrics_wiring.py's own sibling test
    redirects `sampler_module.async_session_maker`, so this never touches
    the real data/assistant.db. Also proves the closure's own `previous_key`
    state survives from one tick to the next (the second tick's detected
    key becomes the argument the sweep sees, exercised indirectly here via
    the "no duplicate SECURITY_ALERT on an unchanged network" behaviour)."""
    monkeypatch.setattr(network_profile_module, "async_session_maker", migrated_session_maker)
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_ONE_PORT, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: CafeWifi", ""),
            }
        ),
    )
    bus = EventBus()
    received: list[dict] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append(payload)

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    scheduler = create_default_network_profile_scheduler(
        event_bus=bus, settings=Settings(_env_file=None)
    )
    assert scheduler is not None

    await scheduler._run_once()
    # A second tick on the SAME (still public, still unchanged) network —
    # must NOT publish a second nudge, proving `previous_key` really is
    # threaded forward from the first tick, not reset to None each time.
    await scheduler._run_once()

    assert len(received) == 1
    assert received[0]["network_key"] == "wifi:CafeWifi"

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert len(rows) == 1
    assert rows[0].network_key == "wifi:CafeWifi"
