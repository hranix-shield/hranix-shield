"""Wires `AvScanScheduler` to real Settings/DB — the layer `app_factory.py`'s
lifespan calls, mirrors `services/backup/wiring.py.create_default_scheduler`.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.db.session import async_session_maker
from app.services.av.scheduler import AvScanScheduler
from app.services.av.settings import AvScheduleSettings, get_av_settings
from app.services.mcp.security_connectors.clamav import ClamAvScanJobRegistry, start_full_scan


def create_default_av_scan_scheduler(
    *,
    job_registry: ClamAvScanJobRegistry,
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    settings: Settings | None = None,
) -> AvScanScheduler:
    settings = settings or get_settings()
    maker = session_maker or async_session_maker

    async def _load_settings() -> AvScheduleSettings:
        async with maker() as session:
            return await get_av_settings(session)

    async def _run_full_scan() -> None:
        # Exactly the same `start_full_scan` the "Полная проверка" button
        # already calls (POST /consoles/av/clamav/scan/full) — a real
        # background ScanJob the console's own job-polling already knows
        # how to show, not a second, parallel scan mechanism.
        # `start_full_scan` DOES raise (ClamAvNotConfiguredError/ClamdError,
        # via an eager ping()) when clamd is unconfigured/unreachable at the
        # scheduled moment — deliberately left unhandled here: AvScanScheduler
        # ._tick's own try/except already logs and swallows it (same "one
        # bad tick must never kill the loop" isolation every scheduler in
        # this codebase applies), so a schedule left enabled against a
        # clamd that's temporarily down just quietly skips that day rather
        # than crashing the scheduler.
        await start_full_scan(job_registry, settings=settings, session_maker=maker)

    return AvScanScheduler(load_settings=_load_settings, run_full_scan=_run_full_scan)
