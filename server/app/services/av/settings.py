"""Post-merge user request (2026-08-02): the DB-persisted, genuinely
editable replacement for `av`'s old `settings.scan_schedule` (a hardcoded
string, never enforced by anything — see `AvSettings`'s own docstring in
app/db/models.py for the full "what used to be fake here" context).

Single-row table (id always `_ROW_ID`), same "one row of config" shape
services/notifications/ uses in-memory, just durable — read/write helpers
here, never raw model access from the router/scheduler, so the "row might
not exist yet" (fresh install, never configured) default lives in exactly
one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AvSettings

_ROW_ID = 1

# Matches the old hardcoded "daily_06:00" placeholder's own time-of-day, so
# a fresh install's first-ever read is unsurprising to anyone who saw the
# previous fake value — NOT itself enabled by default (the schedule must
# stay an explicit opt-in, same "safe default" principle
# Settings.backup_enabled/clamav_enabled already follow — a fresh install
# must never start silently running full scans on its own).
_DEFAULT_HOUR = 6
_DEFAULT_MINUTE = 0
# All 7 days (Python's own datetime.weekday() convention: 0=Monday ...
# 6=Sunday) — same "matches the old always-daily behaviour" reasoning the
# hour/minute defaults above already give, see AvSettings.full_scan_days's
# own docstring for why this also has to be the migration's server_default,
# not just this Python-level default.
_ALL_DAYS = (0, 1, 2, 3, 4, 5, 6)


@dataclass(frozen=True)
class AvScheduleSettings:
    full_scan_schedule_enabled: bool
    full_scan_hour: int
    full_scan_minute: int
    full_scan_days: tuple[int, ...]
    updated_at: datetime | None


_DEFAULT_SETTINGS = AvScheduleSettings(
    full_scan_schedule_enabled=False,
    full_scan_hour=_DEFAULT_HOUR,
    full_scan_minute=_DEFAULT_MINUTE,
    full_scan_days=_ALL_DAYS,
    updated_at=None,
)


async def get_av_settings(session: AsyncSession) -> AvScheduleSettings:
    """The current schedule, or the honest default (disabled, never
    configured) when no row exists yet — never raises, mirrors every other
    connector's own "missing config reads as an honest off-state, not an
    error" convention."""
    row = await session.get(AvSettings, _ROW_ID)
    if row is None:
        return _DEFAULT_SETTINGS
    return AvScheduleSettings(
        full_scan_schedule_enabled=row.full_scan_schedule_enabled,
        full_scan_hour=row.full_scan_hour,
        full_scan_minute=row.full_scan_minute,
        full_scan_days=tuple(row.full_scan_days),
        updated_at=row.updated_at,
    )


async def update_av_settings(
    session: AsyncSession,
    *,
    enabled: bool,
    hour: int,
    minute: int,
    days: list[int],
    now: datetime,
) -> AvScheduleSettings:
    """Upserts the single settings row — `hour`/`minute`/`days` validation
    (0-23/0-59/each in 0-6, non-empty) is the caller's job (the router's own
    Pydantic request model), not this function's, same "validate at the
    boundary" split every other write path in this codebase already
    follows."""
    row = await session.get(AvSettings, _ROW_ID)
    if row is None:
        row = AvSettings(
            id=_ROW_ID,
            full_scan_schedule_enabled=enabled,
            full_scan_hour=hour,
            full_scan_minute=minute,
            full_scan_days=list(days),
            updated_at=now,
        )
        session.add(row)
    else:
        row.full_scan_schedule_enabled = enabled
        row.full_scan_hour = hour
        row.full_scan_minute = minute
        row.full_scan_days = list(days)
        row.updated_at = now
    await session.commit()
    return AvScheduleSettings(
        full_scan_schedule_enabled=row.full_scan_schedule_enabled,
        full_scan_hour=row.full_scan_hour,
        full_scan_minute=row.full_scan_minute,
        full_scan_days=tuple(row.full_scan_days),
        updated_at=row.updated_at,
    )
