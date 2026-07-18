"""Quiet hours (§5.4 of the analytical plan): a configurable daily window
(default 22:00-08:00) during which non-critical notifications are
suppressed — critical ones (see registry.py's criticality call) always go
through regardless.

Timestamps compared here are naive local wall-clock time-of-day, not the
naive-UTC convention used for stored DateTime columns elsewhere in this
codebase (services.auth._now_utc_naive, services.backup.scheduler) — quiet
hours are inherently about the user's own night, and Settings has no place
yet to configure the user's timezone (same accepted limitation already
flagged in services/backup/scheduler.py's module docstring). Phase 0 reads
the process's local time via `datetime.now()` (no tzinfo attached) for this
one purpose only; every stored Notification timestamp still uses the
existing naive-UTC convention (see service.py's `_now`).
"""

from __future__ import annotations

from datetime import datetime, time

from app.config import Settings


def parse_hhmm(value: str) -> time:
    hour_str, _, minute_str = value.partition(":")
    return time(hour=int(hour_str), minute=int(minute_str))


def is_within_window(now: time, start: time, end: time) -> bool:
    """Whether `now` falls in the [start, end) window. `start == end` is
    treated as an empty window (never quiet) rather than "all day" — an
    accidental identical start/end in configuration should not silently
    suppress everything non-critical forever."""
    if start == end:
        return False
    if start < end:
        return start <= now < end
    return now >= start or now < end  # wraps midnight, e.g. 22:00 -> 08:00


def is_quiet_hours_now(settings: Settings, *, now: datetime | None = None) -> bool:
    if not settings.quiet_hours_enabled:
        return False
    reference = now if now is not None else datetime.now()
    start = parse_hhmm(settings.quiet_hours_start)
    end = parse_hhmm(settings.quiet_hours_end)
    return is_within_window(reference.time(), start, end)
