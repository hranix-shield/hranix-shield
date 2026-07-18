"""A-14: diagnostic bundle assembly (§4.7 of the analytical plan).

Ties together three things that already exist rather than inventing new
collection machinery:
  - A-6's `/health/detailed` snapshot (`HealthRegistry.run_all`),
  - A-5's already-masked JSON log file (`Settings.resolved_log_file`) — this
    module reads it verbatim, it does NOT re-mask anything. Masking happens
    once, at write time, in `app.infra.logger_config.SensitiveDataFilter`
    (see that module's docstring); redacting again here would be redundant
    at best and, if the two maskers ever disagreed, confusing at worst,
  - A-4's `events` table (recent event-bus activity).

Nothing in this module is called from a background task, scheduler, or
startup hook — `build_diagnostic_bundle()` only ever runs inside the request
handler for `GET /diagnostics/bundle` (see routers/diagnostics.py), which
itself is only ever reached from the panel's "Отправить отчёт" button after
an explicit on-screen consent step. That is what makes bundle formation
"only by explicit request" per the A-14 task brief — there is deliberately
no code path that forms one without a live HTTP request from an
authenticated user clicking that button.
"""

from __future__ import annotations

import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import __version__
from app.config import Settings, get_settings
from app.db.models import Event
from app.services.event_bus import EventBus
from app.services.health.registry import HealthRegistry

# Defaults chosen to be "enough for a triage read" without the response
# becoming unwieldy; both are also the Query(...) defaults on the router, so
# a caller who wants more/less just overrides them per-request rather than
# this module needing a settings knob.
DEFAULT_LOG_LINES = 200
DEFAULT_EVENT_ROWS = 50
# Hard ceiling regardless of what a client asks for — the rotating file
# handler (see logger_config.configure_logging) caps a single log file at
# 10 MB, so reading the whole thing is already bounded, but an unbounded
# `limit` query param is still an easy way to make one request expensive.
MAX_LOG_LINES = 2000
MAX_EVENT_ROWS = 500


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _tail_lines(path: Path, limit: int) -> list[str]:
    """Returns up to the last `limit` non-blank lines of a text file.

    Reads the whole file into memory rather than seeking from the end — see
    `MAX_LOG_LINES` above for why that is fine at this project's scale.
    A missing file (console-only logging, or nothing logged yet) returns an
    empty list instead of raising; this is a "best-effort read", not
    something that should ever turn bundle formation into a 500.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            lines = [line.rstrip("\n") for line in handle if line.strip()]
    except OSError:
        return []
    return lines[-limit:]


def _parse_log_line(raw: str) -> dict[str, Any]:
    """Parses one line written by `app.infra.logger_config.JsonFormatter`
    back into a structured record (time/level/logger/message/...) for the
    panel's Logs tab to render as a table, not a raw text dump.

    A line that is not valid JSON — should not happen in normal operation,
    but a torn last line during file rotation is possible — degrades to a
    record whose `message` is the raw text rather than being dropped: a
    diagnostic tool that silently discards the one line an operator most
    needs (the last one, mid-crash) would defeat its own purpose.
    """
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        parsed = None
    if isinstance(parsed, dict):
        return parsed
    return {"timestamp": None, "level": None, "logger": None, "message": raw}


def read_recent_logs(settings: Settings, *, limit: int = DEFAULT_LOG_LINES) -> list[dict[str, Any]]:
    """Last `limit` lines of `Settings.resolved_log_file`, parsed.

    Reads exactly what A-5's `SensitiveDataFilter` already wrote to disk —
    no masking happens in this function, see module docstring. Returns the
    empty list (not an error) when file logging is disabled
    (`resolved_log_file` is `None`, see `Settings.resolved_log_file`'s own
    docstring for that convention).
    """
    limit = max(1, min(limit, MAX_LOG_LINES))
    log_file = settings.resolved_log_file
    if not log_file:
        return []
    return [_parse_log_line(line) for line in _tail_lines(Path(log_file), limit)]


async def read_recent_events(
    session: AsyncSession, *, limit: int = DEFAULT_EVENT_ROWS
) -> list[dict[str, Any]]:
    """Last `limit` rows of the `events` table (A-4), oldest first — matches
    the chronological order a reader expects from a log-like section of a
    report, same convention `security_console.overview()`'s event_log
    already established (query DESC for "most recent N", then present
    oldest-first)."""
    limit = max(1, min(limit, MAX_EVENT_ROWS))
    events = (
        await session.scalars(
            # `Event.id.desc()` is a tiebreaker, not the primary sort: SQLite's
            # `CURRENT_TIMESTAMP` has 1-second resolution, so several events
            # published within the same second (routine when the event bus
            # fans one action out to multiple subscribers) would otherwise
            # sort in an unspecified order relative to each other.
            select(Event).order_by(Event.created_at.desc(), Event.id.desc()).limit(limit)
        )
    ).all()
    return [
        {
            "topic": event.topic,
            "payload": event.payload,
            "created_at": event.created_at.isoformat() if event.created_at else None,
        }
        for event in reversed(events)
    ]


def environment_info(settings: Settings) -> dict[str, Any]:
    """Version/environment facts a support triage needs to make sense of a
    bundle in isolation, without also needing the git history it came from.
    Only ever facts about THIS process/product — never a credential or a
    path outside the repo, so (unlike logs/events) there is nothing here
    that needs masking in the first place."""
    return {
        "product": "Hranix Shield",
        "app_version": __version__,
        "phase": "0",
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "ai_enabled": settings.ai_enabled,
        "backup_enabled": settings.backup_enabled,
    }


async def build_diagnostic_bundle(
    *,
    session: AsyncSession,
    health_registry: HealthRegistry,
    event_bus: EventBus,
    settings: Settings | None = None,
    log_lines: int = DEFAULT_LOG_LINES,
    event_rows: int = DEFAULT_EVENT_ROWS,
) -> dict[str, Any]:
    """Assembles the full diagnostic bundle: a health snapshot (A-6), recent
    already-masked log lines (A-5), a recent events summary (A-4), and
    version/environment info — everything §4.7 of the analytical plan asks
    for in one JSON document, with nothing collected that needs a second
    round of redaction (see module docstring).

    See router docstring (`routers/diagnostics.py`) for why this being
    reachable ONLY via that endpoint is what satisfies "forms only on
    explicit request" — this function itself has no opinion on who is
    allowed to call it or when; that gate lives entirely at the HTTP layer.
    """
    settings = settings or get_settings()
    health = await health_registry.run_all(event_bus=event_bus)
    return {
        "generated_at": _now_iso(),
        "environment": environment_info(settings),
        "health": health,
        "logs": read_recent_logs(settings, limit=log_lines),
        "events": await read_recent_events(session, limit=event_rows),
    }
