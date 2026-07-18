"""A-14: diagnostics & system health (§4.7/§5.5 of the analytical plan).

Two read paths, deliberately kept separate:
  - `GET /diagnostics/logs` backs the panel's "Логи" tab — a normal
    "observe this module" read (CLAUDE.md's per-module observation-API
    invariant, same class of endpoint as `GET /health/detailed`): opening
    that tab collects nothing new, it only displays what A-5's
    `SensitiveDataFilter` already wrote to disk, already masked.
  - `GET /diagnostics/bundle` forms the full downloadable report (health +
    logs + events + version, see services/diagnostics.py). This is the one
    the A-14 brief means by "формируется только по явному запросу": nothing
    in this codebase calls `build_diagnostic_bundle()` from a background
    task, scheduler, or startup hook. The panel only reaches this endpoint
    from the "Здоровье системы" screen's "Отправить отчёт" button, and only
    after the user has ticked an explicit on-screen consent checkbox (see
    static/assets/app.js's `openReportConsent`/`handleSendReport`) — the
    consent gate lives entirely in the client's button-click flow, same as
    A-12's `window.confirm()` before a restore. A GET is used here (not
    POST) because forming the bundle has no side effect on server state of
    its own (same reasoning as `GET /health/detailed`, which this endpoint
    calls through `HealthRegistry.run_all`); it is the explicit button
    click that is the consent gate, not the HTTP verb.

Both require `Depends(get_current_user)`, no stronger role than every other
Phase 0 panel endpoint (`viewer` is enough) — a diagnostic bundle can carry
operationally sensitive details even though it is PII/secret-free (see
`build_diagnostic_bundle`'s docstring), so it stays behind auth like
everything else in this panel, not additionally gated behind `admin`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import User
from app.db.session import get_session
from app.dependencies import get_current_user
from app.services.diagnostics import (
    DEFAULT_EVENT_ROWS,
    DEFAULT_LOG_LINES,
    MAX_EVENT_ROWS,
    MAX_LOG_LINES,
    build_diagnostic_bundle,
    read_recent_logs,
)
from app.services.event_bus import EventBus, get_event_bus
from app.services.health import HealthRegistry, get_health_registry

router = APIRouter(prefix="/diagnostics", tags=["diagnostics"])


@router.get("/logs")
async def logs(
    limit: int = Query(DEFAULT_LOG_LINES, ge=1, le=MAX_LOG_LINES),
    level: str | None = Query(None),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Last `limit` masked log lines, optionally filtered to one level
    (`INFO`/`WARNING`/`ERROR`/...).

    `level` filters WITHIN that same `limit`-line window (read the last
    `limit` lines of the file first, then drop non-matching ones) rather
    than searching the whole file for `limit` matches — cheap and honest
    about what it does: "last 200 lines, optionally narrowed to one level"
    can legitimately return fewer than 200 rows for a level. A caller that
    wants a deeper look raises `limit` itself instead of this endpoint
    silently scanning an unbounded amount of the file to fill a quota.
    """
    settings = get_settings()
    entries = read_recent_logs(settings, limit=limit)
    if level:
        wanted = level.upper()
        entries = [entry for entry in entries if (entry.get("level") or "").upper() == wanted]
    return {"entries": entries}


@router.get("/bundle")
async def bundle(
    response: Response,
    log_lines: int = Query(DEFAULT_LOG_LINES, ge=1, le=MAX_LOG_LINES),
    event_rows: int = Query(DEFAULT_EVENT_ROWS, ge=1, le=MAX_EVENT_ROWS),
    session: AsyncSession = Depends(get_session),
    health_registry: HealthRegistry = Depends(get_health_registry),
    event_bus: EventBus = Depends(get_event_bus),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Forms and returns the full diagnostic bundle — see module docstring
    for why reaching this endpoint at all is the "explicit request" the
    A-14 brief requires.

    Sets `Content-Disposition: attachment` (§4.7's own wording: "по кнопке
    ... архив логов ... Отправка ... с разрешения пользователя") so the
    response is a well-formed downloadable attachment even for a client
    that reads this header directly; the panel itself still drives the
    actual save-as via a client-side Blob (see app.js) since `fetch()` with
    an `Authorization` header doesn't trigger a browser download from a
    response header alone — reasoning spelled out in the A-14 task report.
    """
    payload = await build_diagnostic_bundle(
        session=session,
        health_registry=health_registry,
        event_bus=event_bus,
        log_lines=log_lines,
        event_rows=event_rows,
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    response.headers["Content-Disposition"] = (
        f'attachment; filename="hranix-shield-diagnostic-bundle-{stamp}.json"'
    )
    return payload
