"""Escalation (§5.4 of the analytical plan): a critical notification left
unacknowledged for `escalation_minutes` should escalate to channel 6
(SMS/call). Channel 6 does not exist in Phase 0 — it needs a dedicated
phone-terminal (analytical plan §9.1 backlog) — so "escalate" here means:
find the overdue notifications, log a clear, unmistakable no-op for each
(never a silent swallow), and mark them `escalated_at` so the sweep does
not repeat the same no-op forever.

`run_escalation_sweep` is the pure, directly-testable piece (inject `now`,
no waiting); `EscalationScheduler` is the periodic background loop that
calls it in production — same "asyncio background task with injectable
clock/sleep" idiom as services/backup/scheduler.py's BackupScheduler, but
on a fixed interval rather than a once-a-day target time (there is no
"time of day" concept for this sweep, just "check again in N seconds").
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import Notification
from app.db.session import async_session_maker

logger = logging.getLogger(__name__)

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def escalate_to_channel_6(notification: Notification, contacts: list[str]) -> None:
    """The explicit no-op: channel 6 (SMS/call) is not implemented in Phase
    0 (needs the phone-terminal backlog item, analytical plan §9.1) — this
    logs loudly instead of pretending an SMS/call went out, per the A-13
    spec's explicit "не молча проглатывается" requirement."""
    logger.warning(
        "notifications: ESCALATION for critical notification_id=%s topic=%r — channel "
        "'sms_call' is NOT IMPLEMENTED in Phase 0 (requires a phone-terminal, see backlog "
        "§9.1 of the analytical plan). No SMS/call was actually sent. Would-be recipients: %s",
        notification.id,
        notification.topic,
        contacts,
    )


async def run_escalation_sweep(
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    *,
    escalation_minutes: int,
    trusted_contacts: list[str],
    now: datetime | None = None,
) -> list[int]:
    """Escalates every critical, unacknowledged, not-yet-escalated
    `Notification` older than `escalation_minutes`. Returns the ids it
    escalated (empty list = nothing overdue right now).

    Deliberately does NOT consider `suppressed_quiet_hours` rows: a
    critical topic is never suppressed by quiet hours to begin with (see
    registry.register_default_topics), so no critical row should ever have
    that flag set — but the filter below only matches `critical=True`
    rows regardless, so this stays correct even if a future topic's
    criticality gets reconfigured oddly.
    """
    maker = session_maker or async_session_maker
    reference = now if now is not None else _default_clock()
    threshold = reference - timedelta(minutes=escalation_minutes)

    escalated_ids: list[int] = []
    async with maker() as session:
        overdue = (
            await session.scalars(
                select(Notification).where(
                    Notification.critical.is_(True),
                    Notification.acknowledged_at.is_(None),
                    Notification.escalated_at.is_(None),
                    Notification.created_at <= threshold,
                )
            )
        ).all()

        for notification in overdue:
            await escalate_to_channel_6(notification, trusted_contacts)
            notification.escalated_at = reference
            escalated_ids.append(notification.id)

        if overdue:
            await session.commit()

    return escalated_ids


class EscalationScheduler:
    """Runs `run_once` every `interval_seconds`, forever, until `stop()`.

    Always sleeps BEFORE the first run (never fires immediately at
    `start()`) — same reasoning as it being safe for
    `test_auth_startup.py`-style tests that spin up the real app lifespan
    via `with TestClient(app): pass` and tear it down almost immediately:
    the loop is cancelled mid-sleep and never reaches a DB query, so it
    never touches the real `data/assistant.db` in a test that hasn't
    monkeypatched this module's `async_session_maker`.

    `clock`/`sleep` are injectable so tests can drive the loop without
    waiting real wall-clock time, mirroring BackupScheduler.
    """

    def __init__(
        self,
        *,
        interval_seconds: float,
        run_once: Callable[[], Awaitable[None]],
        sleep: Sleeper | None = None,
    ) -> None:
        self._interval_seconds = interval_seconds
        self._run_once = run_once
        self._sleep = sleep or asyncio.sleep
        self._task: asyncio.Task | None = None

    async def _loop(self) -> None:
        while True:
            await self._sleep(self._interval_seconds)
            try:
                await self._run_once()
            except Exception:
                # Isolated the same way BackupScheduler isolates a failing
                # scheduled run: one bad sweep must never kill the loop, or
                # every subsequent escalation check silently stops happening.
                logger.error("notifications: escalation sweep raised", exc_info=True)

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
