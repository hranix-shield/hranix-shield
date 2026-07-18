"""NotificationService: the event-bus subscriber that turns a published
event into a persisted `Notification` row and, where Phase 0 actually
wires real delivery (see channels.CHANNEL_DELIVERY_IMPLEMENTED), a real
channel action (currently: email).

Reads `async_session_maker` from this module's own namespace at call time
(imported here, referenced by bare name below) — not through
`app.db.session` at call time — so a test can monkeypatch
`app.services.notifications.service.async_session_maker` to point at an
isolated tmp DB, the same pattern already used by event_bus.py,
health/checks.py, and backup/service.py (see tests/conftest.py).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.config import Settings, get_settings
from app.db.models import Notification
from app.db.session import async_session_maker
from app.services.notifications.channels import CHANNEL_DELIVERY_IMPLEMENTED, Channel
from app.services.notifications.quiet_hours import is_quiet_hours_now
from app.services.notifications.registry import NotificationRegistry
from app.services.notifications.smtp_client import is_smtp_configured, send_email
from app.services.notifications.trusted_contacts import TrustedContactRegistry

logger = logging.getLogger(__name__)


def _now() -> datetime:
    """Naive UTC now, matching the non-timezone-aware DateTime columns in
    db/models.py — same helper/reasoning as services.auth._now_utc_naive
    and services.backup.service._now. NOT the same clock quiet_hours.py
    uses for the suppression decision itself (that one is deliberately
    local wall-clock time, see quiet_hours.py's module docstring) — this
    one only stamps when the Notification row was created."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class NotificationService:
    """One instance per `create_app()` call (attached nowhere on app.state
    directly — it is wired onto the event bus via
    `register_default_notification_subscribers` below, and the router
    reaches it only through the registries it wraps), same non-singleton
    reasoning as every other per-instance service in this codebase.
    """

    def __init__(
        self,
        *,
        registry: NotificationRegistry,
        trusted_contacts: TrustedContactRegistry,
        settings: Settings | None = None,
        clock: Callable[[], datetime] | None = None,
        quiet_hours_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._trusted_contacts = trusted_contacts
        self._settings_override = settings
        self._clock = clock or _now
        # Separate from `_clock` on purpose (see handle_event below): this
        # one feeds the quiet-hours time-of-day decision, which is local
        # wall-clock time by definition (quiet_hours.py's module docstring),
        # NOT the naive-UTC convention `_clock`/`_now` use to stamp
        # `Notification.created_at`. Injectable so tests can pick a
        # deterministic time-of-day without depending on when the suite
        # happens to run.
        self._quiet_hours_clock = quiet_hours_clock or datetime.now

    def _settings(self) -> Settings:
        return self._settings_override or get_settings()

    async def handle_event(self, topic: str, payload: dict[str, Any]) -> None:
        """The `EventHandler` signature `EventBus.publish` expects — see
        event_bus.py. Isolated the same way every other subscriber is: a
        failure here is caught and logged by `EventBus.publish` itself, it
        can never turn a publisher's request (e.g. /auth/login's brute-force
        lock) into a 500.
        """
        settings = self._settings()
        critical = self._registry.is_critical(topic)
        channels = self._registry.channels_for(topic)
        now = self._clock()

        # Quiet hours use the reader's local wall-clock time-of-day (see
        # quiet_hours.py) — deliberately NOT `now` (naive UTC, only used
        # below to stamp the row) as separate concerns: "when did this
        # happen" vs "is it currently nighttime for the user".
        suppressed = (not critical) and is_quiet_hours_now(
            settings, now=self._quiet_hours_clock()
        )

        notification = Notification(
            topic=str(topic),
            payload=dict(payload),
            critical=critical,
            channels=[] if suppressed else sorted(channel.value for channel in channels),
            suppressed_quiet_hours=suppressed,
            created_at=now,
        )
        async with async_session_maker() as session:
            session.add(notification)
            await session.commit()
            await session.refresh(notification)

        if suppressed:
            logger.info(
                "notifications: topic=%r suppressed by quiet hours (non-critical, now=%s)",
                notification.topic,
                now.isoformat(),
            )
            return

        for channel in sorted(channels, key=lambda c: c.value):
            if channel is Channel.EMAIL:
                await self._deliver_email(notification, settings)
            elif channel is Channel.PANEL_ICON:
                pass  # nothing to do: the persisted row IS this channel's delivery
            elif not CHANNEL_DELIVERY_IMPLEMENTED.get(channel, False):
                logger.info(
                    "notifications: channel %r is enabled for topic=%r (notification_id=%s) "
                    "but has no real delivery wired in Phase 0 — matrix intent recorded, "
                    "nothing was actually sent (see channels.CHANNEL_DELIVERY_IMPLEMENTED)",
                    channel.value,
                    notification.topic,
                    notification.id,
                )

    async def _deliver_email(self, notification: Notification, settings: Settings) -> None:
        if not is_smtp_configured(settings):
            logger.info(
                "notifications: email channel enabled for topic=%r (notification_id=%s) but "
                "SMTP is not configured (SMTP_HOST/SMTP_FROM unset) — skipping; this is the "
                "expected/normal state unless the operator configured SMTP_*",
                notification.topic,
                notification.id,
            )
            return

        recipients = self._trusted_contacts.emails()
        if not recipients:
            logger.info(
                "notifications: email channel enabled for topic=%r (notification_id=%s) but "
                "no trusted contacts are configured — nothing to send to",
                notification.topic,
                notification.id,
            )
            return

        subject = f"Hranix Shield: {notification.topic}"
        body = (
            f"Topic: {notification.topic}\n"
            f"Critical: {notification.critical}\n"
            f"Payload: {notification.payload}\n"
            f"Created at (UTC): {notification.created_at}\n"
        )
        try:
            await send_email(
                host=settings.smtp_host,
                port=settings.smtp_port,
                username=settings.smtp_username,
                password=settings.smtp_password,
                from_addr=settings.smtp_from,
                to_addrs=recipients,
                subject=subject,
                body=body,
            )
        except Exception:
            logger.error(
                "notifications: sending email for topic=%r (notification_id=%s) to %s failed",
                notification.topic,
                notification.id,
                recipients,
                exc_info=True,
            )
            return

        async with async_session_maker() as session:
            db_notification = await session.get(Notification, notification.id)
            if db_notification is not None:
                db_notification.email_sent = True
                await session.commit()
