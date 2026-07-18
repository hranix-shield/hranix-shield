"""A-13: notification channels 1-5 (§5.4 of the analytical plan).

Public surface re-exported here for callers (router, app_factory, tests):
  - channels: the 6-channel enum + which ones Phase 0 actually delivers on.
  - registry: the open, extensible topic x channel matrix.
  - trusted_contacts: in-memory recipient list for email/escalation.
  - quiet_hours: the suppression-window decision.
  - smtp_client: the real stdlib SMTP sender behind channel 5.
  - service: the event-bus subscriber tying all of the above together.
  - escalation: the channel-6 no-op + periodic overdue-critical sweep.
"""

from __future__ import annotations

from app.config import Settings, get_settings
from app.services.event_bus import EventBus, Topic
from app.services.notifications.channels import (
    CHANNEL_DELIVERY_IMPLEMENTED,
    CHANNEL_IDS,
    Channel,
)
from app.services.notifications.escalation import (
    EscalationScheduler,
    escalate_to_channel_6,
    run_escalation_sweep,
)
from app.services.notifications.quiet_hours import is_quiet_hours_now
from app.services.notifications.registry import (
    NotificationRegistry,
    get_notification_registry,
    register_default_topics,
)
from app.services.notifications.service import NotificationService
from app.services.notifications.smtp_client import is_smtp_configured, send_email
from app.services.notifications.trusted_contacts import (
    TrustedContactRegistry,
    get_trusted_contact_registry,
)

__all__ = [
    "CHANNEL_DELIVERY_IMPLEMENTED",
    "CHANNEL_IDS",
    "Channel",
    "EscalationScheduler",
    "NotificationRegistry",
    "NotificationService",
    "TrustedContactRegistry",
    "create_default_escalation_scheduler",
    "escalate_to_channel_6",
    "get_notification_registry",
    "get_trusted_contact_registry",
    "is_quiet_hours_now",
    "is_smtp_configured",
    "register_default_notification_subscribers",
    "register_default_topics",
    "run_escalation_sweep",
    "send_email",
]


def register_default_notification_subscribers(bus: EventBus, service: NotificationService) -> None:
    """Wires `service.handle_event` onto every topic in the `Topic` enum.

    Called once per app instance from `app_factory.create_app()`, mirroring
    `event_bus.register_default_subscribers`/`health.checks.register_default_checks`.
    A future event-bus topic is picked up automatically the moment it is
    added to `Topic` (event_bus.py) — no edit needed here, the same
    "the enum is the extension point" reasoning `register_default_subscribers`
    already relies on for the events-table logger. A topic published without
    ever being added to `Topic` (e.g. a third-party MCP plugin's own topic
    string) needs its own explicit `bus.subscribe(its_topic, service.handle_event)`
    call, exactly as it would need its own `registry.register(...)` call to
    have any channels enabled at all — same shape as a future health check
    calling `HealthRegistry.register(...)` itself.
    """
    for topic in Topic:
        bus.subscribe(topic, service.handle_event)


def create_default_escalation_scheduler(
    *,
    trusted_contacts: TrustedContactRegistry,
    settings: Settings | None = None,
) -> EscalationScheduler:
    """An `EscalationScheduler` wired to real Settings — used by
    app_factory's lifespan, mirrors services/backup/wiring.py's
    create_default_scheduler."""
    settings = settings or get_settings()

    async def _run_once() -> None:
        await run_escalation_sweep(
            escalation_minutes=settings.notifications_escalation_minutes,
            trusted_contacts=trusted_contacts.emails(),
        )

    return EscalationScheduler(
        interval_seconds=settings.notifications_escalation_check_interval_seconds,
        run_once=_run_once,
    )
