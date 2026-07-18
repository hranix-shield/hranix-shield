from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any

from fastapi import Request

from app.db.models import Event
from app.db.session import async_session_maker

logger = logging.getLogger(__name__)

EventHandler = Callable[[str, dict[str, Any]], Awaitable[None]]


class Topic(StrEnum):
    """Event bus topics planned for Phase 0 (see A-4 spec). New topics can be
    published without being added here first — this only names the minimum
    set this phase's tasks are expected to use."""

    HEALTH_CHANGED = "health.changed"
    BACKUP_STATUS = "backup.status"
    SECURITY_ALERT = "security.alert"


class EventBus:
    """In-process async pub/sub.

    A plain dict-of-lists registry keyed by topic: `subscribe` appends a
    handler, `publish` awaits every handler registered for that topic, in
    subscription order. No queueing/buffering — a publish call fans out
    synchronously to whatever is subscribed at that moment.

    A failing handler cannot break `publish()`, the caller, or its sibling
    handlers on the same topic: each handler call is individually isolated
    (see `publish` below). This is load-bearing, not incidental — publishers
    like /auth/login call `publish()` inline in the request path, and future
    subscribers (A-6 health, A-13 notification channels, ...) must be free
    to misbehave without ever being able to turn a routine event (e.g. a
    failed-login attempt) into a 500.
    """

    def __init__(self) -> None:
        self._subscribers: dict[str, list[EventHandler]] = defaultdict(list)

    def subscribe(self, topic: str, handler: EventHandler) -> None:
        self._subscribers[topic].append(handler)

    async def publish(self, topic: str, payload: dict[str, Any]) -> None:
        for handler in list(self._subscribers.get(topic, ())):
            try:
                await handler(topic, payload)
            except Exception:
                handler_name = getattr(handler, "__qualname__", repr(handler))
                logger.error(
                    "event_bus: subscriber %r failed for topic=%r",
                    handler_name,
                    topic,
                    exc_info=True,
                )


async def log_event_to_events_table(topic: str, payload: dict[str, Any]) -> None:
    """Default subscriber: persists any event it is subscribed to into the
    `events` table (model in app/db/models.py, table created by A-2's initial
    migration). Reads `async_session_maker` from this module's namespace at
    call time, so tests can monkeypatch `app.services.event_bus.async_session_maker`
    to point at an isolated tmp DB — same pattern already used for
    `app.services.auth.async_session_maker` in test_auth_startup.py.
    """
    async with async_session_maker() as session:
        session.add(Event(topic=str(topic), payload=dict(payload)))
        await session.commit()


def register_default_subscribers(bus: EventBus) -> None:
    """Wire the events-table logger onto every known topic.

    Called once per app instance from `app_factory.create_app()`, so each
    `create_app()` call (prod entrypoint, or a fresh instance per test) gets
    its own bus with the logger registered exactly once — no shared global
    state to leak subscriptions across tests.
    """
    for topic in Topic:
        bus.subscribe(topic, log_event_to_events_table)


def get_event_bus(request: Request) -> EventBus:
    """FastAPI dependency: the bus instance attached to this app (see
    app_factory.create_app -> app.state.event_bus)."""
    return request.app.state.event_bus
