from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from fastapi import Request

from app.services.event_bus import Topic
from app.services.notifications.channels import Channel


@dataclass
class TopicChannels:
    channels: set[Channel] = field(default_factory=set)
    critical: bool = False


class NotificationRegistry:
    """The "функция x канал" matrix (§5.4 of the analytical plan): which
    channels are enabled for a given event-bus topic, and whether that
    topic counts as critical for quiet-hours purposes (see
    services/notifications/quiet_hours.py).

    Open registry, same shape as `HealthRegistry`/`SecurityConsoleRegistry`:
    a topic registers itself once via `register(topic, channels=..., critical=...)`
    — see `register_default_topics` below for Phase 0's 3 known topics.
    A future phase/plugin introducing a new event-bus topic registers its
    own matrix row the same way, elsewhere; this file/class does not need
    an edit for that (only `register_default_topics` — itself just a
    convenience wiring function, not the registry — would ever need one, and
    only for a topic this repo ships itself rather than a third-party MCP
    plugin, mirroring `health.checks.register_default_checks`).

    Mutable at runtime (`set_channels`): the "Настройки -> Уведомления и
    каналы" screen edits the checkbox matrix through this registry. One
    instance per `create_app()` call, same non-singleton reasoning as every
    other *Registry in this codebase — no state leaks between app instances
    or tests.
    """

    def __init__(self) -> None:
        self._topics: dict[str, TopicChannels] = {}

    def register(self, topic: str, *, channels: Iterable[Channel], critical: bool) -> None:
        self._topics[str(topic)] = TopicChannels(channels=set(channels), critical=critical)

    def known_topics(self) -> list[str]:
        return list(self._topics.keys())

    def channels_for(self, topic: str) -> set[Channel]:
        entry = self._topics.get(str(topic))
        return set(entry.channels) if entry else set()

    def is_critical(self, topic: str) -> bool:
        entry = self._topics.get(str(topic))
        return entry.critical if entry else False

    def set_channels(self, topic: str, channels: Iterable[Channel]) -> None:
        """Updates just the channel set for `topic`, preserving its current
        `critical` flag (or defaulting to False for a topic nobody has
        registered yet) — the matrix UI only ever edits channels, not
        criticality (see task report: severity is a security-policy call,
        kept a developer decision, not user-editable in Phase 0)."""
        existing = self._topics.get(str(topic))
        critical = existing.critical if existing else False
        self._topics[str(topic)] = TopicChannels(channels=set(channels), critical=critical)

    def snapshot(self) -> dict[str, dict[str, Any]]:
        return {
            topic: {
                "channels": sorted(channel.value for channel in entry.channels),
                "critical": entry.critical,
            }
            for topic, entry in self._topics.items()
        }


def register_default_topics(registry: NotificationRegistry) -> None:
    """Wires Phase 0's 3 real event-bus topics onto the channel matrix.

    Called once per app instance from `app_factory.create_app()`, mirroring
    `event_bus.register_default_subscribers` / `health.checks.register_default_checks`.

    Criticality call (see A-13 task report):
      - `SECURITY_ALERT` is always critical — a brute-force lock or future
        intrusion alert is exactly the kind of event quiet hours must not
        swallow.
      - `HEALTH_CHANGED`/`BACKUP_STATUS` are not critical — a subsystem
        wobbling or a backup finishing/failing overnight is worth a panel
        badge and an email in the morning, not worth waking anyone up for.
        A future phase can register additional per-severity topics (e.g. a
        DOWN-only health alert) without touching this function.
    """
    registry.register(
        Topic.SECURITY_ALERT,
        channels={Channel.PANEL_ICON, Channel.TEXT_WINDOW, Channel.SOUND, Channel.EMAIL},
        critical=True,
    )
    registry.register(
        Topic.HEALTH_CHANGED,
        channels={Channel.PANEL_ICON},
        critical=False,
    )
    registry.register(
        Topic.BACKUP_STATUS,
        channels={Channel.PANEL_ICON, Channel.EMAIL},
        critical=False,
    )


def get_notification_registry(request: Request) -> NotificationRegistry:
    """FastAPI dependency: the registry instance attached to this app (see
    app_factory.create_app -> app.state.notification_registry)."""
    return request.app.state.notification_registry
