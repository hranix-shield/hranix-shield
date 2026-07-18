from __future__ import annotations

from enum import StrEnum


class Channel(StrEnum):
    """The 6 notification channels, §5.4 of the analytical plan, in the
    matrix's column order."""

    SOUND = "sound"
    VOICE = "voice"
    TEXT_WINDOW = "text_window"
    PANEL_ICON = "panel_icon"
    EMAIL = "email"
    SMS_CALL = "sms_call"


CHANNEL_IDS: tuple[str, ...] = tuple(channel.value for channel in Channel)

# Honesty flag (see A-13 task report): a channel can be checked "on" in the
# topic x channel matrix (the user's intent) without Phase 0 actually being
# able to deliver on it yet.
#
#   - PANEL_ICON: real — the panel has no push mechanism (WebSocket/SSE) in
#     Phase 0, but the existing poll-on-request shape is enough: a
#     Notification row is persisted the moment the event happens, and
#     GET /notifications/recent (polled from the browser) picks it up on its
#     next request. No lie here — a client that polls sees it.
#   - EMAIL: real — a genuine SMTP send (services/notifications/smtp_client.py),
#     skipped-and-logged only when SMTP_* is left unconfigured.
#   - SOUND / VOICE / TEXT_WINDOW: NOT wired to real delivery this phase.
#     All three would need either a push channel (WebSocket/SSE, not built
#     yet) or a browser-side poll-diff trigger; scoped out of A-13 as a
#     judgment call (see task report) rather than half-built. The matrix
#     still records the user's intended on/off state so a later phase that
#     adds the missing plumbing has nothing to migrate.
#   - SMS_CALL: explicitly out of scope this phase (needs the phone-terminal
#     backlog item, analytical plan §9.1) — deliberately not implemented,
#     see services/notifications/escalation.py's no-op log.
CHANNEL_DELIVERY_IMPLEMENTED: dict[Channel, bool] = {
    Channel.SOUND: False,
    Channel.VOICE: False,
    Channel.TEXT_WINDOW: False,
    Channel.PANEL_ICON: True,
    Channel.EMAIL: True,
    Channel.SMS_CALL: False,
}
