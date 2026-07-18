from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Notification, User
from app.db.session import get_session
from app.dependencies import get_current_user
from app.services.notifications import (
    CHANNEL_DELIVERY_IMPLEMENTED,
    Channel,
    NotificationRegistry,
    TrustedContactRegistry,
    get_notification_registry,
    get_trusted_contact_registry,
    is_smtp_configured,
)

router = APIRouter(prefix="/notifications", tags=["notifications"])

_DEFAULT_RECENT_LIMIT = 20


def _now() -> datetime:
    """Naive UTC now, matching Notification's DateTime columns — same
    helper/reasoning as services.notifications.service._now."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _notification_payload(notification: Notification) -> dict[str, Any]:
    return {
        "id": notification.id,
        "topic": notification.topic,
        "payload": notification.payload,
        "critical": notification.critical,
        "channels": notification.channels or [],
        "email_sent": notification.email_sent,
        "created_at": notification.created_at.isoformat() if notification.created_at else None,
        "read_at": notification.read_at.isoformat() if notification.read_at else None,
        "acknowledged_at": (
            notification.acknowledged_at.isoformat() if notification.acknowledged_at else None
        ),
        "escalated_at": notification.escalated_at.isoformat() if notification.escalated_at else None,
    }


@router.get("/recent")
async def recent(
    limit: int = _DEFAULT_RECENT_LIMIT,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Channel 4 (panel icons/indicators): the topbar badge polls this.

    Only ever returns non-suppressed rows — a notification quiet hours
    suppressed did not reach ANY channel, including this one (see A-13 task
    report: quiet-hours suppression is all-or-nothing across the whole
    matrix, not "suppress everything except the panel"). The row still
    exists in the `notifications` table for anyone querying the DB
    directly; this endpoint just doesn't surface it as a "thing that
    happened and needs your attention".
    """
    items = (
        await session.scalars(
            select(Notification)
            .where(Notification.suppressed_quiet_hours.is_(False))
            .order_by(Notification.created_at.desc())
            .limit(limit)
        )
    ).all()
    unread_count = await session.scalar(
        select(func.count())
        .select_from(Notification)
        .where(
            Notification.suppressed_quiet_hours.is_(False),
            Notification.read_at.is_(None),
        )
    )
    # Computed over the FULL unread set, not just this page's `items` — the
    # topbar badge needs to know whether ANY unread notification is
    # critical, even one older than the `limit` most recent rows, to decide
    # its color (see app.js's renderNotificationsPill).
    unread_critical_count = await session.scalar(
        select(func.count())
        .select_from(Notification)
        .where(
            Notification.suppressed_quiet_hours.is_(False),
            Notification.read_at.is_(None),
            Notification.critical.is_(True),
        )
    )
    return {
        "items": [_notification_payload(item) for item in items],
        "unread_count": unread_count or 0,
        "unread_critical_count": unread_critical_count or 0,
    }


@router.post("/mark-read")
async def mark_read(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Clears the topbar's unread badge — marks every currently-unread,
    non-suppressed notification as read as of now."""
    unread = (
        await session.scalars(
            select(Notification).where(
                Notification.suppressed_quiet_hours.is_(False),
                Notification.read_at.is_(None),
            )
        )
    ).all()
    now = _now()
    for notification in unread:
        notification.read_at = now
    if unread:
        await session.commit()
    return {"unread_count": 0}


@router.post("/{notification_id}/ack")
async def acknowledge(
    notification_id: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Acknowledging a critical notification stops the escalation sweep
    (services/notifications/escalation.py) from treating it as still
    outstanding. Idempotent: acknowledging an already-acknowledged
    notification just returns its current state unchanged."""
    notification = await session.get(Notification, notification_id)
    if notification is None:
        raise HTTPException(status_code=404, detail={"error": "notification_not_found"})

    if notification.acknowledged_at is None:
        notification.acknowledged_at = _now()
        await session.commit()
        await session.refresh(notification)

    return _notification_payload(notification)


@router.get("/settings")
async def get_notification_settings(
    registry: NotificationRegistry = Depends(get_notification_registry),
    trusted_contacts: TrustedContactRegistry = Depends(get_trusted_contact_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Backs the "Настройки -> Уведомления и каналы" screen: the topic x
    channel matrix, which channels Phase 0 actually delivers on (honesty
    flags — a checked-but-unimplemented channel is not a lie, the UI can
    show it as "включено, но пока не доставляется"), quiet hours/escalation
    (read-only in Phase 0 — see task report: these come from Settings/.env,
    not yet a runtime-editable store), and the trusted-contacts list
    (genuinely runtime-editable, see /settings/trusted-contacts below).
    """
    settings = get_settings()
    return {
        "matrix": registry.snapshot(),
        "channel_availability": {
            channel.value: CHANNEL_DELIVERY_IMPLEMENTED.get(channel, False) for channel in Channel
        },
        "quiet_hours": {
            "enabled": settings.quiet_hours_enabled,
            "start": settings.quiet_hours_start,
            "end": settings.quiet_hours_end,
        },
        "escalation": {
            "minutes": settings.notifications_escalation_minutes,
            "check_interval_seconds": settings.notifications_escalation_check_interval_seconds,
        },
        "trusted_contacts": trusted_contacts.emails(),
        "smtp_configured": is_smtp_configured(settings),
    }


class MatrixUpdateRequest(BaseModel):
    channels: list[Channel]


@router.post("/settings/matrix/{topic}")
async def update_matrix(
    topic: str,
    body: MatrixUpdateRequest,
    registry: NotificationRegistry = Depends(get_notification_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Flips one topic's channel checkboxes (in-memory, see
    services/notifications/registry.py) — `topic` must already be a row in
    the matrix (registered via `register_default_topics` or a future
    plugin's own `registry.register(...)` call); an unknown topic is a 404,
    not silently created with an assumed non-critical default."""
    if topic not in registry.known_topics():
        raise HTTPException(status_code=404, detail={"error": "unknown_topic"})

    registry.set_channels(topic, body.channels)
    return {"topic": topic, **registry.snapshot()[topic]}


class TrustedContactsUpdateRequest(BaseModel):
    emails: list[str]


@router.post("/settings/trusted-contacts")
async def update_trusted_contacts(
    body: TrustedContactsUpdateRequest,
    trusted_contacts: TrustedContactRegistry = Depends(get_trusted_contact_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Replaces the whole trusted-contacts list at once (a settings-screen
    "save" action, not incremental add/remove) — in-memory, reset to the
    `TRUSTED_CONTACT_EMAILS` env default on restart, same accepted Phase 0
    limitation as the security console toggles (A-10)."""
    trusted_contacts.set_all(body.emails)
    return {"trusted_contacts": trusted_contacts.emails()}
