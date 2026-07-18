"""run_escalation_sweep against a real (tmp, migrated) SQLite DB — same
"unit test, real tmp DB, monkeypatched module-level async_session_maker"
shape as tests/unit/test_health_checks.py / test_notifications_service.py.
"""

from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

import app.services.notifications.escalation as escalation_module
from app.db.models import Notification
from app.services.notifications.escalation import run_escalation_sweep


async def _insert(maker, **kwargs) -> Notification:
    async with maker() as session:
        notification = Notification(
            topic=kwargs.pop("topic", "security.alert"),
            payload=kwargs.pop("payload", {}),
            critical=kwargs.pop("critical", True),
            channels=kwargs.pop("channels", ["panel_icon"]),
            suppressed_quiet_hours=kwargs.pop("suppressed_quiet_hours", False),
            created_at=kwargs.pop("created_at"),
            acknowledged_at=kwargs.pop("acknowledged_at", None),
            escalated_at=kwargs.pop("escalated_at", None),
        )
        session.add(notification)
        await session.commit()
        await session.refresh(notification)
        return notification


@pytest.mark.unit
async def test_escalates_an_overdue_unacknowledged_critical_notification(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(escalation_module, "async_session_maker", migrated_session_maker)
    now = datetime(2026, 7, 14, 12, 0)
    notification = await _insert(migrated_session_maker, created_at=now - timedelta(minutes=20))

    with caplog.at_level("WARNING"):
        escalated_ids = await run_escalation_sweep(
            migrated_session_maker,
            escalation_minutes=15,
            trusted_contacts=["boss@example.com"],
            now=now,
        )

    assert escalated_ids == [notification.id]
    assert any(
        "ESCALATION" in record.message and "sms_call" in record.message
        for record in caplog.records
    )
    assert any("boss@example.com" in record.message for record in caplog.records)

    async with migrated_session_maker() as session:
        row = await session.get(Notification, notification.id)
    assert row.escalated_at == now


@pytest.mark.unit
async def test_does_not_escalate_before_the_window_elapses(migrated_session_maker):
    now = datetime(2026, 7, 14, 12, 0)
    await _insert(migrated_session_maker, created_at=now - timedelta(minutes=5))

    escalated_ids = await run_escalation_sweep(
        migrated_session_maker, escalation_minutes=15, trusted_contacts=[], now=now
    )

    assert escalated_ids == []


@pytest.mark.unit
async def test_does_not_escalate_a_non_critical_notification(migrated_session_maker):
    now = datetime(2026, 7, 14, 12, 0)
    await _insert(
        migrated_session_maker, critical=False, created_at=now - timedelta(minutes=30)
    )

    escalated_ids = await run_escalation_sweep(
        migrated_session_maker, escalation_minutes=15, trusted_contacts=[], now=now
    )

    assert escalated_ids == []


@pytest.mark.unit
async def test_does_not_escalate_an_already_acknowledged_notification(migrated_session_maker):
    now = datetime(2026, 7, 14, 12, 0)
    await _insert(
        migrated_session_maker,
        created_at=now - timedelta(minutes=30),
        acknowledged_at=now - timedelta(minutes=10),
    )

    escalated_ids = await run_escalation_sweep(
        migrated_session_maker, escalation_minutes=15, trusted_contacts=[], now=now
    )

    assert escalated_ids == []


@pytest.mark.unit
async def test_does_not_escalate_an_already_escalated_notification_again(migrated_session_maker):
    now = datetime(2026, 7, 14, 12, 0)
    await _insert(
        migrated_session_maker,
        created_at=now - timedelta(minutes=30),
        escalated_at=now - timedelta(minutes=5),
    )

    escalated_ids = await run_escalation_sweep(
        migrated_session_maker, escalation_minutes=15, trusted_contacts=[], now=now
    )

    assert escalated_ids == []
