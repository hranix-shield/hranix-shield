"""A-13 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task from A-2 on
adds at least one regression test that must stay green through the rest of
Phase 0 (and beyond). This pins the core notification-channel contract
later tasks (A-14's diagnostics panel, future MCP plugins publishing their
own topics) must not break:
  - a real security.alert reaches channel 4 (GET /notifications/recent)
    through the real event bus, unauthenticated access stays 401;
  - quiet hours suppress a non-critical topic but never a critical one;
  - channel 6 (SMS/call) never silently no-ops — an overdue critical
    notification always produces an explicit, loggable escalation attempt.
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.notifications.service as notifications_service_module
from app.config import Settings
from app.db.models import Notification
from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS
from app.services.event_bus import Topic
from app.services.notifications.escalation import run_escalation_sweep
from tests.common.factories import create_user


@pytest.mark.integration
def test_notifications_recent_without_token_stays_401(client: TestClient):
    response = client.get("/notifications/recent")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_real_security_alert_still_reaches_channel_4(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="regressiontarget", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/auth/login", json={"username": "regressiontarget", "password": "wrong-pass"})

    await create_user(migrated_session_maker, username="regressionobserver", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "regressionobserver", "password": "pw"}
    ).json()["access_token"]

    recent = client.get(
        "/notifications/recent", headers={"Authorization": f"Bearer {token}"}
    ).json()

    assert recent["unread_count"] >= 1
    assert any(item["topic"] == "security.alert" for item in recent["items"])


@pytest.mark.integration
async def test_quiet_hours_still_suppress_non_critical_never_critical(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    now = datetime.now()
    settings = Settings(
        _env_file=None,
        quiet_hours_enabled=True,
        quiet_hours_start=(now - timedelta(minutes=1)).strftime("%H:%M"),
        quiet_hours_end=(now + timedelta(minutes=10)).strftime("%H:%M"),
    )
    monkeypatch.setattr(notifications_service_module, "get_settings", lambda: settings)

    await client.app.state.event_bus.publish(
        Topic.BACKUP_STATUS, {"job_id": 1, "status": "success", "triggered_by": "manual"}
    )
    await create_user(migrated_session_maker, username="regressiontarget2", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/auth/login", json={"username": "regressiontarget2", "password": "wrong-pass"})

    async with migrated_session_maker() as session:
        backup_row = await session.scalar(
            select(Notification).where(Notification.topic == Topic.BACKUP_STATUS.value)
        )
        security_row = await session.scalar(
            select(Notification).where(Notification.topic == Topic.SECURITY_ALERT.value)
        )

    assert backup_row.suppressed_quiet_hours is True  # non-critical: suppressed
    assert security_row.suppressed_quiet_hours is False  # critical: never suppressed


@pytest.mark.unit
async def test_channel_6_escalation_is_never_a_silent_no_op(
    migrated_session_maker, caplog: pytest.LogCaptureFixture
):
    now = datetime(2026, 7, 14, 12, 0)
    async with migrated_session_maker() as session:
        notification = Notification(
            topic="security.alert",
            payload={"reason": "account_locked", "username": "regressiontarget3"},
            critical=True,
            channels=["panel_icon"],
            suppressed_quiet_hours=False,
            created_at=now - timedelta(minutes=30),
        )
        session.add(notification)
        await session.commit()
        await session.refresh(notification)

    with caplog.at_level("WARNING"):
        escalated_ids = await run_escalation_sweep(
            migrated_session_maker,
            escalation_minutes=15,
            trusted_contacts=["boss@example.com"],
            now=now,
        )

    assert escalated_ids == [notification.id]
    assert any(
        "ESCALATION" in record.message and "sms_call" in record.message and "NOT IMPLEMENTED" in record.message
        for record in caplog.records
    )
