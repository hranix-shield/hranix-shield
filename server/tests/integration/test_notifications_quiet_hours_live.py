"""A-13 DoD: "тихие часы подавляют некритическое событие ... security.alert
доходит несмотря на тихие часы" — driven through the REAL event bus and
the REAL HTTP layer (client fixture), not a unit-level quiet_hours.py call.

The quiet-hours WINDOW is set to genuinely bracket the real current
wall-clock time (not a frozen/fake clock) — `quiet_hours.is_quiet_hours_now`
reads real local time by default, so this proves the suppression logic
against an actual "is it quiet right now" decision, the same way a real
deployment would experience it.
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
from tests.common.factories import create_user


def _bracketing_window(now: datetime) -> tuple[str, str]:
    start = (now - timedelta(minutes=2)).strftime("%H:%M")
    end = (now + timedelta(minutes=10)).strftime("%H:%M")
    return start, end


@pytest.mark.integration
async def test_quiet_hours_suppress_health_changed_but_not_security_alert(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    start, end = _bracketing_window(datetime.now())
    settings = Settings(_env_file=None, quiet_hours_enabled=True, quiet_hours_start=start, quiet_hours_end=end)
    monkeypatch.setattr(notifications_service_module, "get_settings", lambda: settings)

    # Non-critical: publish health.changed directly on the app's real bus —
    # the same bus /health/detailed's HealthRegistry would publish to (A-6),
    # just triggered directly here so this test doesn't need to fabricate a
    # flapping subsystem to observe the same event shape.
    await client.app.state.event_bus.publish(
        Topic.HEALTH_CHANGED,
        {"component": "database", "previous_status": "ok", "status": "degraded"},
    )

    # Critical: a real brute-force lockout (A-3/A-4), unchanged mechanism.
    await create_user(migrated_session_maker, username="qhtarget", password="right-pass")
    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post("/auth/login", json={"username": "qhtarget", "password": "wrong-pass"})

    await create_user(migrated_session_maker, username="observer", password="pw", role="admin")
    login = client.post("/auth/login", json={"username": "observer", "password": "pw"})
    token = login.json()["access_token"]

    recent = client.get(
        "/notifications/recent", headers={"Authorization": f"Bearer {token}"}
    ).json()
    topics = [item["topic"] for item in recent["items"]]

    assert "security.alert" in topics, "critical notifications must reach channels despite quiet hours"
    assert "health.changed" not in topics, "non-critical notifications must be suppressed during quiet hours"

    # The suppressed event was still recorded (auditable), just not
    # surfaced as "delivered" — confirms this is suppression, not data loss.
    async with migrated_session_maker() as session:
        health_row = await session.scalar(
            select(Notification).where(Notification.topic == Topic.HEALTH_CHANGED.value)
        )
        security_row = await session.scalar(
            select(Notification).where(Notification.topic == Topic.SECURITY_ALERT.value)
        )
    assert health_row is not None
    assert health_row.suppressed_quiet_hours is True
    assert health_row.channels == []
    assert security_row is not None
    assert security_row.suppressed_quiet_hours is False
    assert security_row.channels != []


@pytest.mark.integration
async def test_health_changed_is_delivered_outside_quiet_hours(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Regression anchor for the other half of the decision: outside the
    configured window, a non-critical topic is NOT suppressed."""
    now = datetime.now()
    # A window nowhere near "now" — i.e. quiet hours are NOT active right now.
    far_start = (now + timedelta(hours=6)).strftime("%H:%M")
    far_end = (now + timedelta(hours=7)).strftime("%H:%M")
    settings = Settings(
        _env_file=None, quiet_hours_enabled=True, quiet_hours_start=far_start, quiet_hours_end=far_end
    )
    monkeypatch.setattr(notifications_service_module, "get_settings", lambda: settings)

    await client.app.state.event_bus.publish(
        Topic.HEALTH_CHANGED,
        {"component": "event_bus", "previous_status": "ok", "status": "degraded"},
    )

    async with migrated_session_maker() as session:
        row = await session.scalar(
            select(Notification).where(Notification.topic == Topic.HEALTH_CHANGED.value)
        )
    assert row is not None
    assert row.suppressed_quiet_hours is False
    assert row.channels == ["panel_icon"]
