"""A-4 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task from A-2 on
adds at least one regression test that must stay green through the rest of
Phase 0 (and beyond). This pins the core event bus contract other tasks
(A-6, A-13, ...) must not break: publish reaches only the subscribed topic's
handlers, and the real end-to-end chain (account lockout -> security.alert
-> events table) keeps logging a row.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import Event
from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS
from app.services.event_bus import EventBus, Topic
from tests.common.factories import create_user


@pytest.mark.integration
async def test_publish_still_reaches_only_its_own_topic():
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    await bus.publish(Topic.BACKUP_STATUS, {"status": "ok"})

    assert received == []


@pytest.mark.integration
async def test_account_lockout_still_logs_security_alert_event(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    await create_user(migrated_session_maker, username="regress-locked", password="right-pass")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        client.post(
            "/auth/login", json={"username": "regress-locked", "password": "wrong-pass"}
        )

    async with migrated_session_maker() as session:
        event = await session.scalar(
            select(Event).where(Event.topic == Topic.SECURITY_ALERT.value)
        )

    assert event is not None
    assert event.payload == {"reason": "account_locked", "username": "regress-locked"}
