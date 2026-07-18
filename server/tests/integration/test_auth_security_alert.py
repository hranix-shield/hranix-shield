"""A-4: real publisher wired to A-3's brute-force lock.

On the failed-login attempt that transitions an account into the locked
state, /auth/login must publish `security.alert` on the event bus, and the
default subscriber (A-4) must persist it into the real `events` table.
Verified against a real migrated tmp SQLite DB, not a mock — the `client`
fixture (conftest.py) already redirects the event bus's DB writes to that
same isolated DB, so no extra monkeypatching is needed here.
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
async def test_five_failed_logins_publish_security_alert_logged_to_events_table(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    await create_user(migrated_session_maker, username="grace", password="right-pass")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        response = client.post(
            "/auth/login", json={"username": "grace", "password": "wrong-pass"}
        )
        assert response.status_code == 401

    async with migrated_session_maker() as session:
        event = await session.scalar(
            select(Event).where(Event.topic == Topic.SECURITY_ALERT.value)
        )

    assert event is not None
    assert event.payload == {"reason": "account_locked", "username": "grace"}


@pytest.mark.integration
async def test_failed_logins_below_threshold_do_not_publish_security_alert(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    await create_user(migrated_session_maker, username="henry", password="right-pass")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        client.post("/auth/login", json={"username": "henry", "password": "wrong-pass"})

    async with migrated_session_maker() as session:
        event = await session.scalar(
            select(Event).where(Event.topic == Topic.SECURITY_ALERT.value)
        )

    assert event is None


@pytest.mark.integration
async def test_repeated_attempts_after_already_locked_do_not_publish_again(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """The event fires exactly once, on the attempt that causes the lock —
    not again on every subsequent attempt against an already-locked account.
    """
    await create_user(migrated_session_maker, username="iris", password="right-pass")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS + 3):
        client.post("/auth/login", json={"username": "iris", "password": "wrong-pass"})

    async with migrated_session_maker() as session:
        events = (
            await session.scalars(
                select(Event).where(Event.topic == Topic.SECURITY_ALERT.value)
            )
        ).all()

    assert len(events) == 1
    assert events[0].payload == {"reason": "account_locked", "username": "iris"}


@pytest.mark.integration
async def test_login_still_returns_401_when_security_alert_subscriber_is_broken(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """A broken subscriber (e.g. the events-table logger hitting a locked DB)
    must not turn /auth/login's routine 401 into a 500 — EventBus.publish()
    isolates each handler, per-handler, so the request path is unaffected.
    """
    await create_user(migrated_session_maker, username="judy", password="right-pass")

    broken_bus = EventBus()

    async def broken_subscriber(topic: str, payload: dict) -> None:
        raise RuntimeError("simulated: sqlite database is locked")

    broken_bus.subscribe(Topic.SECURITY_ALERT, broken_subscriber)
    client.app.state.event_bus = broken_bus

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        response = client.post(
            "/auth/login", json={"username": "judy", "password": "wrong-pass"}
        )
        assert response.status_code == 401
