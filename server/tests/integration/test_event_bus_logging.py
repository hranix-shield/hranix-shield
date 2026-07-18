"""Integration coverage for the default events-table subscriber (A-4).

Uses a real migrated SQLite DB (tmp_path, via the `migrated_session_maker`
fixture from conftest.py — same fixture A-2/A-3 tests use), not a mock.
`app.services.event_bus.async_session_maker` is monkeypatched so the
subscriber's DB writes land in that isolated tmp DB rather than the real
data/assistant.db.
"""

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.event_bus as event_bus_module
from app.db.models import Event
from app.services.event_bus import EventBus, Topic, register_default_subscribers


@pytest.mark.integration
async def test_registered_subscriber_persists_published_event_to_events_table(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(event_bus_module, "async_session_maker", migrated_session_maker)

    bus = EventBus()
    register_default_subscribers(bus)

    await bus.publish(
        Topic.SECURITY_ALERT, {"reason": "account_locked", "username": "irene"}
    )

    async with migrated_session_maker() as session:
        event = await session.scalar(
            select(Event).where(Event.topic == Topic.SECURITY_ALERT.value)
        )

    assert event is not None
    assert event.payload == {"reason": "account_locked", "username": "irene"}
    assert event.created_at is not None


@pytest.mark.integration
async def test_registered_subscriber_covers_every_minimum_topic(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(event_bus_module, "async_session_maker", migrated_session_maker)

    bus = EventBus()
    register_default_subscribers(bus)

    for topic in Topic:
        await bus.publish(topic, {"marker": topic.value})

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(Event))).all()

    logged_topics = {row.topic for row in rows}
    assert logged_topics == {topic.value for topic in Topic}
