import pytest

from app.services.event_bus import EventBus, Topic


@pytest.mark.unit
async def test_publish_delivers_to_subscribed_topic_handler_with_the_exact_payload():
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    payload = {"reason": "account_locked", "username": "alice"}
    await bus.publish(Topic.SECURITY_ALERT, payload)

    assert received == [(Topic.SECURITY_ALERT, payload)]


@pytest.mark.unit
async def test_publish_does_not_deliver_to_handlers_subscribed_to_a_different_topic():
    bus = EventBus()
    security_calls: list[dict] = []
    backup_calls: list[dict] = []

    async def on_security(topic: str, payload: dict) -> None:
        security_calls.append(payload)

    async def on_backup(topic: str, payload: dict) -> None:
        backup_calls.append(payload)

    bus.subscribe(Topic.SECURITY_ALERT, on_security)
    bus.subscribe(Topic.BACKUP_STATUS, on_backup)

    await bus.publish(Topic.SECURITY_ALERT, {"reason": "account_locked", "username": "bob"})

    assert security_calls == [{"reason": "account_locked", "username": "bob"}]
    assert backup_calls == []


@pytest.mark.unit
async def test_publish_to_topic_without_subscribers_does_not_raise():
    bus = EventBus()

    await bus.publish(Topic.HEALTH_CHANGED, {"status": "degraded"})


@pytest.mark.unit
async def test_multiple_subscribers_on_the_same_topic_are_all_called_in_order():
    bus = EventBus()
    calls: list[str] = []

    async def first(topic: str, payload: dict) -> None:
        calls.append("first")

    async def second(topic: str, payload: dict) -> None:
        calls.append("second")

    bus.subscribe(Topic.BACKUP_STATUS, first)
    bus.subscribe(Topic.BACKUP_STATUS, second)

    await bus.publish(Topic.BACKUP_STATUS, {})

    assert calls == ["first", "second"]


@pytest.mark.unit
async def test_a_failing_subscriber_does_not_raise_out_of_publish_and_does_not_block_others():
    """A broken handler (e.g. the events-table logger hitting a locked
    SQLite DB) must not: (1) propagate out of publish() into the caller —
    which, for /auth/login, would turn a routine 401 into a 500 — or
    (2) prevent a sibling subscriber on the same topic from still running.
    """
    bus = EventBus()
    calls: list[str] = []

    async def broken(topic: str, payload: dict) -> None:
        calls.append("broken-called")
        raise RuntimeError("simulated subscriber failure (e.g. db locked)")

    async def healthy(topic: str, payload: dict) -> None:
        calls.append("healthy-called")

    bus.subscribe(Topic.SECURITY_ALERT, broken)
    bus.subscribe(Topic.SECURITY_ALERT, healthy)

    await bus.publish(Topic.SECURITY_ALERT, {"reason": "account_locked", "username": "carol"})

    assert calls == ["broken-called", "healthy-called"]


@pytest.mark.unit
async def test_a_failing_subscriber_is_logged_as_an_error(caplog: pytest.LogCaptureFixture):
    bus = EventBus()

    async def broken(topic: str, payload: dict) -> None:
        raise RuntimeError("simulated subscriber failure")

    bus.subscribe(Topic.SECURITY_ALERT, broken)

    with caplog.at_level("ERROR", logger="app.services.event_bus"):
        await bus.publish(Topic.SECURITY_ALERT, {"reason": "account_locked", "username": "dan"})

    assert len(caplog.records) == 1
    assert caplog.records[0].levelname == "ERROR"
    assert Topic.SECURITY_ALERT.value in caplog.records[0].getMessage()
