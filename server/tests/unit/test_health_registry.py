import pytest

from app.services.event_bus import EventBus, Topic
from app.services.health.registry import CheckResult, HealthRegistry, Status, worst_status


@pytest.mark.unit
def test_worst_status_of_empty_iterable_is_ok():
    assert worst_status([]) == Status.OK


@pytest.mark.unit
def test_worst_status_picks_the_worst_of_mixed_statuses():
    assert worst_status([Status.OK, Status.DEGRADED]) == Status.DEGRADED
    assert worst_status([Status.OK, Status.DEGRADED, Status.DOWN]) == Status.DOWN
    assert worst_status([Status.DOWN, Status.OK]) == Status.DOWN


@pytest.mark.unit
async def test_run_all_with_no_registered_checks_aggregates_to_ok():
    registry = HealthRegistry()

    result = await registry.run_all()

    assert result == {"status": "ok", "components": {}}


@pytest.mark.unit
async def test_run_all_reports_each_registered_check_by_name():
    registry = HealthRegistry()

    async def ok_check() -> CheckResult:
        return CheckResult(status=Status.OK)

    async def degraded_check() -> CheckResult:
        return CheckResult(status=Status.DEGRADED, details={"error": "slow"})

    registry.register("alpha", ok_check)
    registry.register("beta", degraded_check)

    result = await registry.run_all()

    assert result["components"]["alpha"] == {"status": "ok"}
    assert result["components"]["beta"] == {"status": "degraded", "error": "slow"}


@pytest.mark.unit
async def test_run_all_aggregate_status_is_the_worst_of_all_components():
    registry = HealthRegistry()

    async def ok_check() -> CheckResult:
        return CheckResult(status=Status.OK)

    async def degraded_check() -> CheckResult:
        return CheckResult(status=Status.DEGRADED)

    registry.register("alpha", ok_check)
    registry.register("beta", degraded_check)

    result = await registry.run_all()

    assert result["status"] == "degraded"


@pytest.mark.unit
async def test_a_check_that_raises_is_reported_as_down_not_propagated():
    registry = HealthRegistry()

    async def broken_check() -> CheckResult:
        raise RuntimeError("boom")

    registry.register("gamma", broken_check)

    result = await registry.run_all()

    assert result["status"] == "down"
    assert result["components"]["gamma"]["status"] == "down"
    assert "boom" in result["components"]["gamma"]["error"]


@pytest.mark.unit
async def test_first_observation_of_a_check_does_not_publish_health_changed():
    registry = HealthRegistry()
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.HEALTH_CHANGED, record)

    async def ok_check() -> CheckResult:
        return CheckResult(status=Status.OK)

    registry.register("database", ok_check)

    await registry.run_all(event_bus=bus)

    assert received == []


@pytest.mark.unit
async def test_transition_publishes_health_changed_with_component_and_statuses():
    registry = HealthRegistry()
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.HEALTH_CHANGED, record)

    status_box = {"value": Status.OK}

    async def flaky_check() -> CheckResult:
        return CheckResult(status=status_box["value"])

    registry.register("database", flaky_check)

    await registry.run_all(event_bus=bus)  # baseline: ok, no publish
    status_box["value"] = Status.DEGRADED
    await registry.run_all(event_bus=bus)  # transition: ok -> degraded

    assert received == [
        (
            Topic.HEALTH_CHANGED,
            {"component": "database", "previous_status": "ok", "status": "degraded"},
        )
    ]


@pytest.mark.unit
async def test_repeated_run_with_unchanged_status_does_not_publish_again():
    registry = HealthRegistry()
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.HEALTH_CHANGED, record)

    status_box = {"value": Status.OK}

    async def flaky_check() -> CheckResult:
        return CheckResult(status=status_box["value"])

    registry.register("database", flaky_check)

    await registry.run_all(event_bus=bus)  # baseline: ok
    status_box["value"] = Status.DEGRADED
    await registry.run_all(event_bus=bus)  # ok -> degraded: publishes once
    await registry.run_all(event_bus=bus)  # still degraded: must NOT publish again
    await registry.run_all(event_bus=bus)  # still degraded: must NOT publish again

    assert len(received) == 1


@pytest.mark.unit
async def test_transition_back_to_ok_publishes_health_changed_again():
    registry = HealthRegistry()
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def record(topic: str, payload: dict) -> None:
        received.append((topic, payload))

    bus.subscribe(Topic.HEALTH_CHANGED, record)

    status_box = {"value": Status.OK}

    async def flaky_check() -> CheckResult:
        return CheckResult(status=status_box["value"])

    registry.register("database", flaky_check)

    await registry.run_all(event_bus=bus)  # baseline: ok
    status_box["value"] = Status.DEGRADED
    await registry.run_all(event_bus=bus)  # ok -> degraded
    status_box["value"] = Status.OK
    await registry.run_all(event_bus=bus)  # degraded -> ok

    assert [payload for _, payload in received] == [
        {"component": "database", "previous_status": "ok", "status": "degraded"},
        {"component": "database", "previous_status": "degraded", "status": "ok"},
    ]


@pytest.mark.unit
async def test_run_all_without_an_event_bus_does_not_raise():
    registry = HealthRegistry()

    async def degraded_check() -> CheckResult:
        return CheckResult(status=Status.DEGRADED)

    registry.register("database", degraded_check)

    await registry.run_all()
    result = await registry.run_all()

    assert result["status"] == "degraded"
