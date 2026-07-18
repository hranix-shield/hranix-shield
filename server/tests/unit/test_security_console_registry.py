import pytest

from app.services.security_console import (
    CONSOLE_IDS,
    ConsoleId,
    ConsoleStatus,
    SecurityConsoleRegistry,
    worst_console_status,
)


@pytest.mark.unit
def test_worst_console_status_of_empty_iterable_is_ok():
    assert worst_console_status([]) == ConsoleStatus.OK


@pytest.mark.unit
def test_worst_console_status_picks_the_worst_of_mixed_statuses():
    assert worst_console_status([ConsoleStatus.OK, ConsoleStatus.DEGRADED]) == ConsoleStatus.DEGRADED
    assert (
        worst_console_status([ConsoleStatus.OK, ConsoleStatus.DEGRADED, ConsoleStatus.DOWN])
        == ConsoleStatus.DOWN
    )
    assert worst_console_status([ConsoleStatus.DOWN, ConsoleStatus.OK]) == ConsoleStatus.DOWN


@pytest.mark.unit
def test_console_ids_cover_all_six_consoles_from_the_plan():
    assert CONSOLE_IDS == ("perimeter", "ids", "av", "network", "backup", "logs")
    assert set(CONSOLE_IDS) == {c.value for c in ConsoleId}


@pytest.mark.unit
def test_every_console_starts_enabled_and_ok():
    registry = SecurityConsoleRegistry()

    for console_id in CONSOLE_IDS:
        assert registry.is_enabled(console_id) is True
        assert registry.status_for(console_id) == ConsoleStatus.OK

    assert registry.aggregate_status() == ConsoleStatus.OK


@pytest.mark.unit
def test_disabling_a_console_reports_degraded_not_down():
    registry = SecurityConsoleRegistry()

    registry.set_enabled("ids", False)

    assert registry.is_enabled("ids") is False
    assert registry.status_for("ids") == ConsoleStatus.DEGRADED


@pytest.mark.unit
def test_disabling_one_console_degrades_the_aggregate_others_unaffected():
    registry = SecurityConsoleRegistry()

    registry.set_enabled("ids", False)

    assert registry.aggregate_status() == ConsoleStatus.DEGRADED
    assert registry.status_for("perimeter") == ConsoleStatus.OK


@pytest.mark.unit
def test_re_enabling_a_console_restores_ok_and_the_aggregate():
    registry = SecurityConsoleRegistry()
    registry.set_enabled("av", False)
    assert registry.aggregate_status() == ConsoleStatus.DEGRADED

    registry.set_enabled("av", True)

    assert registry.status_for("av") == ConsoleStatus.OK
    assert registry.aggregate_status() == ConsoleStatus.OK


@pytest.mark.unit
def test_snapshot_reports_status_and_enabled_for_every_console():
    registry = SecurityConsoleRegistry()
    registry.set_enabled("network", False)

    snapshot = registry.snapshot()

    assert set(snapshot.keys()) == set(CONSOLE_IDS)
    assert snapshot["network"] == {"status": "degraded", "enabled": False}
    assert snapshot["perimeter"] == {"status": "ok", "enabled": True}


@pytest.mark.unit
def test_unknown_console_id_defaults_to_enabled_ok():
    registry = SecurityConsoleRegistry()

    assert registry.is_enabled("not-a-real-console") is True
    assert registry.status_for("not-a-real-console") == ConsoleStatus.OK
