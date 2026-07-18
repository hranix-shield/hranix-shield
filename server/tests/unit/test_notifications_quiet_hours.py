from datetime import datetime, time

import pytest

from app.config import Settings
from app.services.notifications.quiet_hours import (
    is_quiet_hours_now,
    is_within_window,
    parse_hhmm,
)


@pytest.mark.unit
def test_parse_hhmm():
    assert parse_hhmm("22:00") == time(22, 0)
    assert parse_hhmm("08:05") == time(8, 5)


@pytest.mark.unit
def test_is_within_window_normal_non_wrapping_range():
    start, end = time(9, 0), time(17, 0)

    assert is_within_window(time(12, 0), start, end) is True
    assert is_within_window(time(9, 0), start, end) is True  # inclusive start
    assert is_within_window(time(17, 0), start, end) is False  # exclusive end
    assert is_within_window(time(8, 59), start, end) is False


@pytest.mark.unit
def test_is_within_window_wraps_midnight():
    start, end = time(22, 0), time(8, 0)

    assert is_within_window(time(23, 0), start, end) is True
    assert is_within_window(time(2, 0), start, end) is True
    assert is_within_window(time(22, 0), start, end) is True  # inclusive start
    assert is_within_window(time(8, 0), start, end) is False  # exclusive end
    assert is_within_window(time(12, 0), start, end) is False


@pytest.mark.unit
def test_is_within_window_equal_start_and_end_is_never_quiet():
    assert is_within_window(time(3, 0), time(22, 0), time(22, 0)) is False


@pytest.mark.unit
def test_is_quiet_hours_now_respects_the_enabled_flag():
    settings = Settings(
        _env_file=None,
        quiet_hours_enabled=False,
        quiet_hours_start="22:00",
        quiet_hours_end="08:00",
    )

    # 02:00 would be inside the window if quiet hours were enabled.
    assert is_quiet_hours_now(settings, now=datetime(2026, 7, 14, 2, 0)) is False


@pytest.mark.unit
def test_is_quiet_hours_now_true_inside_the_configured_window():
    settings = Settings(
        _env_file=None,
        quiet_hours_enabled=True,
        quiet_hours_start="22:00",
        quiet_hours_end="08:00",
    )

    assert is_quiet_hours_now(settings, now=datetime(2026, 7, 14, 23, 30)) is True


@pytest.mark.unit
def test_is_quiet_hours_now_false_outside_the_configured_window():
    settings = Settings(
        _env_file=None,
        quiet_hours_enabled=True,
        quiet_hours_start="22:00",
        quiet_hours_end="08:00",
    )

    assert is_quiet_hours_now(settings, now=datetime(2026, 7, 14, 12, 0)) is False
