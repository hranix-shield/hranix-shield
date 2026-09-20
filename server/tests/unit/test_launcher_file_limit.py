"""A-46: `launcher._raise_open_file_limit` — real bug found live
(2026-08-03, see
docs/план-спецификация-фаза-0-лимит-открытых-файлов-2026-08-16.md for the
full diagnosis): a `launchd`-launched packaged `.app` defaults to a soft
`RLIMIT_NOFILE` of 256, low enough that a real custom/full scan (one fresh
TCP connection per file, see `ClamdClient`'s own docstring) ran the whole
process into that ceiling and froze the entire single-worker event loop —
not just the scan request, `/health` too. `resource_module` is injected
here (a `types.SimpleNamespace` standing in for the stdlib `resource`
module) rather than relying on `sys.modules` patching, since the real
import happens locally inside the function — the same test-injection seam
convention (`sleep`, `client`, ...) already used throughout this codebase.
"""

from __future__ import annotations

import types

import pytest

import launcher

_RLIM_INFINITY = 9223372036854775807


def _fake_resource(*, soft: int, hard: int, raise_on_set: Exception | None = None):
    calls: list[tuple[int, tuple[int, int]]] = []

    def _setrlimit(which, values):
        if raise_on_set is not None:
            raise raise_on_set
        calls.append((which, values))

    return (
        types.SimpleNamespace(
            RLIMIT_NOFILE=7,
            RLIM_INFINITY=_RLIM_INFINITY,
            getrlimit=lambda which: (soft, hard),
            setrlimit=_setrlimit,
        ),
        calls,
    )


@pytest.mark.unit
def test_raises_soft_limit_toward_the_desired_target(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    fake, calls = _fake_resource(soft=256, hard=4096)

    launcher._raise_open_file_limit(resource_module=fake)

    assert calls == [(7, (min(launcher._DESIRED_NOFILE_SOFT_LIMIT, 4096), 4096))]


@pytest.mark.unit
def test_does_nothing_when_soft_limit_is_already_at_or_above_the_target(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    fake, calls = _fake_resource(soft=launcher._DESIRED_NOFILE_SOFT_LIMIT, hard=_RLIM_INFINITY)

    launcher._raise_open_file_limit(resource_module=fake)

    assert calls == []


@pytest.mark.unit
def test_uses_the_desired_target_directly_when_hard_limit_is_reported_as_infinity(
    monkeypatch: pytest.MonkeyPatch,
):
    """macOS-known quirk (see this module's own docstring): `setrlimit`
    does not reliably accept the raw `RLIM_INFINITY` sentinel back as a
    value — the target must be a concrete number even when `hard` itself
    is reported as "unlimited"."""
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    fake, calls = _fake_resource(soft=256, hard=_RLIM_INFINITY)

    launcher._raise_open_file_limit(resource_module=fake)

    assert calls == [(7, (launcher._DESIRED_NOFILE_SOFT_LIMIT, _RLIM_INFINITY))]


@pytest.mark.unit
def test_caps_the_target_at_a_concrete_hard_limit_below_the_desired_value(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    fake, calls = _fake_resource(soft=256, hard=1024)

    launcher._raise_open_file_limit(resource_module=fake)

    assert calls == [(7, (1024, 1024))]


@pytest.mark.unit
@pytest.mark.parametrize("exc", [ValueError("nope"), OSError("nope")])
def test_swallows_a_setrlimit_failure_without_raising(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
):
    monkeypatch.setattr(launcher.sys, "platform", "darwin")
    fake, _calls = _fake_resource(soft=256, hard=4096, raise_on_set=exc)

    launcher._raise_open_file_limit(resource_module=fake)  # must not raise


@pytest.mark.unit
def test_is_a_no_op_on_windows(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(launcher.sys, "platform", "win32")
    touched: list[str] = []
    fake = types.SimpleNamespace(
        RLIMIT_NOFILE=7,
        RLIM_INFINITY=_RLIM_INFINITY,
        getrlimit=lambda which: touched.append("getrlimit") or (256, 4096),
        setrlimit=lambda which, values: touched.append("setrlimit"),
    )

    launcher._raise_open_file_limit(resource_module=fake)

    assert touched == []
