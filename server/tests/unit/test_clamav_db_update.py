"""Post-merge user request (2026-08-02): `clamav.update_clamav_databases` —
"Обновить базы сейчас", a narrow elevated docker-exec exception for ClamAV
(same shape A-43/A-45 already established for CrowdSec). `elevated_run` and
`fetch_av_clamav_data` are monkeypatched at their bare names imported into
`app.services.mcp.security_connectors.clamav`, same "inject a fake
transport" technique test_crowdsec_scenario_updates.py already uses — none
of this ever pops a real OS dialog or touches a real container.
"""

from __future__ import annotations

import pytest

import app.services.mcp.security_connectors.clamav as clamav_module
from app.services.mcp.security_connectors.clamav import (
    ClamAvDbUpdateError,
    _poll_until_databases_updated_at_changes,
    update_clamav_databases,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult


def _fake_elevated_run(result: ElevatedRunResult, *, captured: dict | None = None):
    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        if captured is not None:
            captured["command"] = command
            captured["reason_ru"] = reason_ru
            captured["reason_en"] = reason_en
            captured["timeout"] = timeout
        return result

    return _run


def _fake_fetch_av_clamav_data(
    *,
    before="2026-08-01T00:00:00",
    after="2026-08-02T12:00:00",
    database_version="27500",
    calls: list[int] | None = None,
):
    """Real bug found live (2026-08-03): `update_clamav_databases` now reads
    this TWICE (once for the pre-update baseline, once — at least — inside
    the post-RELOAD poll) and compares the two, so a fake that always
    returns the same fixed value can never see a "change" and would poll
    the full `_DB_UPDATE_RELOAD_POLL_ATTEMPTS`, sleeping real wall-clock
    seconds between each. This fake instead returns `before` on the first
    call and `after` on every call after that — the honest shape of a real
    reload actually taking effect — so the poll loop exits on its very
    first post-RELOAD read, no sleeping involved. `calls`, if given, records
    how many times this fake was invoked (a list is used as a mutable
    counter cell, same convention `captured` already uses below)."""
    state = {"n": 0}

    async def _fake(settings=None, *, job_registry=None):
        state["n"] += 1
        if calls is not None:
            calls.append(state["n"])
        databases_updated_at = before if state["n"] == 1 else after
        return {
            "connector": {"status": "ok"},
            "engine_version": "1.5.3",
            "database_version": database_version,
            "databases_updated_at": databases_updated_at,
            "quarantine_count": 0,
            "last_scan_at": None,
            "clean": None,
        }

    return _fake


@pytest.fixture(autouse=True)
def _fixed_docker_binary(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(clamav_module, "_resolve_docker_binary", lambda: "/usr/local/bin/docker")


@pytest.mark.unit
async def test_update_databases_ok_runs_freshclam_then_a_fresh_readback(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}
    # A-63 follow-up: this test pins the POSIX (macOS/Linux) contract — the
    # bash-script path. Windows now takes its own direct docker-exec branch
    # (see the dedicated test below), so pin the platform explicitly.
    monkeypatch.setattr(clamav_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        clamav_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout=""), captured=captured),
    )
    monkeypatch.setattr(
        clamav_module, "fetch_av_clamav_data", _fake_fetch_av_clamav_data(after="2026-08-02T12:00:00")
    )

    result = await update_clamav_databases()

    assert result["status"] == "ok"
    assert result["databases_updated_at"] == "2026-08-02T12:00:00"
    assert result["database_version"] == "27500"
    # A real network fetch (against ClamAV's own signature CDN) — must not
    # rely on elevated_run's default 120s timeout, same reasoning A-45's
    # own CrowdSec hub-update timeout override documents.
    assert captured["timeout"] == clamav_module._DB_UPDATE_ELEVATED_TIMEOUT
    assert captured["timeout"] > 120.0
    assert captured["command"][0] == "/bin/bash"
    assert "Hranix Shield" in captured["reason_ru"]


@pytest.mark.unit
async def test_update_databases_ok_also_triggers_a_reload_before_the_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    """Regression test for a real bug found live (2026-08-02): freshclam
    only writes new signature files to disk, clamd only picks them up on
    RELOAD — without this, `databases_updated_at` kept reporting the stale
    pre-update value until the operator happened to trigger a reload some
    other way (e.g. clicking "Перечитать базы" separately)."""
    reload_calls: list[int] = []

    class _FakeReloadClient:
        async def reload(self):
            reload_calls.append(1)

    monkeypatch.setattr(
        clamav_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok", stdout=""))
    )
    monkeypatch.setattr(clamav_module, "create_clamav_client", lambda settings=None: _FakeReloadClient())
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _fake_fetch_av_clamav_data())

    result = await update_clamav_databases()

    assert result["status"] == "ok"
    assert reload_calls == [1]


@pytest.mark.unit
async def test_update_databases_ok_skips_reload_gracefully_when_clamav_not_configured(
    monkeypatch: pytest.MonkeyPatch,
):
    """`create_clamav_client` honestly returns `None` when clamav_enabled is
    off — the reload step must skip cleanly, never crash the whole action
    (the freshclam step itself already succeeded)."""
    monkeypatch.setattr(
        clamav_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok", stdout=""))
    )
    monkeypatch.setattr(clamav_module, "create_clamav_client", lambda settings=None: None)
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _fake_fetch_av_clamav_data())

    result = await update_clamav_databases()

    assert result["status"] == "ok"


@pytest.mark.unit
async def test_update_databases_ok_survives_a_reload_that_itself_fails(monkeypatch: pytest.MonkeyPatch):
    """A RELOAD hiccup must not turn an otherwise-genuine freshclam success
    into a reported failure — the download already happened."""

    class _FailingReloadClient:
        async def reload(self):
            raise clamav_module.ClamdError("boom", reason="unreachable")

    monkeypatch.setattr(
        clamav_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok", stdout=""))
    )
    monkeypatch.setattr(clamav_module, "create_clamav_client", lambda settings=None: _FailingReloadClient())
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _fake_fetch_av_clamav_data())

    result = await update_clamav_databases()

    assert result["status"] == "ok"


@pytest.mark.unit
async def test_update_databases_script_execs_freshclam_inside_the_container():
    script = clamav_module._build_db_update_script("/usr/local/bin/docker")

    assert "docker exec" in script or "/usr/local/bin/docker exec" in script
    assert clamav_module.CLAMAV_CONTAINER_NAME in script
    assert "freshclam" in script


@pytest.mark.unit
async def test_update_databases_on_windows_runs_docker_exec_freshclam_directly(
    monkeypatch: pytest.MonkeyPatch,
):
    """A-63 follow-up (live finding 2026-09-21): on Windows there is no
    `/bin/bash`, so the POSIX script-file path failed instantly (cmd exit 3,
    «Система не может найти указанный путь») and the «Обновить базы» button
    could never work. On Windows the elevated command is the docker exec
    directly — no temp script — with the resolved (quoted-at-the-cmd-layer)
    docker binary."""
    captured: dict = {}
    monkeypatch.setattr(clamav_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(clamav_module, "_resolve_docker_binary", lambda: "docker")
    monkeypatch.setattr(
        clamav_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout=""), captured=captured),
    )
    monkeypatch.setattr(
        clamav_module, "fetch_av_clamav_data", _fake_fetch_av_clamav_data(after="2026-08-02T12:00:00")
    )

    result = await update_clamav_databases()

    assert result["status"] == "ok"
    assert captured["command"] == [
        "docker", "exec", clamav_module.CLAMAV_CONTAINER_NAME, "freshclam",
    ]


@pytest.mark.unit
async def test_update_databases_cancelled_raises_elevation_cancelled_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    readback_calls: list[int] = []

    async def _fake_readback(settings=None, *, job_registry=None):
        readback_calls.append(1)
        return {}

    monkeypatch.setattr(
        clamav_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _fake_readback)

    with pytest.raises(ClamAvDbUpdateError) as exc_info:
        await update_clamav_databases()

    assert exc_info.value.reason == "elevation_cancelled"
    assert readback_calls == []  # never reads back after a cancelled/failed elevation


@pytest.mark.unit
async def test_update_databases_failed_raises_elevation_failed_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    readback_calls: list[int] = []

    async def _fake_readback(settings=None, *, job_registry=None):
        readback_calls.append(1)
        return {}

    monkeypatch.setattr(
        clamav_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="docker: command not found")),
    )
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _fake_readback)

    with pytest.raises(ClamAvDbUpdateError) as exc_info:
        await update_clamav_databases()

    assert exc_info.value.reason == "elevation_failed"
    assert readback_calls == []


# ---------------------------------------------------------------------------
# Real bug found live (2026-08-03): "Базы обновлены" kept showing the old
# date even though "Базы сигнатур обновлены." reported success — RELOAD's
# ack is fire-and-forget, not proof the reload has actually finished (see
# `_poll_until_databases_updated_at_changes`'s own docstring). These tests
# drive the polling helper directly, with an injected instant fake `sleep`
# (same seam every other scheduler/poller in this codebase already uses) so
# none of them waits any real wall-clock time.
# ---------------------------------------------------------------------------


def _sequenced_fetch(values: list[str | None]):
    """Returns each of `values` in turn (one per call), as
    `databases_updated_at`; raises `IndexError` if called more times than
    `values` has entries — a test bug (an unexpectedly-still-polling loop),
    not something a real caller should ever trigger."""
    state = {"n": 0}

    async def _fake(settings=None, *, job_registry=None):
        value = values[state["n"]]
        state["n"] += 1
        return {"databases_updated_at": value, "database_version": "27500"}

    return _fake


@pytest.mark.unit
async def test_poll_returns_immediately_when_the_very_first_read_already_changed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _sequenced_fetch(["2026-08-03T00:00:00"]))
    sleep_calls: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    result = await _poll_until_databases_updated_at_changes(
        clamav_module.get_settings(), "2026-08-01T00:00:00", sleep=_fake_sleep
    )

    assert result["databases_updated_at"] == "2026-08-03T00:00:00"
    assert sleep_calls == []  # no waiting needed at all


@pytest.mark.unit
async def test_poll_retries_a_few_times_then_returns_once_it_changes(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        clamav_module,
        "fetch_av_clamav_data",
        _sequenced_fetch(
            ["2026-08-01T00:00:00", "2026-08-01T00:00:00", "2026-08-01T00:00:00", "2026-08-03T00:00:00"]
        ),
    )
    sleep_calls: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    result = await _poll_until_databases_updated_at_changes(
        clamav_module.get_settings(), "2026-08-01T00:00:00", attempts=10, delay_seconds=1.5, sleep=_fake_sleep
    )

    assert result["databases_updated_at"] == "2026-08-03T00:00:00"
    assert sleep_calls == [1.5, 1.5, 1.5]  # 3 unchanged reads before the 4th (changed) one


@pytest.mark.unit
async def test_poll_honestly_returns_the_last_seen_value_if_it_never_changes(
    monkeypatch: pytest.MonkeyPatch,
):
    """Never fabricates a "changed" result — if `databases_updated_at`
    genuinely never differs within the attempt budget (a real slow reload,
    or freshclam finding nothing new), the last real read is returned as-is,
    same value as `before`."""
    monkeypatch.setattr(
        clamav_module, "fetch_av_clamav_data", _sequenced_fetch(["2026-08-01T00:00:00"] * 4)
    )
    sleep_calls: list[float] = []

    async def _fake_sleep(delay: float) -> None:
        sleep_calls.append(delay)

    result = await _poll_until_databases_updated_at_changes(
        clamav_module.get_settings(), "2026-08-01T00:00:00", attempts=4, delay_seconds=1.5, sleep=_fake_sleep
    )

    assert result["databases_updated_at"] == "2026-08-01T00:00:00"
    assert sleep_calls == [1.5, 1.5, 1.5]  # 3 sleeps between the 4 reads, then gives up honestly


@pytest.mark.unit
async def test_poll_treats_a_none_before_baseline_as_a_real_value_to_compare_against(
    monkeypatch: pytest.MonkeyPatch,
):
    """A fresh install / never-reachable-before state has `before=None` —
    the very first successful real read (anything not `None`) must count as
    "changed", not be mistaken for "still absent"."""
    monkeypatch.setattr(clamav_module, "fetch_av_clamav_data", _sequenced_fetch(["2026-08-03T00:00:00"]))

    async def _fake_sleep(delay: float) -> None:
        raise AssertionError("must not sleep: the first read already differs from None")

    result = await _poll_until_databases_updated_at_changes(
        clamav_module.get_settings(), None, sleep=_fake_sleep
    )

    assert result["databases_updated_at"] == "2026-08-03T00:00:00"
