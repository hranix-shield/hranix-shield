"""A-45: elevated docker-exec check+apply of CrowdSec scenario/hub updates —
fully offline: `elevated_run` itself is monkeypatched here (same "inject a
fake transport" technique test_crowdsec_scenario_thresholds.py's A-43 tests
already use), so none of this ever pops a real OS dialog or touches a real
container.

Every fixture below is a byte-for-byte excerpt of this task's own live
investigation against the real `hranix-crowdsec` container (see crowdsec.py's
"A-45 addendum" docstring section) — including BOTH the "real upgrades
queued" and "already current" forms of `cscli hub upgrade --dry-run`'s own
"Action plan:" output, confirmed live on the SAME container before and after
a real (non-dry-run) `cscli hub upgrade` was applied.

Live-container coverage (the real DoD click-and-verify loop, including
applying a genuine upgrade and confirming the readback) is this task's own
report, not an automated test — there is no way to pop a real Touch ID prompt
from CI.
"""

from __future__ import annotations

import json

import pytest

import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecScenarioError,
    apply_scenario_updates,
    check_scenario_updates,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult

# Real `cscli hub update && cscli hub upgrade --dry-run` stdout while this
# container genuinely had pending upgrades (see crowdsec.py's "A-45
# addendum" docstring section) — the diagnostic "X is outdated because of
# Y"/"level=info ..." noise confirmed live to be on STDERR, so it is
# deliberately NOT part of this stdout-only fixture.
_REAL_PLAN_WITH_UPGRADES = """\
Action plan:
📥 download
 collections: crowdsecurity/sshd (0.9 -> 0.9), crowdsecurity/whitelist-good-actors (0.4 -> 0.4)
 scenarios: crowdsecurity/ssh-time-based-bf (0.2 -> 0.3)
 postoverflows: crowdsecurity/rdns (0.3 -> 0.4)
🔄 check & update data files

Dry run, no action taken.
"""

# Real output from the SAME container, same command, AFTER a genuine
# (non-dry-run) `cscli hub upgrade` had already been applied — confirmed
# live: the `🔄 check & update data files` line alone is NOT a "nothing
# to do" signal by itself, it is present in BOTH fixtures.
_REAL_PLAN_ALREADY_CURRENT = """\
Action plan:
🔄 check & update data files

Dry run, no action taken.
"""

# A real (trimmed) excerpt of `cscli hub list -o json`'s stdout while two
# items were genuinely outdated (see crowdsec.py's "A-45 addendum").
_REAL_HUB_LIST_WITH_OUTDATED = json.dumps(
    {
        "collections": [
            {"name": "crowdsecurity/linux", "local_version": "0.4", "status": "enabled"},
            {"name": "crowdsecurity/sshd", "local_version": "0.9", "status": "enabled,update-available"},
        ],
        "scenarios": [
            {
                "name": "crowdsecurity/ssh-time-based-bf",
                "local_version": "0.2",
                "status": "enabled,update-available",
            },
        ],
        "postoverflows": [
            {"name": "crowdsecurity/rdns", "local_version": "0.3", "status": "enabled,update-available"},
        ],
        "parsers": [],
        "contexts": [],
        "appsec-configs": [],
        "appsec-rules": [],
    }
)

_REAL_HUB_LIST_ALL_CURRENT = json.dumps(
    {
        "collections": [
            {"name": "crowdsecurity/linux", "local_version": "0.4", "status": "enabled"},
            {"name": "crowdsecurity/sshd", "local_version": "0.9", "status": "enabled"},
        ],
        "scenarios": [
            {"name": "crowdsecurity/ssh-time-based-bf", "local_version": "0.3", "status": "enabled"},
        ],
        "postoverflows": [
            {"name": "crowdsecurity/rdns", "local_version": "0.4", "status": "enabled"},
        ],
        "parsers": [],
        "contexts": [],
        "appsec-configs": [],
        "appsec-rules": [],
    }
)


def _fake_elevated_run(result: ElevatedRunResult, *, captured: dict | None = None):
    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        if captured is not None:
            captured["command"] = command
            captured["reason_ru"] = reason_ru
            captured["reason_en"] = reason_en
        return result

    return _run


def _queued_elevated_run(results: list[ElevatedRunResult]):
    calls: list[dict] = []

    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        calls.append({"command": command, "reason_ru": reason_ru, "reason_en": reason_en})
        return results[len(calls) - 1]

    return _run, calls


@pytest.fixture(autouse=True)
def _fixed_docker_binary(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(crowdsec_module, "_resolve_docker_binary", lambda: "/usr/local/bin/docker")


# ---------------------------------------------------------------------------
# _scenario_update_plan_has_upgrades — the honest "is there really something
# to apply" signal, on the two REAL live sample outputs.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_plan_has_upgrades_true_on_real_output_with_real_version_bumps():
    assert crowdsec_module._scenario_update_plan_has_upgrades(_REAL_PLAN_WITH_UPGRADES) is True


@pytest.mark.unit
def test_plan_has_upgrades_false_on_real_already_current_output():
    """The DoD's own core warning: the `🔄 check & update data files` line
    alone must NOT be mistaken for "there is something to apply" — it is
    present in this fixture too, and must still read as `False`."""
    assert crowdsec_module._scenario_update_plan_has_upgrades(_REAL_PLAN_ALREADY_CURRENT) is False


@pytest.mark.unit
def test_plan_has_upgrades_false_on_empty_string():
    assert crowdsec_module._scenario_update_plan_has_upgrades("") is False


# ---------------------------------------------------------------------------
# _build_apply_scenario_updates_script — post-merge review fix (Finding 1):
# the restart must be UNCONDITIONAL, never gated on the arrow-heuristic text
# match, since only the dry-run form of `cscli hub upgrade`'s stdout was
# ever confirmed live to use that exact format.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_apply_script_restarts_unconditionally_not_gated_on_arrow_match():
    script_text = crowdsec_module._build_apply_scenario_updates_script("/usr/local/bin/docker")

    assert "restart crowdsec" in script_text
    assert "HRANIX_SCENARIO_UPDATES_APPLIED" in script_text
    assert "HRANIX_SCENARIO_UPDATES_NOOP" in script_text
    # The restart line must appear BEFORE the `if echo ... -> ...` arrow
    # check — i.e. it always runs, regardless of which branch the arrow
    # check takes (that check only decides which marker to print).
    assert script_text.index("restart crowdsec") < script_text.index("if echo")


# ---------------------------------------------------------------------------
# _parse_hub_list_outdated
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_hub_list_outdated_finds_every_update_available_item_across_categories():
    outdated = crowdsec_module._parse_hub_list_outdated(_REAL_HUB_LIST_WITH_OUTDATED)

    assert set(outdated) == {
        "crowdsecurity/sshd",
        "crowdsecurity/ssh-time-based-bf",
        "crowdsecurity/rdns",
    }


@pytest.mark.unit
def test_parse_hub_list_outdated_empty_when_all_current():
    assert crowdsec_module._parse_hub_list_outdated(_REAL_HUB_LIST_ALL_CURRENT) == []


@pytest.mark.unit
def test_parse_hub_list_outdated_never_crashes_on_unparseable_output():
    result = crowdsec_module._parse_hub_list_outdated("not json at all")

    assert result  # honestly non-empty (never silently "nothing outdated")
    assert isinstance(result, list)


@pytest.mark.unit
def test_parse_hub_list_outdated_never_crashes_on_unexpected_json_shape():
    result = crowdsec_module._parse_hub_list_outdated(json.dumps([1, 2, 3]))

    assert result
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# check_scenario_updates()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_check_scenario_updates_ok_with_real_upgrades(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["reason_ru"] = reason_ru
        captured["reason_en"] = reason_en
        captured["timeout"] = timeout
        return ElevatedRunResult(status="ok", stdout=_REAL_PLAN_WITH_UPGRADES)

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)

    result = await check_scenario_updates()

    assert result["status"] == "ok"
    assert result["has_upgrades"] is True
    # The raw output is returned VERBATIM — no re-parsing into a structured
    # shape (A-36's own "show the real tool output" discipline).
    assert result["plan"] == _REAL_PLAN_WITH_UPGRADES
    assert captured["command"][:3] == ["/usr/local/bin/docker", "exec", crowdsec_module.CROWDSEC_CONTAINER_NAME]
    assert "hub update" in captured["command"][-1]
    assert "hub upgrade --dry-run" in captured["command"][-1]
    assert "Hranix Shield" in captured["reason_ru"]
    # Post-merge review fix (Finding 6): this is a real network fetch
    # against hub.crowdsec.net, not a purely local docker action — it must
    # not rely on elevated_run's default 120s timeout.
    assert captured["timeout"] == crowdsec_module._SCENARIO_UPDATES_ELEVATED_TIMEOUT
    assert captured["timeout"] > 120.0


@pytest.mark.unit
async def test_check_scenario_updates_ok_already_current(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout=_REAL_PLAN_ALREADY_CURRENT)),
    )

    result = await check_scenario_updates()

    assert result["status"] == "ok"
    assert result["has_upgrades"] is False
    assert result["plan"] == _REAL_PLAN_ALREADY_CURRENT


@pytest.mark.unit
async def test_check_scenario_updates_cancelled_raises_elevation_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await check_scenario_updates()

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_check_scenario_updates_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="docker: command not found")),
    )

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await check_scenario_updates()

    assert exc_info.value.reason == "elevation_failed"


# ---------------------------------------------------------------------------
# apply_scenario_updates()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_apply_scenario_updates_ok_runs_apply_script_then_a_separate_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[dict] = []

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        entry = {"command": command, "reason_ru": reason_ru, "reason_en": reason_en, "timeout": timeout}
        if len(calls) == 0:
            # Read the real script file WHILE it still exists — same
            # technique test_crowdsec_scenario_thresholds.py's A-43 write
            # test already uses (elevated_run is called from inside a
            # `with tempfile.TemporaryDirectory()` block).
            entry["script_text"] = open(command[1], encoding="utf-8").read()
            calls.append(entry)
            return ElevatedRunResult(status="ok", stdout=_REAL_PLAN_WITH_UPGRADES + "HRANIX_SCENARIO_UPDATES_APPLIED\n")
        calls.append(entry)
        return ElevatedRunResult(status="ok", stdout=_REAL_HUB_LIST_ALL_CURRENT)

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)

    result = await apply_scenario_updates()

    assert result["status"] == "ok"
    assert result["applied"] is True
    # Post-merge review fix (Finding 3): the internal sentinel marker line
    # must never leak into the operator-facing plan text.
    assert result["plan"] == _REAL_PLAN_WITH_UPGRADES.rstrip("\n")
    assert "HRANIX_SCENARIO_UPDATES_APPLIED" not in result["plan"]
    # Exactly two elevated calls: the apply(+unconditional restart) script,
    # then a SEPARATE readback — never trusting the script's own clean exit
    # as proof.
    assert len(calls) == 2
    assert calls[0]["command"][0] == "/bin/bash"
    assert calls[1]["command"][:3] == ["/usr/local/bin/docker", "exec", crowdsec_module.CROWDSEC_CONTAINER_NAME]
    assert "hub list -o json" in calls[1]["command"][-1]
    # Post-merge review fix (Finding 6): the apply script's own elevated_run
    # (real network fetch, `cscli hub upgrade`) gets the longer, network-
    # aware timeout — unlike the readback below (`cscli hub list -o json`
    # is a purely local read, same as every other elevated call in this
    # module, so it keeps elevated_run's default).
    assert calls[0]["timeout"] == crowdsec_module._SCENARIO_UPDATES_ELEVATED_TIMEOUT
    assert calls[0]["timeout"] > 120.0
    assert calls[1]["timeout"] == 120.0

    script_text = calls[0]["script_text"]
    assert "cscli hub upgrade" in script_text
    assert "--dry-run" not in script_text  # the REAL install, never the preview flag
    assert script_text.count("/usr/local/bin/docker") == 2  # once for exec, once for compose
    assert "compose -f" in script_text
    assert "restart crowdsec" in script_text
    assert "HRANIX_SCENARIO_UPDATES_APPLIED" in script_text
    assert "HRANIX_SCENARIO_UPDATES_NOOP" in script_text
    # Post-merge review fix (Finding 1): restart is unconditional — it must
    # run before the arrow-heuristic `if` branch, not inside it.
    assert script_text.index("restart crowdsec") < script_text.index("if echo")


@pytest.mark.unit
async def test_apply_scenario_updates_noop_when_nothing_to_install(monkeypatch: pytest.MonkeyPatch):
    """Honest non-error outcome: the apply script itself decided (via the
    SAME arrow-based signal `check_scenario_updates` uses) that there was
    nothing real to install — e.g. a race with another operator/process.
    The restart still runs unconditionally either way (post-merge review
    fix, Finding 1) — only the informational `applied` flag is honestly
    `False` here; this must NOT raise."""
    calls: list[dict] = []

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        calls.append({"command": command})
        if len(calls) == 1:
            return ElevatedRunResult(status="ok", stdout=_REAL_PLAN_ALREADY_CURRENT + "HRANIX_SCENARIO_UPDATES_NOOP\n")
        return ElevatedRunResult(status="ok", stdout=_REAL_HUB_LIST_ALL_CURRENT)

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)

    result = await apply_scenario_updates()

    assert result["status"] == "ok"
    assert result["plan"] == _REAL_PLAN_ALREADY_CURRENT.rstrip("\n")
    assert "HRANIX_SCENARIO_UPDATES_NOOP" not in result["plan"]
    assert result["applied"] is False
    assert len(calls) == 2  # readback still happens even on a NOOP


@pytest.mark.unit
async def test_apply_scenario_updates_readback_mismatch_never_reports_a_fake_success(
    monkeypatch: pytest.MonkeyPatch,
):
    """The DoD's own core discipline: a restart that exits zero is NOT proof
    the new versions are genuinely active — a fresh `cscli hub list -o json`
    still showing an outdated item must raise, never be reported as
    success."""
    calls: list[dict] = []

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        calls.append({"command": command})
        if len(calls) == 1:
            return ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_UPDATES_APPLIED\n")
        return ElevatedRunResult(status="ok", stdout=_REAL_HUB_LIST_WITH_OUTDATED)  # still outdated!

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await apply_scenario_updates()

    assert exc_info.value.reason == "readback_mismatch"
    assert len(calls) == 2  # the readback WAS attempted, it just did not confirm


@pytest.mark.unit
async def test_apply_scenario_updates_unexpected_marker_raises_elevation_failed_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([ElevatedRunResult(status="ok", stdout="something unexpected\n")])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await apply_scenario_updates()

    assert exc_info.value.reason == "elevation_failed"
    assert len(calls) == 1  # no readback attempted — the write itself was not understood


@pytest.mark.unit
async def test_apply_scenario_updates_cancelled_raises_elevation_cancelled_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([ElevatedRunResult(status="cancelled")])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await apply_scenario_updates()

    assert exc_info.value.reason == "elevation_cancelled"
    assert len(calls) == 1


@pytest.mark.unit
async def test_apply_scenario_updates_failed_raises_elevation_failed_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([ElevatedRunResult(status="failed", stderr="boom")])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await apply_scenario_updates()

    assert exc_info.value.reason == "elevation_failed"
    assert len(calls) == 1
