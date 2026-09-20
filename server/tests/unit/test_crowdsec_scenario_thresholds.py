"""A-43: elevated docker-exec read/write of CrowdSec scenario capacity/
leakspeed — fully offline: `elevated_run` itself is monkeypatched here (same
"inject a fake transport" technique test_os_firewall_elevated.py already
uses), so none of this ever pops a real OS dialog or touches a real
container. Every parsing fixture below is a byte-for-byte excerpt of this
task's own live investigation against the real `hranix-crowdsec` container
(see crowdsec.py's "A-43 addendum" docstring section) — including the
discovery that `ssh-bf.yaml`/`ssh-slow-bf.yaml`/`ssh-time-based-bf.yaml`
each hold TWO YAML documents (a bare `---` separator), not the one the plan
document's own table names.

Live-container coverage (the real DoD click-and-verify loop, including the
mandatory revert-to-5 afterwards) is this task's own report, not an
automated test — there is no way to pop a real Touch ID prompt from CI.
"""

from __future__ import annotations

import pytest

import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecScenarioError,
    read_scenario_thresholds,
    write_scenario_threshold,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult

# A real excerpt (trimmed to the fields this module parses) of `docker exec
# hranix-crowdsec sh -c 'for f in .../*.yaml; do cat "$f"; done'`'s actual
# live output while building this task — see crowdsec.py's "A-43 addendum".
_REAL_READ_OUTPUT = """\
===HRANIX-SCENARIO-FILE:/etc/crowdsec/scenarios/ssh-bf.yaml===
# ssh bruteforce
type: leaky
name: crowdsecurity/ssh-bf
description: "Detect ssh bruteforce"
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
leakspeed: "10s"
capacity: 5
groupby: evt.Meta.source_ip
---
# ssh user-enum
type: leaky
name: crowdsecurity/ssh-bf_user-enum
filter: evt.Meta.log_type == 'ssh_failed-auth'
groupby: evt.Meta.source_ip
leakspeed: 10s
capacity: 5
===HRANIX-SCENARIO-FILE:/etc/crowdsec/scenarios/ssh-generic-test.yaml===
type: trigger
name: crowdsecurity/ssh-generic-test
description:  "Crowdsec Generic Test Scenario: SSH brute force trigger"
filter: "evt.Meta.log_type == 'ssh_failed-auth'"
groupby: evt.Meta.source_ip
===HRANIX-SCENARIO-FILE:/etc/crowdsec/scenarios/ssh-time-based-bf.yaml===
type: conditional
name: crowdsecurity/ssh-time-based-bf
filter: "evt.Meta.service == 'ssh'"
groupby: evt.Meta.source_ip
capacity: -1
condition: |
    let failedAuths = filter(queue.Queue, {#.Meta.log_type == 'ssh_failed-auth'});
    len(failedAuths) >= 4
leakspeed: 2h
"""


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
    """Every test in this file cares about the SHAPE of the elevated
    command, not which `docker` binary this particular CI machine happens
    to have on PATH — pinned once so assertions are deterministic
    regardless of the host running the suite."""
    monkeypatch.setattr(crowdsec_module, "_resolve_docker_binary", lambda: "/usr/local/bin/docker")


# ---------------------------------------------------------------------------
# _parse_scenario_document / _parse_scenario_documents
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_scenario_document_leaky_scenario():
    text = 'type: leaky\nname: crowdsecurity/ssh-bf\nleakspeed: "10s"\ncapacity: 5\n'

    entry = crowdsec_module._parse_scenario_document(text)

    assert entry == {"name": "crowdsecurity/ssh-bf", "type": "leaky", "capacity": 5, "leakspeed": "10s"}


@pytest.mark.unit
def test_parse_scenario_document_trigger_scenario_has_no_capacity_or_leakspeed():
    """A-43's own honesty requirement: `type: trigger` scenarios genuinely
    have no `capacity`/`leakspeed` fields in their real YAML — must come
    back `None`, never a fabricated `0`."""
    text = "type: trigger\nname: crowdsecurity/ssh-generic-test\nfilter: \"...\"\n"

    entry = crowdsec_module._parse_scenario_document(text)

    assert entry == {"name": "crowdsecurity/ssh-generic-test", "type": "trigger", "capacity": None, "leakspeed": None}


@pytest.mark.unit
def test_parse_scenario_document_conditional_scenario_capacity_minus_one():
    """`crowdsecurity/ssh-time-based-bf`'s real `capacity: -1` ("unlimited"
    sentinel, confirmed live) must parse as the real int `-1`, not `None`
    and not be mistaken for a trigger scenario."""
    text = "type: conditional\nname: crowdsecurity/ssh-time-based-bf\ncapacity: -1\nleakspeed: 2h\n"

    entry = crowdsec_module._parse_scenario_document(text)

    assert entry == {
        "name": "crowdsecurity/ssh-time-based-bf",
        "type": "conditional",
        "capacity": -1,
        "leakspeed": "2h",
    }


@pytest.mark.unit
def test_parse_scenario_document_ignores_indented_condition_block_lines():
    """`condition: |` multi-line blocks (real `ssh-time-based-bf.yaml`
    content) are always indented — must never be mis-parsed as a top-level
    `capacity`/`leakspeed`/`type`/`name` field."""
    text = (
        "type: conditional\n"
        "name: crowdsecurity/ssh-time-based-bf\n"
        "condition: |\n"
        "    let failedAuths = filter(queue.Queue, {#.Meta.log_type == 'ssh_failed-auth'});\n"
        "    len(failedAuths) >= 4\n"
        "capacity: -1\n"
        "leakspeed: 2h\n"
    )

    entry = crowdsec_module._parse_scenario_document(text)

    assert entry["capacity"] == -1
    assert entry["leakspeed"] == "2h"


@pytest.mark.unit
def test_parse_scenario_document_no_name_returns_none():
    entry = crowdsec_module._parse_scenario_document("\n\n")

    assert entry is None


@pytest.mark.unit
def test_parse_scenario_documents_splits_a_two_scenario_file():
    """A-43's own live discovery: `ssh-bf.yaml` genuinely holds TWO
    documents (separated by a bare `---`) — `crowdsecurity/ssh-bf` AND
    `crowdsecurity/ssh-bf_user-enum` — both must come back as independent
    rows, both tagged with the SAME file path."""
    content = (
        "type: leaky\nname: crowdsecurity/ssh-bf\ncapacity: 5\nleakspeed: 10s\n"
        "---\n"
        "type: leaky\nname: crowdsecurity/ssh-bf_user-enum\ncapacity: 5\nleakspeed: 10s\n"
    )

    entries = crowdsec_module._parse_scenario_documents("/etc/crowdsec/scenarios/ssh-bf.yaml", content)

    assert [e["name"] for e in entries] == ["crowdsecurity/ssh-bf", "crowdsecurity/ssh-bf_user-enum"]
    assert all(e["file"] == "/etc/crowdsec/scenarios/ssh-bf.yaml" for e in entries)


@pytest.mark.unit
def test_parse_scenario_documents_single_document_file_has_no_trailing_empty_row():
    content = "type: trigger\nname: crowdsecurity/ssh-generic-test\n"

    entries = crowdsec_module._parse_scenario_documents(
        "/etc/crowdsec/scenarios/ssh-generic-test.yaml", content
    )

    assert len(entries) == 1


# ---------------------------------------------------------------------------
# _parse_scenario_files_output — the full multi-file, multi-document shape
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_scenario_files_output_real_live_excerpt():
    entries = crowdsec_module._parse_scenario_files_output(_REAL_READ_OUTPUT)

    by_name = {e["name"]: e for e in entries}
    assert set(by_name) == {
        "crowdsecurity/ssh-bf",
        "crowdsecurity/ssh-bf_user-enum",
        "crowdsecurity/ssh-generic-test",
        "crowdsecurity/ssh-time-based-bf",
    }
    assert by_name["crowdsecurity/ssh-bf"] == {
        "name": "crowdsecurity/ssh-bf",
        "type": "leaky",
        "capacity": 5,
        "leakspeed": "10s",
        "file": "/etc/crowdsec/scenarios/ssh-bf.yaml",
    }
    # Both documents inside ssh-bf.yaml share the same file path.
    assert by_name["crowdsecurity/ssh-bf_user-enum"]["file"] == "/etc/crowdsec/scenarios/ssh-bf.yaml"
    assert by_name["crowdsecurity/ssh-bf_user-enum"]["capacity"] == 5
    # trigger: honestly None, not 0.
    assert by_name["crowdsecurity/ssh-generic-test"]["capacity"] is None
    assert by_name["crowdsecurity/ssh-generic-test"]["leakspeed"] is None
    # conditional: capacity -1 is a real value, not None.
    assert by_name["crowdsecurity/ssh-time-based-bf"]["capacity"] == -1
    assert by_name["crowdsecurity/ssh-time-based-bf"]["leakspeed"] == "2h"


# ---------------------------------------------------------------------------
# _validate_capacity / _validate_leakspeed
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("capacity", [1, 5, 10, -1])
def test_validate_capacity_accepts_positive_ints_and_minus_one(capacity):
    crowdsec_module._validate_capacity(capacity)  # must not raise


@pytest.mark.unit
@pytest.mark.parametrize("capacity", [0, -2, -100])
def test_validate_capacity_rejects_zero_and_other_negatives(capacity):
    with pytest.raises(CrowdSecScenarioError) as exc_info:
        crowdsec_module._validate_capacity(capacity)
    assert exc_info.value.reason == "invalid_capacity"


@pytest.mark.unit
@pytest.mark.parametrize("leakspeed", ["10s", "180s", "60s", "2h", "30m", "1s"])
def test_validate_leakspeed_accepts_digits_plus_unit(leakspeed):
    crowdsec_module._validate_leakspeed(leakspeed)  # must not raise


@pytest.mark.unit
@pytest.mark.parametrize("leakspeed", ["10", "s10", "1.5s", "", "10 s", "10sec", "-5s"])
def test_validate_leakspeed_rejects_everything_else(leakspeed):
    with pytest.raises(CrowdSecScenarioError) as exc_info:
        crowdsec_module._validate_leakspeed(leakspeed)
    assert exc_info.value.reason == "invalid_leakspeed"


# ---------------------------------------------------------------------------
# _scenario_sed_program — the range-scoped sed program itself
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scenario_sed_program_escapes_slash_and_scopes_to_name_through_next_doc_separator():
    program = crowdsec_module._scenario_sed_program("crowdsecurity/ssh-bf", capacity=7, leakspeed="15s")

    assert program.startswith("/^name: crowdsecurity\\/ssh-bf$/,/^---$/{")
    assert "s/^capacity: .*/capacity: 7/" in program
    assert 's/^leakspeed: .*/leakspeed: "15s"/' in program


# ---------------------------------------------------------------------------
# read_scenario_thresholds()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_read_scenario_thresholds_ok_returns_parsed_scenarios(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout=_REAL_READ_OUTPUT), captured=captured),
    )

    result = await read_scenario_thresholds()

    assert result["status"] == "ok"
    names = {s["name"] for s in result["scenarios"]}
    assert "crowdsecurity/ssh-bf" in names
    assert "crowdsecurity/ssh-bf_user-enum" in names
    # ONE elevated call for every file at once, never one per file.
    assert captured["command"][:3] == ["/usr/local/bin/docker", "exec", crowdsec_module.CROWDSEC_CONTAINER_NAME]
    assert "Hranix Shield" in captured["reason_ru"]


@pytest.mark.unit
async def test_read_scenario_thresholds_cancelled_raises_elevation_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await read_scenario_thresholds()

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_read_scenario_thresholds_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        crowdsec_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="docker: command not found")),
    )

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await read_scenario_thresholds()

    assert exc_info.value.reason == "elevation_failed"


# ---------------------------------------------------------------------------
# write_scenario_threshold()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_write_scenario_threshold_validates_before_ever_calling_elevated_run(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=0, leakspeed="10s")
    assert exc_info.value.reason == "invalid_capacity"

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=5, leakspeed="not-a-duration")
    assert exc_info.value.reason == "invalid_leakspeed"

    assert calls == []  # never sent to elevated_run at all


@pytest.mark.unit
async def test_write_scenario_threshold_ok_runs_write_script_then_a_separate_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    readback_output = _REAL_READ_OUTPUT.replace('leakspeed: "10s"\ncapacity: 5', 'leakspeed: "15s"\ncapacity: 7')
    calls: list[dict] = []

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        entry = {"command": command, "reason_ru": reason_ru, "reason_en": reason_en}
        if len(calls) == 0:
            # Read the real script file WHILE it still exists — `elevated_run`
            # is called from inside a `with tempfile.TemporaryDirectory()`
            # block (see `write_scenario_threshold`), which deletes the
            # directory the instant this call returns — same technique
            # test_os_firewall_elevated.py's own block_all_incoming test uses.
            entry["script_text"] = open(command[1], encoding="utf-8").read()
            calls.append(entry)
            return ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_WRITE_OK\n")
        calls.append(entry)
        return ElevatedRunResult(status="ok", stdout=readback_output)

    monkeypatch.setattr(crowdsec_module, "elevated_run", fake_elevated_run)

    result = await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=7, leakspeed="15s")

    assert result == {
        "status": "ok",
        "scenario": {
            "name": "crowdsecurity/ssh-bf",
            "type": "leaky",
            "capacity": 7,
            "leakspeed": "15s",
            "file": "/etc/crowdsec/scenarios/ssh-bf.yaml",
        },
    }
    # Exactly two elevated calls: the write+restart script, then a SEPARATE
    # readback — never trusting the script's own clean exit as proof.
    assert len(calls) == 2
    assert calls[0]["command"][0] == "/bin/bash"
    assert calls[1]["command"][:3] == ["/usr/local/bin/docker", "exec", crowdsec_module.CROWDSEC_CONTAINER_NAME]
    # The write script itself is a real script file containing sed + a
    # conditional restart — proves the actual commands (not just the
    # dispatch) are what gets run elevated, same technique
    # test_os_firewall_elevated.py's own block_all_incoming test uses.
    script_text = calls[0]["script_text"]
    assert "sed -i" in script_text
    # The resolved ABSOLUTE docker path is used throughout, not the bare
    # `docker` word — `_resolve_docker_binary`'s own "elevated PATH may not
    # include /usr/local/bin" rationale.
    assert script_text.count("/usr/local/bin/docker") == 2  # once for exec, once for compose
    assert "compose -f" in script_text
    assert "restart crowdsec" in script_text
    assert "HRANIX_SCENARIO_WRITE_OK" in script_text


@pytest.mark.unit
async def test_write_scenario_threshold_not_found_raises_scenario_not_found_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    write_result = ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_NOT_FOUND\n")
    run, calls = _queued_elevated_run([write_result])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/does-not-exist", capacity=5, leakspeed="10s")

    assert exc_info.value.reason == "scenario_not_found"
    assert len(calls) == 1  # no readback attempted — nothing was written


@pytest.mark.unit
async def test_write_scenario_threshold_trigger_scenario_raises_scenario_has_no_threshold(
    monkeypatch: pytest.MonkeyPatch,
):
    """The honest regression case: a `type: trigger` scenario must be
    rejected server-side too, never silently accepted just because the
    client sent a request (defense in depth, mirrors this project's other
    write endpoints)."""
    write_result = ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_NO_THRESHOLD\n")
    run, calls = _queued_elevated_run([write_result])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-generic-test", capacity=5, leakspeed="10s")

    assert exc_info.value.reason == "scenario_has_no_threshold"
    assert len(calls) == 1  # no readback attempted — nothing was written


@pytest.mark.unit
async def test_write_scenario_threshold_readback_mismatch_never_reports_a_fake_success(
    monkeypatch: pytest.MonkeyPatch,
):
    """The DoD's own core discipline: a `docker compose restart` that exits
    zero is NOT proof the new value is genuinely applied — a fresh read
    showing the OLD value must raise, never be reported as success."""
    write_result = ElevatedRunResult(status="ok", stdout="HRANIX_SCENARIO_WRITE_OK\n")
    stale_readback = ElevatedRunResult(status="ok", stdout=_REAL_READ_OUTPUT)  # still capacity 5/leakspeed 10s
    run, calls = _queued_elevated_run([write_result, stale_readback])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=7, leakspeed="15s")

    assert exc_info.value.reason == "readback_mismatch"
    assert len(calls) == 2  # the readback WAS attempted, it just did not confirm the change


@pytest.mark.unit
async def test_write_scenario_threshold_cancelled_raises_elevation_cancelled_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([ElevatedRunResult(status="cancelled")])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=7, leakspeed="15s")

    assert exc_info.value.reason == "elevation_cancelled"
    assert len(calls) == 1


@pytest.mark.unit
async def test_write_scenario_threshold_failed_raises_elevation_failed_without_a_readback(
    monkeypatch: pytest.MonkeyPatch,
):
    run, calls = _queued_elevated_run([ElevatedRunResult(status="failed", stderr="boom")])
    monkeypatch.setattr(crowdsec_module, "elevated_run", run)

    with pytest.raises(CrowdSecScenarioError) as exc_info:
        await write_scenario_threshold("crowdsecurity/ssh-bf", capacity=7, leakspeed="15s")

    assert exc_info.value.reason == "elevation_failed"
    assert len(calls) == 1
