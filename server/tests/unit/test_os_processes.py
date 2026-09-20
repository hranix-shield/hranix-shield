"""A-52: `os_processes.terminate_process` — the network console's «Завершить
процесс» action. Same offline `elevated_run` monkeypatching technique
tests/unit/test_os_firewall_blocked_ports.py already uses for A-37 — none
of this pops a real OS dialog and none of it depends on which OS the test
suite itself runs on for the SCRIPT-BUILDING tests.

The one thing that genuinely CANNOT be faked here — whether a real `ps`/
`kill` on THIS actual machine correctly refuses to signal a process whose
name no longer matches — is covered separately, live, against a real
short-lived subprocess this test suite spawns itself (no elevation
involved: the identity CHECK is exercised by running the generated script
body directly, not through `elevated_run`/a real OS password prompt), see
the "live" tests at the bottom of this file.
"""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

import app.services.mcp.security_connectors.os_processes as os_processes_module
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from app.services.mcp.security_connectors.os_processes import (
    OSProcessError,
    terminate_process,
)


def _fake_elevated_run(result: ElevatedRunResult, *, captured: dict | None = None):
    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        if captured is not None:
            captured["command"] = command
            captured["reason_ru"] = reason_ru
            captured["reason_en"] = reason_en
        return result

    return _run


# ---------------------------------------------------------------------------
# Input validation — rejected before any script is even built.
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize("bad_pid", [0, -1, -12345])
async def test_terminate_process_rejects_a_non_positive_pid(bad_pid, monkeypatch: pytest.MonkeyPatch):
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_processes_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(bad_pid, "sleep")

    assert exc_info.value.reason == "invalid_pid"
    assert called["count"] == 0


@pytest.mark.unit
async def test_terminate_process_rejects_an_empty_expected_name(monkeypatch: pytest.MonkeyPatch):
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_processes_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(1234, "")

    assert exc_info.value.reason == "invalid_pid"
    assert called["count"] == 0


# ---------------------------------------------------------------------------
# _build_macos_linux_terminate_script — the identity-check-then-kill body.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_macos_linux_script_checks_identity_before_kill():
    script = os_processes_module._build_macos_linux_terminate_script(1234, "sleep")

    assert "ps -p 1234 -o comm=" in script
    assert "kill -TERM 1234" in script
    assert os_processes_module._IDENTITY_MISMATCH_MARKER in script
    # The identity check must appear BEFORE the kill line — never the
    # reverse, that would defeat the entire point of this module.
    assert script.index("if [") < script.index("kill -TERM")


@pytest.mark.unit
def test_macos_linux_script_shell_quotes_the_expected_name():
    """A process name is normally just a bare word, but this function must
    not assume that — `shlex.quote` protects against a name containing
    shell metacharacters regardless of how implausible that is in
    practice (defense in depth, same standard os_firewall.py's own
    IP/port scripts already hold themselves to)."""
    script = os_processes_module._build_macos_linux_terminate_script(1234, "weird; rm -rf /")

    assert "'weird; rm -rf /'" in script


# ---------------------------------------------------------------------------
# terminate_process() — per-platform elevated dispatch
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_linux_terminate_runs_the_script_via_bin_bash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["reason_ru"] = reason_ru
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_processes_module, "elevated_run", fake_elevated_run)

    result = await terminate_process(4321, "python3")

    assert result == {"status": "ok", "pid": 4321, "terminated": True}
    assert captured["command"][0] == "/bin/bash"
    assert "python3" in captured["reason_ru"]
    assert "4321" in captured["reason_ru"]
    assert "kill -TERM 4321" in captured["script_text"]


@pytest.mark.unit
async def test_terminate_process_cancelled_raises_elevation_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_processes_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(4321, "python3")

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_terminate_process_identity_mismatch_is_distinguished_from_a_generic_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    """The whole point of this module: a script failure that specifically
    carries the identity-mismatch marker must map to
    `process_identity_mismatch`, NOT the generic `elevation_failed` —
    these mean very different things to an operator (see
    os_processes.py's own module docstring)."""
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "Darwin")
    marker = os_processes_module._IDENTITY_MISMATCH_MARKER
    monkeypatch.setattr(
        os_processes_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(status="failed", stderr=f"{marker}: expected python3, found totally_different")
        ),
    )

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(4321, "python3")

    assert exc_info.value.reason == "process_identity_mismatch"


@pytest.mark.unit
async def test_terminate_process_generic_script_failure_raises_elevation_failed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_processes_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="kill: no such process")),
    )

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(4321, "python3")

    assert exc_info.value.reason == "elevation_failed"


@pytest.mark.unit
async def test_windows_terminate_uses_stop_process_and_strips_exe_suffix(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_processes_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await terminate_process(4321, "notepad.exe")

    assert captured["command"][0] == "powershell.exe"
    ps_command = captured["command"][-1]
    assert "Stop-Process -Id 4321" in ps_command
    assert "Get-Process -Id 4321" in ps_command
    assert "notepad" in ps_command


@pytest.mark.unit
async def test_terminate_process_unsupported_platform_raises_not_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_processes_module.platform, "system", lambda: "PlanNine")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_processes_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSProcessError) as exc_info:
        await terminate_process(4321, "python3")

    assert exc_info.value.reason == "not_configured"
    assert called["count"] == 0


# ---------------------------------------------------------------------------
# Live tests — the generated script's own BODY run for real (no elevation,
# no real OS password prompt: `elevated_run` is not involved here at all,
# only bash+ps+kill against a real disposable subprocess this test spawns
# and owns). macOS/Linux only (`sys.platform`) — this is exactly the "one
# real thing worth proving live" the A-30…A-54 план-спецификация's own DoD
# calls for regarding the PID-reuse race protection.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="script targets macOS/Linux's ps+kill, not Windows")
def test_live_script_terminates_a_real_process_when_the_name_matches():
    proc = subprocess.Popen(["sleep", "20"])
    try:
        time.sleep(0.2)  # let it actually start
        script = os_processes_module._build_macos_linux_terminate_script(proc.pid, "sleep")
        result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=5)

        assert result.returncode == 0, result.stderr
        time.sleep(0.3)
        assert proc.poll() is not None, "process should have been terminated"
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.skipif(sys.platform == "win32", reason="script targets macOS/Linux's ps+kill, not Windows")
def test_live_script_refuses_to_kill_when_the_name_does_not_match():
    """The actual race-condition protection, proven against a real PID —
    not a mock — the same live proof the план-спецификация's own DoD names
    explicitly."""
    proc = subprocess.Popen(["sleep", "20"])
    try:
        time.sleep(0.2)
        script = os_processes_module._build_macos_linux_terminate_script(proc.pid, "totally_wrong_name")
        result = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True, timeout=5)

        assert result.returncode != 0
        assert os_processes_module._IDENTITY_MISMATCH_MARKER in result.stderr
        assert proc.poll() is None, "process must NOT have been touched"
    finally:
        if proc.poll() is None:
            proc.kill()
