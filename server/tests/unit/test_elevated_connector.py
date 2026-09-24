"""A-36: `elevated.py`'s `elevated_run` — platform dispatch + the honest
ok/cancelled/failed three-way outcome, fully offline (the low-level
subprocess `runner` is injected here, same "fake the transport, exercise
the real parsing logic" technique
packaging/macos/test/test_wazuh_agent_setup.py already uses for its own
`run_privileged_install`'s `runner` parameter) — no real `osascript`/
`pkexec`/`powershell.exe` invocation, and no real OS dialog ever pops
during this test run. The macOS branch's cancelled-vs-failed distinction
is this module's single most important behaviour (see elevated.py's own
docstring) and gets the most coverage here; Windows/Linux get enough
coverage to prove the dispatch and each platform's own documented
exit-code/marker contract, matching the "implemented from documentation,
not live-verified" disclosure already in elevated.py's own docstrings.
"""

import sys
from pathlib import Path

import pytest

import app.services.mcp.security_connectors.elevated as elevated_module
from app.services.mcp.security_connectors.elevated import ElevatedRunResult, elevated_run


def _fake_runner(responses: dict[str, tuple[int, str, str]]):
    """`responses` maps the first argv element (the binary name) to a fixed
    `(returncode, stdout, stderr)` reply — same shape
    test_os_firewall_connector.py's own `_fake_run` helper already uses."""

    async def _run(argv: list[str], *, timeout: float):
        return responses[argv[0]]

    return _run


# ---------------------------------------------------------------------------
# macOS — osascript
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_ok_returns_the_real_command_output(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_runner(argv, *, timeout):
        captured["argv"] = argv
        captured["timeout"] = timeout
        return (0, "scrub-anchor \"com.apple/*\" all fragment reassemble\n", "")

    result = await elevated_run(
        ["pfctl", "-s", "rules"], reason_ru="Прочитать правила", reason_en="Read rules", runner=fake_runner
    )

    assert result == ElevatedRunResult(
        status="ok", stdout='scrub-anchor "com.apple/*" all fragment reassemble\n', stderr=""
    )
    assert captured["argv"][0] == "osascript"
    assert captured["argv"][1] == "-e"
    applescript = captured["argv"][2]
    assert "with administrator privileges" in applescript
    assert "with prompt" in applescript
    # Both languages combined into the one native dialog — see
    # elevated.py's own docstring for why (the server does not know which
    # language the human at THIS machine's keyboard reads).
    assert "Прочитать правила" in applescript
    assert "Read rules" in applescript
    # pfctl's own argv, shell-joined into the one `do shell script` string.
    assert "pfctl -s rules" in applescript


@pytest.mark.unit
async def test_macos_user_cancel_is_reported_as_cancelled_never_failed(monkeypatch: pytest.MonkeyPatch):
    """Confirmed live while building this task (2026-07-23, this dev
    machine): clicking "Cancel" in the real system dialog makes osascript
    exit 1 with stderr containing exactly this text — the DoD's own
    "distinguish cancelled from failed" scenario."""
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")

    async def fake_runner(argv, *, timeout):
        return (1, "", "128:2: execution error: User canceled. (-128)\n")

    result = await elevated_run(
        ["pfctl", "-s", "rules"], reason_ru="r", reason_en="e", runner=fake_runner
    )

    assert result.status == "cancelled"
    assert result.status != "failed"


@pytest.mark.unit
async def test_macos_cancel_marker_matched_case_insensitively(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")

    async def fake_runner(argv, *, timeout):
        return (1, "", "Something something -128 something\n")

    result = await elevated_run(["true"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "cancelled"


@pytest.mark.unit
async def test_macos_real_command_failure_is_reported_as_failed_never_cancelled(
    monkeypatch: pytest.MonkeyPatch,
):
    """A genuine failure of the ELEVATED command itself (not a decline) —
    must never be reported as `cancelled`, the DoD's own "never conflate"
    requirement in the other direction."""
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")

    async def fake_runner(argv, *, timeout):
        return (1, "", "pfctl: some genuine syntax error in ruleset\n")

    result = await elevated_run(["pfctl", "-f", "-"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"
    assert result.status != "cancelled"


@pytest.mark.unit
async def test_macos_missing_osascript_is_reported_as_failed_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")

    async def fake_runner(argv, *, timeout):
        raise FileNotFoundError("osascript not found")

    result = await elevated_run(["pfctl"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


@pytest.mark.unit
async def test_macos_timeout_is_reported_as_failed_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Darwin")

    async def fake_runner(argv, *, timeout):
        raise TimeoutError("did not return in time")

    result = await elevated_run(["pfctl"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Linux — pkexec (NOT verified live, see elevated.py's own docstring)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_linux_ok(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Linux")
    captured: dict = {}

    async def fake_runner(argv, *, timeout):
        captured["argv"] = argv
        return (0, "-A INPUT -j DROP\n", "")

    result = await elevated_run(["iptables", "-S"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result == ElevatedRunResult(status="ok", stdout="-A INPUT -j DROP\n", stderr="")
    assert captured["argv"] == ["pkexec", "iptables", "-S"]


@pytest.mark.unit
async def test_linux_pkexec_126_is_cancelled_per_its_own_documented_exit_code(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Linux")

    async def fake_runner(argv, *, timeout):
        return (126, "", "")

    result = await elevated_run(["iptables", "-S"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "cancelled"


@pytest.mark.unit
async def test_linux_pkexec_other_nonzero_is_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Linux")

    async def fake_runner(argv, *, timeout):
        return (127, "", "pkexec: Authorization could not be obtained\n")

    result = await elevated_run(["iptables", "-S"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


@pytest.mark.unit
async def test_linux_missing_pkexec_is_reported_as_failed_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Linux")

    async def fake_runner(argv, *, timeout):
        raise FileNotFoundError("pkexec not found")

    result = await elevated_run(["iptables", "-S"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Windows — UAC via Start-Process -Verb RunAs (NOT verified live, see
# elevated.py's own docstring)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_windows_ok_reads_back_the_elevated_commands_own_output(monkeypatch: pytest.MonkeyPatch):
    """The elevated `cmd.exe` this module launches redirects its own
    stdout/stderr/exit-code to three temp files (see
    `_elevated_run_windows`'s own docstring for why it cannot pipe them
    back directly) — this fake runner plays that elevated process's role
    by writing those same three files itself, proving the real read-back
    logic (not just the dispatch)."""
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    async def fake_runner(argv, *, timeout):
        script_path = Path(argv[-1])
        tmp_path = script_path.parent
        (tmp_path / "stdout.txt").write_text("Rule Name: Core Networking\n", encoding="utf-8")
        (tmp_path / "stderr.txt").write_text("", encoding="utf-8")
        (tmp_path / "exitcode.txt").write_text("0\n", encoding="utf-8")
        return (0, "", "")

    result = await elevated_run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        reason_ru="r",
        reason_en="e",
        runner=fake_runner,
    )

    assert result.status == "ok"
    assert result.stdout == "Rule Name: Core Networking\n"


@pytest.mark.unit
async def test_windows_uac_decline_marker_is_cancelled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    async def fake_runner(argv, *, timeout):
        return (1, "HRANIX_ELEVATION_CANCELLED\n", "")

    result = await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "cancelled"


@pytest.mark.unit
async def test_windows_inner_command_nonzero_exit_is_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    async def fake_runner(argv, *, timeout):
        script_path = Path(argv[-1])
        tmp_path = script_path.parent
        (tmp_path / "stdout.txt").write_text("", encoding="utf-8")
        (tmp_path / "stderr.txt").write_text("Access is denied.\n", encoding="utf-8")
        (tmp_path / "exitcode.txt").write_text("1\n", encoding="utf-8")
        return (0, "", "")

    result = await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"
    assert "Access is denied" in result.stderr


@pytest.mark.unit
async def test_windows_powershell_level_failure_without_marker_is_failed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    async def fake_runner(argv, *, timeout):
        return (1, "", "some unrelated PowerShell error\n")

    result = await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


@pytest.mark.unit
async def test_windows_missing_powershell_is_reported_as_failed_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "Windows")

    async def fake_runner(argv, *, timeout):
        raise FileNotFoundError("powershell.exe not found")

    result = await elevated_run(["netsh"], reason_ru="r", reason_en="e", runner=fake_runner)

    assert result.status == "failed"


# ---------------------------------------------------------------------------
# Unsupported platform / default (real) runner
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_unsupported_platform_is_reported_as_failed_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(elevated_module.platform, "system", lambda: "PlanNine")

    result = await elevated_run(["whoami"], reason_ru="r", reason_en="e")

    assert result.status == "failed"
    assert "PlanNine" in result.stderr


# A-65-0 (из промпта A-64): единственный тест файла, запускающий реальный
# процесс — но это unix-бинарь /bin/echo, на Windows его не существует
# (ограничение среды; Windows-планировка покрыта остальными тестами файла).
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="запускает unix-бинарь /bin/echo (ограничение среды)",
)
@pytest.mark.unit
async def test_default_runner_executes_a_real_local_command():
    """The one test in this file that runs a REAL subprocess — but a
    plain, unprivileged `/bin/echo`, never an elevation mechanism, so it
    stays a fast, deterministic unit test while still proving
    `_default_runner`'s own real `asyncio.create_subprocess_exec` plumbing
    (decoding, returncode) actually works, not just its callers' mocks."""
    returncode, stdout, stderr = await elevated_module._default_runner(
        ["/bin/echo", "hranix"], timeout=5.0
    )

    assert returncode == 0
    assert stdout == "hranix\n"
    assert stderr == ""
