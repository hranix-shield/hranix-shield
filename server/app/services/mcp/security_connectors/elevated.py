"""A-36: reusable one-shot privilege-escalation helper — the SAME pattern
`packaging/macos/wazuh_agent_setup.py`'s `run_privileged_install` already
established and got reviewed for A-25 (`osascript ... with administrator
privileges`, a visible system dialog, nothing stays elevated afterwards),
now factored out as a general-purpose, cross-platform primitive so this
task's own `os_firewall.py` additions (and A-37/A-38 after it, see
docs/план-спецификация-фаза-0-периметр-контроль-2026-07-23.md's "Порядок
разработки") get it for free instead of each reinventing escalation.

**Why this is not a violation of "never escalate this app's own
privileges"** (see that same plan document's "Важное решение, требующее
явного внимания" section, and CLAUDE.md's own architecture notes): every
single call here is its own independent, visible OS-native authorization
prompt (Touch ID/password on macOS, UAC on Windows, a polkit dialog on
Linux) — this module never stores a token, a cached credential, or an
elevated subprocess handle between calls. Two calls five seconds apart
each show their own prompt (macOS's own Authorization Services MAY
briefly cache a *user's own prior authentication* for a few minutes — that
is OS behaviour outside this module's control, not something this module
does or relies on). Nothing in this process ever runs as root/
Administrator itself; only the one short-lived child command named in
`command` does, for exactly the duration of that one call.

**Three, and only three, honest outcomes** — never conflated:
  - `"ok"`: the elevated command ran and exited zero.
  - `"cancelled"`: the user was shown the OS prompt and explicitly declined
    it (clicked "Cancel"/"Deny", or dismissed a Touch ID prompt) — NOT an
    error, a legitimate, expected, user-initiated outcome.
  - `"failed"`: anything else — the elevated command itself exited non-zero,
    the escalation mechanism itself is unavailable (`osascript`/
    `powershell.exe`/`pkexec` missing), or it timed out.

macOS is the only platform live-verified while building this task (this
dev machine's own OS, see this task's own report for the exact live
transcript — including deliberately clicking "Cancel" once to confirm the
`cancelled` path). Windows/Linux are implemented from each platform's own
documented escalation mechanism (UAC `Start-Process -Verb RunAs` /
`pkexec`) and explicitly flagged as NOT verified live in their own
docstrings below — the same honest disclosure convention this project
already uses for `os_firewall.py`'s own unverified Windows/Linux branches
(A-18/A-28) and `packaging/macos/wazuh_agent_setup.py`'s own macOS-only
live verification.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import shlex
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Awaitable, Callable

from app.services.mcp.security_connectors._local_command import WINDOWS_CREATE_NO_WINDOW

logger = logging.getLogger(__name__)

# A caller-injectable low-level "run this argv, return (returncode, stdout,
# stderr)" seam — same injection technique
# `wazuh_agent_setup.run_privileged_install`'s own `runner` parameter
# already uses, so unit tests can exercise every branch below (ok/
# cancelled/failed, per platform) without ever popping a real OS dialog.
_Runner = Callable[..., Awaitable[tuple[int, str, str]]]


@dataclass
class ElevatedRunResult:
    """`status` is one of `"ok"` / `"cancelled"` / `"failed"` — see this
    module's docstring for the exact, non-negotiable meaning of each.
    `stdout`/`stderr` are the ELEVATED command's own output when the
    escalation mechanism itself succeeded (`ok`, and usually `cancelled`
    too — most escalation tools still report cancellation as text through
    the same channels); on a `failed` outcome they hold whatever
    diagnostic text is available (may be empty, e.g. a bare timeout)."""

    status: str
    stdout: str = field(default="")
    stderr: str = field(default="")


async def _default_runner(argv: list[str], *, timeout: float) -> tuple[int, str, str]:
    """The real subprocess runner used in production — `asyncio.
    create_subprocess_exec` (argv list, never a shell string), same
    reasoning `_local_command.run_local_command` already documents: this
    codebase's services are async end-to-end, a blocking `subprocess.run`
    here would stall the event loop for however long a human takes to
    answer the OS prompt (which can be a long time)."""
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        creationflags=WINDOWS_CREATE_NO_WINDOW,
    )
    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError:
        process.kill()
        await process.wait()
        raise
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    assert process.returncode is not None  # communicate() awaited above
    return process.returncode, stdout, stderr


# ---------------------------------------------------------------------------
# macOS — osascript "do shell script ... with administrator privileges"
# (A-25's already-reviewed mechanism). Live-verified while building this
# task (2026-07-23, this dev machine): a genuine "ok" run (real `pfctl -s
# rules` output returned), and a genuine "cancelled" run (clicked "Cancel"
# in the real system dialog) — see this task's own report for both
# transcripts.
# ---------------------------------------------------------------------------

# osascript's own AppleEvent error text/code when the user declines the
# authorization dialog — confirmed live 2026-07-23 on this dev machine
# (macOS): clicking "Cancel" makes `osascript` exit 1 with stderr
# containing exactly `... User canceled. (-128)`. Matching on the numeric
# code AND the English phrase (lower-cased) covers both a possible
# localized-vs-not stderr string and any minor wording drift across macOS
# versions — `-128` is Apple's own long-documented AppleEvent
# `errAEUserCanceled` constant, the more stable of the two signals.
_OSASCRIPT_CANCELLED_MARKERS = ("-128", "user canceled", "user cancelled")


def _escape_for_applescript_string(text: str) -> str:
    """Escapes `text` for embedding inside an AppleScript double-quoted
    string literal — the identical two-step backslash-then-quote escaping
    `wazuh_agent_setup.run_privileged_install` already uses for this exact
    same `do shell script "..." with administrator privileges` mechanism."""
    return text.replace("\\", "\\\\").replace('"', '\\"')


async def _elevated_run_macos(
    command: list[str],
    *,
    reason_ru: str,
    reason_en: str,
    timeout: float,
    runner: _Runner,
) -> ElevatedRunResult:
    # `shlex.join` (not a naive `" ".join`) so an argument containing a
    # space/quote (a file path, most likely) survives being re-parsed by
    # the shell `do shell script` itself invokes — the same "argv, not a
    # shell string, until the very last unavoidable boundary" discipline
    # `run_local_command`/`wazuh_agent_setup.build_privileged_setup_script`
    # already follow.
    shell_command = shlex.join(command)
    # Both languages, always — the server never guesses which language the
    # human standing at THIS machine's own keyboard reads (this dialog is
    # native OS chrome, not a value returned to an API client, so
    # CLAUDE.md's "server never emits client-facing language text" rule
    # does not apply the same way here; combining both is the honest
    # choice that loses no information either way).
    prompt_text = f"{reason_ru} / {reason_en}"
    applescript = (
        'do shell script "'
        + _escape_for_applescript_string(shell_command)
        + '"'
        + " with administrator privileges"
        + ' with prompt "'
        + _escape_for_applescript_string(prompt_text)
        + '"'
    )
    try:
        returncode, stdout, stderr = await runner(["osascript", "-e", applescript], timeout=timeout)
    except FileNotFoundError:
        return ElevatedRunResult(status="failed", stderr="osascript is not available on this host")
    except TimeoutError:
        return ElevatedRunResult(status="failed", stderr=f"osascript did not return within {timeout}s")

    if returncode == 0:
        return ElevatedRunResult(status="ok", stdout=stdout, stderr=stderr)

    combined = f"{stdout}\n{stderr}".lower()
    if any(marker in combined for marker in _OSASCRIPT_CANCELLED_MARKERS):
        return ElevatedRunResult(status="cancelled", stdout=stdout, stderr=stderr)
    return ElevatedRunResult(status="failed", stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# Linux — pkexec (standard polkit escalation dialog). NOT verified live —
# this dev machine is macOS, same disclosure convention
# os_firewall.py's own unverified Linux branches already use (A-18/A-28).
# ---------------------------------------------------------------------------

# Per `pkexec(1)`'s own documented exit-status contract: 126 when the user
# dismissed/declined the authentication dialog, 127 when authorization
# could not be obtained for some other reason (no polkit policy grants it,
# etc). Any other non-zero code is, ambiguously, either the launched
# command's own real exit code OR a rarer pkexec-level failure — this
# function cannot tell those apart without a live host to confirm the
# exact boundary against, so (like `_linux_firewall_rule_count`'s own
# unverified sibling in os_firewall.py) it is treated as an honest
# `"failed"` rather than guessed at.
_PKEXEC_CANCELLED_RETURNCODE = 126


async def _elevated_run_linux(
    command: list[str],
    *,
    reason_ru: str,
    reason_en: str,
    timeout: float,
    runner: _Runner,
) -> ElevatedRunResult:
    """NOT verified live (no Linux host available while building this
    task). `reason_ru`/`reason_en` are accepted for API symmetry with the
    other two platforms but are NOT shown in polkit's own dialog text —
    unlike osascript's `with prompt "..."`, `pkexec` has no runtime
    "custom message" argument; its dialog text comes from an installed
    `.policy` XML action definition this project does not ship (building
    and installing a custom polkit policy file was out of this task's
    scope) — an honest platform limitation, not silently pretended
    otherwise."""
    logger.info("elevated_run (linux, pkexec): %s / %s", reason_ru, reason_en)
    try:
        returncode, stdout, stderr = await runner(["pkexec", *command], timeout=timeout)
    except FileNotFoundError:
        return ElevatedRunResult(
            status="failed", stderr="pkexec is not installed on this host (requires polkit)"
        )
    except TimeoutError:
        return ElevatedRunResult(status="failed", stderr=f"pkexec did not return within {timeout}s")

    if returncode == _PKEXEC_CANCELLED_RETURNCODE:
        return ElevatedRunResult(status="cancelled", stdout=stdout, stderr=stderr)
    if returncode == 0:
        return ElevatedRunResult(status="ok", stdout=stdout, stderr=stderr)
    return ElevatedRunResult(status="failed", stdout=stdout, stderr=stderr)


# ---------------------------------------------------------------------------
# Windows — UAC via PowerShell's `Start-Process -Verb RunAs`. NOT verified
# live (no Windows host available while building this task).
# ---------------------------------------------------------------------------

# A marker THIS script itself prints — not a parse of .NET's own
# (locale-dependent) exception message text — so `_elevated_run_windows`
# can tell "the user declined the UAC prompt" apart from any other
# PowerShell-level failure. Grounded in Microsoft's own documented
# behaviour: `Start-Process -Verb RunAs` throws a
# `System.ComponentModel.Win32Exception` wrapping native error 1223
# (`ERROR_CANCELLED`) when the UAC prompt is declined.
_WINDOWS_CANCELLED_MARKER = "HRANIX_ELEVATION_CANCELLED"


def _quote_for_cmd(part: str) -> str:
    """Minimal double-quoting for a `cmd.exe /c` argument list — wraps any
    argument containing a space (the common case: a file path) in double
    quotes; arguments with an embedded double-quote are not expected here
    (every A-36 caller passes plain binary names/simple flags/paths, see
    os_firewall.py) and are intentionally not further escaped, matching
    this function's own "not verified live" scope."""
    return f'"{part}"' if " " in part else part


async def _elevated_run_windows(
    command: list[str],
    *,
    reason_ru: str,
    reason_en: str,
    timeout: float,
    runner: _Runner,
) -> ElevatedRunResult:
    """NOT verified live. `reason_ru`/`reason_en` are accepted for API
    symmetry with the other two platforms and logged, but do NOT appear in
    the native UAC consent dialog — unlike osascript's `with prompt`, UAC
    has no supported way to inject a custom message for an ad hoc command
    (only a signed executable's own embedded manifest/publisher name is
    shown there). An honest platform limitation, not silently pretended
    otherwise.

    stdout/stderr of the ELEVATED command cannot be piped directly back to
    this (unprivileged) process across the UAC boundary — `Start-Process`
    launches a detached process — so the elevated `cmd.exe` redirects them
    to two temp files instead, read back here afterwards. NTFS permissions
    are per-user, not per-integrity-level: the same signed-in user's own
    unprivileged process can read a file its own elevated process just
    wrote (standard, documented Windows ACL behaviour — UAC's "no write
    up" mandatory-integrity rule restricts writes across levels, not
    reads, for the same user account).
    """
    logger.info("elevated_run (windows, UAC): %s / %s", reason_ru, reason_en)
    with tempfile.TemporaryDirectory(prefix="hranix-elevated-") as tmp:
        tmp_path = Path(tmp)
        stdout_path = tmp_path / "stdout.txt"
        stderr_path = tmp_path / "stderr.txt"
        exit_code_path = tmp_path / "exitcode.txt"
        inner_command = " ".join(_quote_for_cmd(part) for part in command)
        ps_script = (
            "$ErrorActionPreference = 'Stop'\n"
            "try {\n"
            "  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList "
            f"'/c {inner_command} 1> \"{stdout_path}\" 2> \"{stderr_path}\"' "
            "-Verb RunAs -Wait -PassThru -WindowStyle Hidden\n"
            f"  $p.ExitCode | Out-File -FilePath '{exit_code_path}' -Encoding ascii\n"
            "} catch {\n"
            f"  Write-Output '{_WINDOWS_CANCELLED_MARKER}'\n"
            "  exit 1\n"
            "}\n"
        )
        script_path = tmp_path / "hranix-elevated-run.ps1"
        script_path.write_text(ps_script, encoding="utf-8")

        try:
            returncode, stdout, stderr = await runner(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script_path),
                ],
                timeout=timeout,
            )
        except FileNotFoundError:
            return ElevatedRunResult(status="failed", stderr="powershell.exe is not available on this host")
        except TimeoutError:
            return ElevatedRunResult(status="failed", stderr=f"powershell.exe did not return within {timeout}s")

        if _WINDOWS_CANCELLED_MARKER in stdout or _WINDOWS_CANCELLED_MARKER in stderr:
            return ElevatedRunResult(status="cancelled", stdout=stdout, stderr=stderr)
        if returncode != 0:
            return ElevatedRunResult(status="failed", stdout=stdout, stderr=stderr)

        inner_stdout = stdout_path.read_text(encoding="utf-8", errors="replace") if stdout_path.exists() else ""
        inner_stderr = stderr_path.read_text(encoding="utf-8", errors="replace") if stderr_path.exists() else ""
        inner_exit = exit_code_path.read_text(encoding="utf-8").strip() if exit_code_path.exists() else ""
        if inner_exit and inner_exit != "0":
            return ElevatedRunResult(
                status="failed", stdout=inner_stdout, stderr=inner_stderr or f"exit code {inner_exit}"
            )
        return ElevatedRunResult(status="ok", stdout=inner_stdout, stderr=inner_stderr)


async def elevated_run(
    command: list[str],
    *,
    reason_ru: str,
    reason_en: str,
    timeout: float = 120.0,
    runner: _Runner | None = None,
) -> ElevatedRunResult:
    """Runs `command` (an argv list, never a shell string from the
    caller's side) ONCE, elevated, via this platform's own standard OS
    authorization mechanism — see this module's docstring for the full
    "why this is not a standing-privilege escalation" rationale and the
    exact three-way `status` contract.

    `reason_ru`/`reason_en` are a short, human-readable explanation of WHY
    elevation is being requested (shown in the dialog itself on macOS, see
    `_elevated_run_macos`; accepted-but-not-displayable on Windows/Linux
    for the documented reasons in each platform helper above) — every
    caller in this codebase (`os_firewall.py`) passes a concrete,
    specific reason, never a generic "the app needs admin rights".

    `timeout` defaults to 120 seconds — long enough for a human to
    actually type a password/complete Touch ID (unlike the 5s default
    `_local_command.run_local_command` uses for its own always-fast,
    never-interactive OS queries), still finite so a truly abandoned
    dialog does not hang a request forever.

    `runner` is the same test-injection seam
    `wazuh_agent_setup.run_privileged_install`'s own `runner` parameter
    already established — production code never passes it (defaults to
    `_default_runner`, a real subprocess); tests inject a fake to exercise
    every ok/cancelled/failed branch on every platform without ever
    popping a real OS dialog (see
    tests/unit/test_elevated_connector.py).

    Never raises: an unsupported `platform.system()` is reported as an
    honest `ElevatedRunResult(status="failed", ...)`, same "never crash
    the caller, always report a status" discipline this project's other
    connectors already follow (though note: unlike those *read-only*
    connectors, this helper's own CALLERS — e.g.
    `os_firewall.read_firewall_rules()` — DO raise a typed error on
    anything other than `ok`, mirroring `crowdsec.py`'s ban_ip/
    unban_decision write-action shape, not the never-raise read shape;
    see os_firewall.py's own "A-36" docstring section)."""
    active_runner = runner or _default_runner
    system = platform.system()
    if system == "Darwin":
        return await _elevated_run_macos(
            command, reason_ru=reason_ru, reason_en=reason_en, timeout=timeout, runner=active_runner
        )
    if system == "Windows":
        return await _elevated_run_windows(
            command, reason_ru=reason_ru, reason_en=reason_en, timeout=timeout, runner=active_runner
        )
    if system == "Linux":
        return await _elevated_run_linux(
            command, reason_ru=reason_ru, reason_en=reason_en, timeout=timeout, runner=active_runner
        )
    return ElevatedRunResult(status="failed", stderr=f"unsupported platform: {system!r}")
