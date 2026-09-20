"""A-52: terminating a specific process by PID — the «Сеть» console's
«Завершить процесс» action (see
docs/план-спецификация-фаза-0-сеть-доработка-2026-08-17.md's "Завершение
процесса" section). A genuinely NEW capability for this codebase: before
this task, nothing anywhere in this project ever sent a process a signal —
every other connector in this `security_connectors/` package is read-only
or, at most, adds/removes a narrow, fully-reversible firewall rule
(os_firewall.py's `block_port`/`block_ip`). Killing a process is
IRREVERSIBLE (there is no "un-kill"), so this module is deliberately built
with more layers of protection than any sibling connector, per the user's
own explicit request (2026-08-17) to make this "as soft and protected as
possible, with several warnings":

  1. UI layer (app.js's connection-detail modal, A-53): a persistent,
     always-visible warning next to the button, plus TWO separate
     `window.confirm()` dialogs before the request is even sent (the
     project's existing convention — A-36's `handleBlockAllIncoming` —
     already uses one `confirm()` for its own wide-blast-radius action;
     this one doubles it, matching the strictly higher, irreversible
     stakes of ending a process entirely versus blocking future traffic).
  2. The real OS admin-password prompt itself (`elevated_run`) — an
     inherent, un-skippable third confirmation gate, the same one-shot
     mechanism (never a standing privilege escalation) every other
     elevated action in this codebase already relies on.
  3. THIS module's own identity re-check, described in detail below — a
     technical (not just a UX) protection against the specific "wrong
     process" risk A-30's original "Разорвать соединение"/"Блокировать
     процесс" placeholders named as their reason for staying disabled in
     the first place (see `CONSOLE_META.network.actions`' own A-30
     history in app.js before A-54 removed the placeholders).
  4. SIGTERM, never SIGKILL (see `terminate_process()`'s own docstring for
     why, and for the honest Windows caveat where this distinction does
     not really exist).

Same "external OS mechanism reached via subprocess, nothing linked into
this process" shape the licence gate (CLAUDE.md) and every other connector
in this package already establishes.
"""

from __future__ import annotations

import logging
import platform
import shlex
import tempfile
from pathlib import Path
from typing import Any

from app.services.mcp.security_connectors.elevated import elevated_run

logger = logging.getLogger(__name__)

_TERMINATE_REASON_RU = "Hranix Shield: завершить процесс {name} (PID {pid})"
_TERMINATE_REASON_EN = "Hranix Shield: terminate process {name} (PID {pid})"

# Written to stderr by every platform's own script/command below, and ONLY
# by the identity-mismatch branch — `terminate_process()` greps the
# elevated result's stderr for this exact marker to tell "the process at
# this PID is no longer the one the operator saw" apart from every other
# possible failure (permission problem, `kill` itself rejected, ...),
# since `elevated_run`'s own `ElevatedRunResult` does not expose a raw
# platform exit code, only the three-way ok/cancelled/failed `status` (see
# elevated.py's own docstring) — text-sniffing stderr for a known marker is
# the same technique `_local_command.looks_like_permission_denied` already
# uses for its own "which specific failure was this" distinction.
_IDENTITY_MISMATCH_MARKER = "HRANIX_PROCESS_IDENTITY_MISMATCH"


class OSProcessError(RuntimeError):
    """`reason` is one of `"elevation_cancelled"` / `"elevation_failed"`
    (same two `elevated_run()` outcomes every elevated action in this
    codebase already uses) / `"process_identity_mismatch"` (new — see this
    module's own docstring, point 3) / `"invalid_pid"` (a non-positive PID
    was rejected before any script even ran — `kill`/`Stop-Process` treat
    PID 0 and negative PIDs as "the whole process group"/"every process
    this caller can signal" on POSIX, never this project's intent)."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _build_macos_linux_terminate_script(pid: int, expected_name: str) -> str:
    """Shared between macOS and Linux — both have `ps`/`kill` with
    identical-enough syntax for this narrow use. The identity check is the
    ENTIRE reason this is a generated script and not a plain `["kill",
    "-TERM", str(pid)]` argv handed straight to `elevated_run`: the check
    must happen INSIDE the elevated execution, immediately before `kill`,
    not in Python before `elevated_run` is even called (see this module's
    own docstring's point 3, and the А-50…А-54 план-спецификация's own
    "Завершение процесса" section) — the real race window is the time a
    human takes to enter their password at the OS prompt in between, not
    this script's own near-instant runtime.

    `ps -p <pid> -o comm=` reports either a bare command name or a full
    path depending on the process (confirmed live on this dev machine —
    e.g. `/bin/zsh` for a shell, `sleep` for a short-lived one) — `basename`
    normalises both to just the executable name, matching
    osquery's own `processes.name` column shape (documented as the short
    process name, not a path) that `expected_name` was read from
    (security_console.py's `_network_payload`, sourced from `osquery.py`'s
    `_ACTIVE_CONNECTIONS_SQL` join). `expected_name` is shell-quoted
    (`shlex.quote`) before embedding — defense in depth: it currently only
    ever originates from real OS process-table state, never raw free-text
    user input, but this project quotes/validates everything embedded into
    a generated shell script regardless of its current source (same
    standard `os_firewall.py`'s IP/port scripts already hold themselves
    to)."""
    quoted_name = shlex.quote(expected_name)
    return (
        "#!/bin/bash\n"
        f"actual=$(ps -p {pid} -o comm= 2>/dev/null | xargs -I{{}} basename {{}} 2>/dev/null || true)\n"
        f'if [ "$actual" != {quoted_name} ]; then\n'
        f'  echo "{_IDENTITY_MISMATCH_MARKER}: expected {quoted_name}, found ${{actual:-<gone>}}" >&2\n'
        "  exit 1\n"
        "fi\n"
        f"kill -TERM {pid}\n"
    )


def _build_windows_terminate_command(pid: int, expected_name: str) -> str:
    """NOT verified live (this dev machine is macOS — same disclosure
    every other unverified Windows branch in this project's `os_firewall.py`
    already carries). `Get-Process`'s own `.ProcessName` never includes the
    `.exe` suffix osquery's Windows `processes.name` column typically does
    — stripped on both sides before comparing, same normalisation intent
    as the macOS/Linux script's `basename` above.

    HONEST DISCLOSURE (this module's own "never silently overstate what an
    action does" discipline, same as every platform-difference note
    elsewhere in this codebase): Windows has no direct SIGTERM equivalent.
    `Stop-Process` (without `-Force`) still requests a normal process exit
    where the target process has registered a handler for it, but there is
    no POSIX-signal-shaped "ask nicely, the process can catch it and clean
    up" guarantee the way SIGTERM gives on macOS/Linux — this is a real
    platform capability gap, not something this function papers over by
    claiming a "soft" kill that does not really exist here."""
    quoted_name = expected_name.replace("'", "''")
    return (
        f"$p = Get-Process -Id {pid} -ErrorAction SilentlyContinue; "
        f"$actual = if ($p) {{ $p.ProcessName }} else {{ $null }}; "
        f"$expected = '{quoted_name}' -replace '\\.exe$', ''; "
        "if ($actual -ne $expected) { "
        f"  Write-Error \"{_IDENTITY_MISMATCH_MARKER}: expected $expected, found $actual\"; "
        "  exit 1 "
        "}; "
        f"Stop-Process -Id {pid}"
    )


async def terminate_process(pid: int, expected_name: str) -> dict[str, Any]:
    """A-52: sends SIGTERM (macOS/Linux) / `Stop-Process` (Windows, see the
    honest caveat in `_build_windows_terminate_command`'s own docstring) to
    `pid`, via a one-shot elevated OS admin prompt — but ONLY if the
    process currently AT `pid` still has the name `expected_name` the
    caller last saw (checked inside the elevated script itself — see
    `_build_macos_linux_terminate_script`'s own docstring for exactly why
    there, not here in Python). If the PID has already exited, or now
    belongs to a different process (PID reuse — the exact race this whole
    module exists to guard against), this raises
    `OSProcessError(reason="process_identity_mismatch")` and never sends
    any signal at all.

    Never SIGKILL: SIGTERM gives the target process a chance to shut down
    cleanly (flush buffers, release locks, ...) — this project's own
    explicit choice (2026-08-17) for the "as soft as possible" default;
    a process that ignores SIGTERM entirely simply keeps running, an
    honest (not silently-escalated-to-SIGKILL) outcome the caller can see
    and decide on separately."""
    if pid <= 0:
        raise OSProcessError(f"refusing to signal PID {pid} (not a real single process)", reason="invalid_pid")
    if not expected_name:
        raise OSProcessError("expected_name must not be empty", reason="invalid_pid")

    reason_ru = _TERMINATE_REASON_RU.format(name=expected_name, pid=pid)
    reason_en = _TERMINATE_REASON_EN.format(name=expected_name, pid=pid)
    system = platform.system()
    if system in ("Darwin", "Linux"):
        script = _build_macos_linux_terminate_script(pid, expected_name)
        with tempfile.TemporaryDirectory(prefix="hranix-terminate-") as tmp:
            script_path = Path(tmp) / "hranix-terminate-process.sh"
            script_path.write_text(script, encoding="utf-8")
            result = await elevated_run(["/bin/bash", str(script_path)], reason_ru=reason_ru, reason_en=reason_en)
    elif system == "Windows":
        result = await elevated_run(
            ["powershell.exe", "-NoProfile", "-Command", _build_windows_terminate_command(pid, expected_name)],
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    else:
        raise OSProcessError(f"unsupported platform: {system!r}", reason="not_configured")

    if result.status == "cancelled":
        raise OSProcessError("the user declined the elevation prompt", reason="elevation_cancelled")
    if result.status == "failed":
        if _IDENTITY_MISMATCH_MARKER in result.stderr:
            logger.warning("os_processes: identity mismatch terminating pid=%s name=%r: %s", pid, expected_name, result.stderr.strip())
            raise OSProcessError(
                f"process {pid} no longer matches the expected name {expected_name!r}",
                reason="process_identity_mismatch",
            )
        raise OSProcessError(
            f"elevated terminate failed: {result.stderr.strip() or result.stdout.strip()}",
            reason="elevation_failed",
        )
    logger.info("os_processes: terminated pid=%s name=%r (SIGTERM)", pid, expected_name)
    return {"status": "ok", "pid": pid, "terminated": True}
