"""A-18: cross-platform "is the OS's own firewall on" check — one of the two
new connectors this task builds for the `perimeter` console (the third
source, CrowdSec's bouncer, already existed from A-11 and is only rewired
onto this console, see `security_console.py`).

Same "external tool reached from outside the process, never linked in"
shape the licence gate (CLAUDE.md) and A-11's CrowdSec connector already
established — here the "external tool" is simply the OS itself, reached via
`asyncio.create_subprocess_exec` (see `_local_command.py`), never a shell
string and never a blocking `subprocess.run`.

Three honest non-`ok` states, same vocabulary as this task's disk-encryption
sibling and the DoD's own wording:
  - `"not_configured"`: this platform has no tool this module knows how to
    ask (an unsupported `platform.system()`, or — Linux only — neither `ufw`
    nor `iptables` is installed).
  - `"permission_denied"`: the tool exists and ran, but refused to answer
    without elevated privileges this process does not have and — per this
    task's own risk note — must not acquire by asking the whole service to
    run as root/administrator. Confirmed empirically on macOS while building
    this task: `pfctl -s info` without sudo answers exactly
    "pfctl: /dev/pf: Permission denied".
  - `"unreachable"`: the tool ran but exited non-zero for some other reason,
    its output could not be parsed, or it timed out.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import platform
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BlockedIp, BlockedPort
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    looks_like_permission_denied,
    run_local_command,
)
from app.services.mcp.security_connectors.elevated import ElevatedRunResult, elevated_run

logger = logging.getLogger(__name__)

OS_FIREWALL_CONNECTOR_NAME = "os_firewall"

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"

# A-28: `pfctl -s rules` — the *ruleset* listing, a different pf subcommand
# (and, confirmed live, a different permission requirement) from `pfctl -s
# info` (the on/off status `_macos_pfctl_fallback()` above already uses).
_PF_RULES_ARGS = ("pfctl", "-s", "rules")


class OSFirewallError(RuntimeError):
    """`reason` is one of `"not_configured"` / `"permission_denied"` /
    `"unreachable"` for the read-only functions above this class's first
    use — see this module's docstring. A-36's three ELEVATED action
    functions below (`read_firewall_rules`/`block_all_incoming`/
    `unblock_all_incoming`) raise this SAME exception class with two
    additional reasons instead: `"elevation_cancelled"` (the user declined
    the OS admin prompt — not an error, an honest terminal outcome) and
    `"elevation_failed"` (the elevated command itself failed) — see this
    module's "A-36" section docstring for why those three functions raise
    at all rather than following the never-raise dict-return shape every
    function above them uses."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


async def _run(*args: str) -> tuple[int, str, str]:
    """Translates the shared local-command helper's exceptions into this
    module's own `OSFirewallError` reasons."""
    try:
        return await run_local_command(*args)
    except LocalCommandNotFound as exc:
        raise OSFirewallError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise OSFirewallError(str(exc), reason="unreachable") from exc


async def _macos_firewall_active() -> bool:
    """Primary: `socketfilterfw --getglobalstate` — Apple's own CLI for
    exactly the "Firewall" toggle System Settings shows, and (confirmed live
    while building this task, macOS 26.5.2) does **not** require sudo:
    prints `"Firewall is enabled. (State = 1)"` / `"Firewall is disabled.
    (State = 0)"` as a plain user.

    This task's own brief names two other commands (`pfctl -s info` and/or
    `defaults read .../com.apple.alf globalstate`) — both were tried live
    while building this connector and neither is usable as the *primary*
    signal on current macOS:
      - `pfctl -s info` without sudo answers
        `"pfctl: /dev/pf: Permission denied"` — it needs root, which this
        service must not acquire wholesale (see this task's risk note). Kept
        below as a *fallback* for hosts where `/dev/pf` happens to be
        readable non-root, so a permission failure there still surfaces
        `permission_denied` instead of a false `unreachable`.
      - `defaults read /Library/Preferences/com.apple.alf globalstate`
        answered `"does not exist"` (exit 1) on this dev machine even though
        the firewall was genuinely on — Apple has evidently relocated this
        preference in recent macOS releases, so it is not a reliable signal
        here and this module does not use it.
    """
    try:
        returncode, stdout, stderr = await _run(_SOCKETFILTERFW, "--getglobalstate")
    except OSFirewallError:
        return await _macos_pfctl_fallback()

    combined = f"{stdout}\n{stderr}"
    if returncode == 0:
        lowered = stdout.lower()
        if "enabled" in lowered:
            return True
        if "disabled" in lowered:
            return False
    if looks_like_permission_denied(combined):
        raise OSFirewallError("socketfilterfw denied access", reason="permission_denied")
    return await _macos_pfctl_fallback()


async def _macos_pfctl_fallback() -> bool:
    returncode, stdout, stderr = await _run("pfctl", "-s", "info")
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("pfctl -s info requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"pfctl -s info exited {returncode}: {stderr.strip()}", reason="unreachable")
    lowered = stdout.lower()
    if "status: enabled" in lowered:
        return True
    if "status: disabled" in lowered:
        return False
    raise OSFirewallError("could not parse pfctl -s info output", reason="unreachable")


async def _windows_powershell_output(command: str, *, timeout: float = 15.0) -> str:
    """Run a read-only PowerShell one-liner and return its stdout — the
    shared, locale-proof data path for this module's Windows READ checks.

    The netsh text parsing these checks used before (A-18/A-28) is only
    correct on en-US Windows: netsh output is MUI-localized, and a real
    ru-RU host — this product's primary audience — prints
    «Состояние ВКЛЮЧИТЬ» / «Имя правила», not "State ON" / "Rule Name"
    (caught live by the 2026-09-19 Windows acceptance, console showed
    `unreachable` on a healthy Russian machine). Asking the CIM store via
    the NetSecurity cmdlets and parsing structured JSON/numbers instead of
    localized text removes the locale from the equation; the ELEVATED
    Windows actions below already go through PowerShell one-liners, so
    this reads as the same convention, just for reads.

    The command is prefixed with an explicit `[Console]::OutputEncoding`
    switch to UTF-8: without it, a localized Windows host writes its
    stderr (denial messages included) in the legacy OEM codepage (cp866
    on ru-RU — caught live, 2026-09-19), which `run_local_command`'s
    UTF-8 decode turns into replacement-char mush that no
    `looks_like_permission_denied` marker can ever match.
    """
    try:
        returncode, stdout, stderr = await run_local_command(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + command,
            timeout=timeout,
        )
    except LocalCommandNotFound as exc:
        raise OSFirewallError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise OSFirewallError(f"powershell timed out after {timeout}s", reason="unreachable") from exc
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("PowerShell query requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"powershell exited {returncode}: {stderr.strip()}", reason="unreachable")
    return stdout


async def _windows_firewall_active() -> bool:
    """`Get-NetFirewallProfile` (CIM, via `_windows_powershell_output`) —
    every profile's `Enabled` flag. Reported as active only when *every*
    profile is enabled — any profile off is a real posture gap, matching
    how Windows' own Security Center badge behaves, not a detail to
    average away. Same semantics as the original A-18 en-US netsh-text
    parse, now locale-proof (see `_windows_powershell_output`).

    Verified live on a real ru-RU Windows host (2026-09-19 Windows
    acceptance): three healthy profiles answer as
    `[{"Name":"Domain","Enabled":1},...]` — note `Enabled` serializes as
    `1`/`0`, not `true`/`false` (Windows PowerShell 5.1's ConvertTo-Json of
    the CIM-backed property), which is why the parse truth-tests the value
    instead of comparing it to the string "true".
    """
    stdout = await _windows_powershell_output(
        "Get-NetFirewallProfile | Select-Object Name,Enabled | ConvertTo-Json -Compress"
    )
    try:
        profiles = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise OSFirewallError(
            f"could not parse Get-NetFirewallProfile output: {stdout.strip()[:200]!r}", reason="unreachable"
        ) from exc
    if isinstance(profiles, dict):
        profiles = [profiles]
    enabled = [bool(profile.get("Enabled")) for profile in profiles]
    if not enabled:
        raise OSFirewallError("Get-NetFirewallProfile returned no profiles", reason="unreachable")
    return all(enabled)


async def _linux_firewall_active() -> bool:
    """`ufw status` first (the default on Ubuntu/Debian, simple `"Status:
    active"` / `"Status: inactive"` text) — `iptables -L` only as a fallback
    when `ufw` itself is not installed, exactly this task's spec. Neither
    binary present at all is an honest `not_configured` (no firewall tool
    this module knows how to ask), not an error.
    """
    try:
        returncode, stdout, stderr = await _run("ufw", "status")
    except OSFirewallError as exc:
        if exc.reason != "not_configured":
            raise
        return await _linux_iptables_fallback()

    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("ufw status requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"ufw status exited {returncode}: {stderr.strip()}", reason="unreachable")
    lowered = stdout.lower()
    if "status: active" in lowered:
        return True
    if "status: inactive" in lowered:
        return False
    raise OSFirewallError("could not parse ufw status output", reason="unreachable")


async def _linux_iptables_fallback() -> bool:
    try:
        returncode, stdout, stderr = await _run("iptables", "-L")
    except OSFirewallError as exc:
        if exc.reason == "not_configured":
            raise OSFirewallError(
                "neither ufw nor iptables is installed on this host", reason="not_configured"
            ) from exc
        raise

    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("iptables -L requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"iptables -L exited {returncode}: {stderr.strip()}", reason="unreachable")

    # Any chain with a non-empty rule set, or a non-ACCEPT default policy,
    # counts as "the firewall is doing something" — a bare `iptables -L`
    # with all built-in chains at policy ACCEPT and zero rules is the
    # kernel's un-configured default, i.e. no firewall active.
    has_policy_deny = bool(re.search(r"policy (DROP|REJECT)", stdout))
    has_rules = bool(re.search(r"^(ACCEPT|DROP|REJECT|LOG)\b", stdout, flags=re.MULTILINE))
    return has_policy_deny or has_rules


async def _firewall_active_for_current_platform() -> bool:
    system = platform.system()
    if system == "Darwin":
        return await _macos_firewall_active()
    if system == "Windows":
        return await _windows_firewall_active()
    if system == "Linux":
        return await _linux_firewall_active()
    raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")


async def fetch_firewall_status() -> dict[str, Any]:
    """Real data for the `os_firewall` slice of `GET
    /security/consoles/perimeter` (see `security_console.py._perimeter_payload`).
    Never raises: an unsupported platform / missing tool / permission
    problem / any other failure is reported as an honest `connector.status`,
    never a 500 and never a guessed `active`."""
    try:
        active = await _firewall_active_for_current_platform()
    except OSFirewallError as exc:
        logger.warning("os_firewall: %s", exc)
        return {"connector": {"status": exc.reason}, "active": None}
    return {"connector": {"status": "ok"}, "active": active}


# ---------------------------------------------------------------------------
# A-28: `perimeter`'s `firewall_rules` metric — listing (not just toggling)
# each platform's actual ruleset, a distinct capability from
# `_firewall_active_for_current_platform()` above (on/off toggle) with its
# own, independently-failing permission requirements — confirmed live on
# this dev machine (macOS): `socketfilterfw --getglobalstate` (the toggle,
# no sudo needed) and `pfctl -s rules` (the ruleset, sudo required) gave
# DIFFERENT results, so this needs its own connector status, not a reuse of
# `fetch_firewall_status()`'s.
# ---------------------------------------------------------------------------


async def _macos_firewall_rule_count() -> int:
    """`pfctl -s rules` — confirmed live while building A-28 (this dev
    machine, macOS 26.5.2, plain user, no sudo, no cached credential):
    prints exactly `pfctl: /dev/pf: Permission denied` and exits 1 — the
    same `/dev/pf` permission wall `_macos_pfctl_fallback()` already hit for
    `pfctl -s info` in A-18, now confirmed for `-s rules` too.

    No user-level alternative exists for the pf *ruleset* the way
    `socketfilterfw --getglobalstate` exists for the on/off *toggle*:
    Apple's own `socketfilterfw` only reports the ALF (Application Layer
    Firewall) global state, it has no "list rules" subcommand at all — this
    function has no fallback to try, unlike `_macos_firewall_active()`
    above. This is expected, per this task's own brief, to always raise
    `permission_denied` in the un-elevated case this service must stay in
    — see `fetch_firewall_rules()`'s docstring for how that honest failure
    is what disables the perimeter console's "Правила фаервола" button
    (principle 10) instead of showing a fake rule list."""
    returncode, stdout, stderr = await _run(*_PF_RULES_ARGS)
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("pfctl -s rules requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"pfctl -s rules exited {returncode}: {stderr.strip()}", reason="unreachable")
    lines = [line for line in stdout.splitlines() if line.strip() and not line.strip().startswith("#")]
    return len(lines)


async def _windows_firewall_rule_count() -> int:
    """`Get-NetFirewallRule | Measure-Object` (CIM, via
    `_windows_powershell_output`) — the total rule count, including
    disabled rules, matching what the original A-28 `^Rule Name:` line
    count of `netsh ... show rule name=all` used to count on en-US text.
    Locale-proof (see `_windows_powershell_output`): «Имя правила:» only
    exists in en-US output, ru-RU prints «Имя правила» — the text-parse
    path was caught live on a real Russian Windows host (2026-09-19
    acceptance) answering `unreachable`. Enumerating all rules via CIM
    takes a few seconds on a real host (680 rules measured live), hence
    the generous timeout. Verified live: the same host answers `680`.
    """
    stdout = await _windows_powershell_output(
        "(Get-NetFirewallRule | Measure-Object).Count", timeout=30.0
    )
    try:
        return int(stdout.strip())
    except ValueError as exc:
        raise OSFirewallError(
            f"could not parse Get-NetFirewallRule count output: {stdout.strip()[:200]!r}",
            reason="unreachable",
        ) from exc


async def _linux_firewall_rule_count() -> int:
    """`iptables -S` — NOT verified live either (same disclosure as the
    Windows path above). Each output line is one rule specification
    (`-P <chain> <policy>` for a chain's default policy, `-N <chain>` for a
    user-defined chain, `-A <chain> ...` for an actual appended rule) —
    counting `-A` lines specifically is this module's rule count, mirroring
    how `_linux_iptables_fallback()` above already treats "an ACCEPT/DROP/
    REJECT/LOG line" as "a rule" rather than counting chain declarations/
    default policies as rules too."""
    returncode, stdout, stderr = await _run("iptables", "-S")
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("iptables -S requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"iptables -S exited {returncode}: {stderr.strip()}", reason="unreachable")
    return len(re.findall(r"^-A\b", stdout, flags=re.MULTILINE))


async def _firewall_rule_count_for_current_platform() -> int:
    system = platform.system()
    if system == "Darwin":
        return await _macos_firewall_rule_count()
    if system == "Windows":
        return await _windows_firewall_rule_count()
    if system == "Linux":
        return await _linux_firewall_rule_count()
    raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")


async def fetch_firewall_rules() -> dict[str, Any]:
    """Real data for `perimeter`'s `firewall_rules` metric (A-28, see
    `security_console.py._perimeter_payload`) — same never-raises honest-
    `connector.status` contract as `fetch_firewall_status()` above.

    Confirmed live on this dev machine (macOS): returns
    `{"connector": {"status": "permission_denied"}, "count": None}` — pf's
    ruleset genuinely cannot be read without root on current macOS, with no
    user-level workaround (see `_macos_firewall_rule_count()`'s docstring).
    This is also the reason the perimeter console's "Правила фаервола"
    button stays a disabled, explained placeholder (principle 10) rather
    than a real rule-list view — see `security_console.py._perimeter_payload`
    and `app.js`'s `CONSOLE_META.perimeter.actions`."""
    try:
        count = await _firewall_rule_count_for_current_platform()
    except OSFirewallError as exc:
        logger.warning("os_firewall (rules): %s", exc)
        return {"connector": {"status": exc.reason}, "count": None}
    return {"connector": {"status": "ok"}, "count": count}


# ---------------------------------------------------------------------------
# A-36: one-shot ELEVATED actions — a genuinely different shape from every
# function above this point. Everything above is a passive, never-
# privileged, never-raising POLL (safe to run on every console refresh).
# The three functions below instead ask for a real, one-time OS admin
# prompt (via `elevated_run`, see elevated.py) EVERY time they are called —
# no privilege is ever cached in this module or this process between calls
# (see elevated.py's own docstring + the plan document's "Важное решение"
# section for the full rationale on why this does not violate the "never
# escalate this app's own privileges" architecture principle). Because an
# elevation attempt has a genuinely different, ACTION-shaped outcome space
# (did the user consent? did the privileged command itself succeed?), these
# three RAISE `OSFirewallError` on anything other than a clean `ok` —
# mirroring `crowdsec.py`'s `ban_ip`/`unban_decision` write-action shape,
# not the never-raise passive-read shape every function above uses.
# ---------------------------------------------------------------------------

_FIREWALL_READ_RULES_REASON_RU = "Hranix Shield: прочитать правила фаервола"
_FIREWALL_READ_RULES_REASON_EN = "Hranix Shield: read the firewall ruleset"
_FIREWALL_BLOCK_ALL_REASON_RU = "Hranix Shield: заблокировать весь входящий трафик"
_FIREWALL_BLOCK_ALL_REASON_EN = "Hranix Shield: block all incoming traffic"
_FIREWALL_UNBLOCK_ALL_REASON_RU = "Hranix Shield: разблокировать весь входящий трафик"
_FIREWALL_UNBLOCK_ALL_REASON_EN = "Hranix Shield: unblock all incoming traffic"


def _raise_for_elevated_result(result: ElevatedRunResult) -> None:
    """Shared translation from `elevated_run()`'s own three-way
    `ElevatedRunResult.status` into this module's `OSFirewallError` — used
    by all three functions below. Only called for `"cancelled"`/`"failed"`
    (a caller checks `result.status == "ok"` first and returns normally in
    that case, see e.g. `read_firewall_rules()`)."""
    if result.status == "cancelled":
        raise OSFirewallError("the user declined the elevation prompt", reason="elevation_cancelled")
    raise OSFirewallError(
        f"elevated command failed: {result.stderr.strip() or result.stdout.strip()}",
        reason="elevation_failed",
    )


async def _macos_read_firewall_rules() -> list[str]:
    result = await elevated_run(
        list(_PF_RULES_ARGS),
        reason_ru=_FIREWALL_READ_RULES_REASON_RU,
        reason_en=_FIREWALL_READ_RULES_REASON_EN,
    )
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return [line for line in result.stdout.splitlines() if line.strip()]


async def _linux_read_firewall_rules() -> list[str]:
    """NOT verified live (same disclosure as `_linux_firewall_rule_count`
    above) — `iptables -S` prints one rule specification per line (see
    that function's own docstring), reused here verbatim as raw text
    rather than re-parsed into a count, per this task's own "minimal
    parsing is fine" brief."""
    result = await elevated_run(
        ["iptables", "-S"],
        reason_ru=_FIREWALL_READ_RULES_REASON_RU,
        reason_en=_FIREWALL_READ_RULES_REASON_EN,
    )
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return [line for line in result.stdout.splitlines() if line.strip()]


async def _windows_read_firewall_rules() -> list[str]:
    """NOT verified live (same disclosure as `_windows_firewall_rule_count`
    above)."""
    result = await elevated_run(
        ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"],
        reason_ru=_FIREWALL_READ_RULES_REASON_RU,
        reason_en=_FIREWALL_READ_RULES_REASON_EN,
    )
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return [line for line in result.stdout.splitlines() if line.strip()]


async def read_firewall_rules() -> dict[str, Any]:
    """A-36: the REAL ruleset text (not just `fetch_firewall_rules()`'s
    bare count above) via a one-shot elevated OS-admin prompt — this is
    what turns the perimeter console's "Правила фаервола" button from a
    disabled, tooltip-only placeholder (A-28/A-31) into a real action.

    Deliberately minimal parsing — raw non-empty output lines, per this
    task's own brief ("парсинг может быть минимальным... структурный
    парсинг pf-синтаксиса это отдельная, необязательная для DoD работа");
    a caller wanting structured rule objects would need a real pf-syntax
    parser, out of scope here.

    Raises `OSFirewallError` (reason `elevation_cancelled`/
    `elevation_failed`/`not_configured`) on anything other than success —
    see this module's "A-36" section docstring for why this differs from
    `fetch_firewall_rules()`'s never-raise shape."""
    system = platform.system()
    if system == "Darwin":
        rules = await _macos_read_firewall_rules()
    elif system == "Linux":
        rules = await _linux_read_firewall_rules()
    elif system == "Windows":
        rules = await _windows_read_firewall_rules()
    else:
        raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")
    return {"status": "ok", "rules": rules}


def _build_block_all_incoming_script() -> str:
    """A single pf rule set that REPLACES whatever ruleset is currently
    loaded with just `block in all` (see this task's own brief: "широкий
    радиус поражения — может отрезать легитимные локальные сервисы" — this
    IS the intended, explicitly-warned-about effect, not a bug) and makes
    sure pf itself is enabled (`pfctl -e`; a harmless no-op, ignored, if it
    already was — confirmed live while building this task: re-enabling an
    already-enabled pf answers `pfctl: pf already enabled` and exits
    non-zero, hence the `|| true`).

    Written to a real script FILE and run via `/bin/bash <path>` (not
    inlined into `elevated_run`'s own single-command argv) — same reason
    `wazuh_agent_setup.build_privileged_setup_script` gives: one elevation
    prompt for the whole multi-step sequence, and AppleScript's own quoting
    only has to handle the one script path, not this script's full body."""
    return "#!/bin/bash\nset -e\necho 'block in all' | /sbin/pfctl -f -\n/sbin/pfctl -e 2>/dev/null || true\n"


def _build_unblock_all_incoming_script() -> str:
    """Reloads macOS's own default `/etc/pf.conf` — the same file macOS
    itself loads pf from by default — restoring whatever state was active
    before `block_all_incoming()` replaced it. This module never captured
    the exact prior custom ruleset (pf has no "save current ruleset"
    primitive `read_firewall_rules()`'s raw text output could safely be
    fed back into unattended), so "reload the OS's own default" is the
    honest, safe restoration point, not a guessed reconstruction."""
    return "#!/bin/bash\nset -e\n/sbin/pfctl -f /etc/pf.conf\n"


async def _run_elevated_firewall_script(script: str, *, reason_ru: str, reason_en: str) -> ElevatedRunResult:
    with tempfile.TemporaryDirectory(prefix="hranix-firewall-") as tmp:
        script_path = Path(tmp) / "hranix-firewall-action.sh"
        script_path.write_text(script, encoding="utf-8")
        return await elevated_run(["/bin/bash", str(script_path)], reason_ru=reason_ru, reason_en=reason_en)


# Linux: a single, uniquely-tagged INPUT rule (via `-m comment`) inserted at
# the very top of the chain — NOT `iptables -P INPUT DROP` (which rewrites
# the chain's own default POLICY in place and has no matching "what was it
# before" to restore from, the same "no save-current-ruleset primitive"
# problem `_build_unblock_all_incoming_script()`'s docstring already names
# for pf). A tagged, individually-`-D`-deletable rule is both a real
# block-everything (it is inserted first, before any ACCEPT rule) and
# cleanly, exactly reversible. NOT verified live (same disclosure as this
# module's other unverified Linux branches).
_LINUX_BLOCK_ALL_COMMENT = "hranix-shield-block-all-incoming"
_LINUX_BLOCK_ALL_RULE_ARGS = ("-m", "comment", "--comment", _LINUX_BLOCK_ALL_COMMENT, "-j", "DROP")

# Windows: `netsh advfirewall set allprofiles firewallpolicy` — the
# documented mechanism for the firewall's own default inbound action.
# `blockinboundalways` additionally overrides any existing ALLOW
# exceptions (Windows' own normal default is `blockinbound`, which still
# honours configured exceptions) — the "always" variant is what makes this
# a genuine block-everything, matching this task's own intent. Restoring
# to plain `blockinbound` (not attempting to detect/preserve whatever the
# actual prior policy per-profile was — Windows exposes no single
# "restore previous policy" primitive either) is the same "reload the OS's
# own normal default" honest restoration point `_build_
# unblock_all_incoming_script()` already uses for pf.conf. NOT verified
# live (same disclosure as this module's other unverified Windows
# branches).
_WINDOWS_BLOCK_ALL_ARGS = ("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinboundalways,allowoutbound")
_WINDOWS_UNBLOCK_ALL_ARGS = ("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,allowoutbound")


async def _block_all_incoming_for_current_platform() -> ElevatedRunResult:
    system = platform.system()
    if system == "Darwin":
        return await _run_elevated_firewall_script(
            _build_block_all_incoming_script(),
            reason_ru=_FIREWALL_BLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_BLOCK_ALL_REASON_EN,
        )
    if system == "Linux":
        return await elevated_run(
            ["iptables", "-I", "INPUT", "1", *_LINUX_BLOCK_ALL_RULE_ARGS],
            reason_ru=_FIREWALL_BLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_BLOCK_ALL_REASON_EN,
        )
    if system == "Windows":
        return await elevated_run(
            list(_WINDOWS_BLOCK_ALL_ARGS),
            reason_ru=_FIREWALL_BLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_BLOCK_ALL_REASON_EN,
        )
    raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")


async def _unblock_all_incoming_for_current_platform() -> ElevatedRunResult:
    system = platform.system()
    if system == "Darwin":
        return await _run_elevated_firewall_script(
            _build_unblock_all_incoming_script(),
            reason_ru=_FIREWALL_UNBLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_UNBLOCK_ALL_REASON_EN,
        )
    if system == "Linux":
        return await elevated_run(
            ["iptables", "-D", "INPUT", *_LINUX_BLOCK_ALL_RULE_ARGS],
            reason_ru=_FIREWALL_UNBLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_UNBLOCK_ALL_REASON_EN,
        )
    if system == "Windows":
        return await elevated_run(
            list(_WINDOWS_UNBLOCK_ALL_ARGS),
            reason_ru=_FIREWALL_UNBLOCK_ALL_REASON_RU,
            reason_en=_FIREWALL_UNBLOCK_ALL_REASON_EN,
        )
    raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")


async def block_all_incoming() -> dict[str, Any]:
    """A-36: macOS is the only platform live-verified on this dev machine
    (see this task's own report) — the Linux/Windows branches below are
    implemented from each platform's own documented mechanism (a tagged
    `iptables` rule / `netsh advfirewall ... firewallpolicy`) but NOT
    verified live, same honest disclosure this module's other unverified
    platform branches already use.

    Raises `OSFirewallError` on anything other than success (reason
    `elevation_cancelled`/`elevation_failed`/`not_configured`) — see the
    router's `perimeter_firewall_block_all` for how that maps to an HTTP
    response."""
    result = await _block_all_incoming_for_current_platform()
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "blocked": True}


async def unblock_all_incoming() -> dict[str, Any]:
    """A-36: the reverse of `block_all_incoming()` above — same per-
    platform scope (macOS live-verified, Linux/Windows implemented from
    documentation only) and the same raise-on-non-ok contract."""
    result = await _unblock_all_incoming_for_current_platform()
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "blocked": False}


# ---------------------------------------------------------------------------
# A-37: per-PORT blocking — a genuinely NARROWER elevated action than A-36's
# block_all_incoming/unblock_all_incoming above, by this task's own explicit
# plan-document brief: "выделенный pf-anchor `hranix-blocked-ports` на
# macOS (НЕ трогает системные правила напрямую — добавляет/убирает только
# из СВОЕГО anchor'а, отдельно от block_all_incoming's 'block in all'
# замены всего ruleset'а)". `block_port()`/`unblock_port()` below share the
# same "no privilege ever cached, every call its own OS admin prompt" A-36
# contract (raise `OSFirewallError` with `elevation_cancelled`/
# `elevation_failed`/`not_configured` on anything other than `ok`, via the
# same `_raise_for_elevated_result` helper above) — only the underlying
# per-platform command differs.
# ---------------------------------------------------------------------------

# The dedicated pf anchor this task's own port-blocking rules live in — kept
# entirely separate from block_all_incoming's direct main-ruleset rewrite
# above, and never referenced from `/etc/pf.conf` by this module (modifying
# the system's own pf.conf to wire this anchor into live packet filtering
# would be a materially bigger, more persistent system change than "add one
# port to my own anchor", out of this task's own narrow-scope brief) — see
# `_build_macos_sync_blocked_ports_script`'s own docstring for the full
# honest disclosure of what this does and does not guarantee on macOS.
MACOS_BLOCKED_PORTS_ANCHOR = "hranix-blocked-ports"

# Linux: this task's own plan-document brief names this exact chain name
# ("отдельная iptables-цепочка `HRANIX-BLOCKED` на Linux").
LINUX_BLOCKED_PORTS_CHAIN = "HRANIX-BLOCKED"

_BLOCK_PORT_REASON_RU = "Hranix Shield: заблокировать порт {port}"
_BLOCK_PORT_REASON_EN = "Hranix Shield: block port {port}"
_UNBLOCK_PORT_REASON_RU = "Hranix Shield: разблокировать порт {port}"
_UNBLOCK_PORT_REASON_EN = "Hranix Shield: unblock port {port}"


def _build_macos_sync_blocked_ports_script(ports: list[int]) -> str:
    """pf has no "add/remove one rule from an anchor" primitive: `pfctl -a
    <anchor> -f -` always REPLACES that anchor's ENTIRE rule set (the exact
    same replace-only semantics `_build_block_all_incoming_script()` above
    already relies on for the *main* ruleset, just scoped here to one named
    anchor instead of the whole pf configuration) — so the only correct way
    to add or remove a SINGLE port without silently dropping every other
    port this operator has already blocked is to regenerate the anchor's
    WHOLE body from `ports` (the complete, current desired set) on EVERY
    call, never an incremental patch.

    `ports` is expected, caller-side, to already be the fresh, post-write
    `blocked_ports` DB table contents (see `security_console.py`'s
    `perimeter_block_port`/`perimeter_unblock_port`, this function's only
    two real callers via `block_port`/`unblock_port` below) — this function
    itself never reads the database, it only renders whatever list it is
    given.

    Each port gets TWO rules (`proto tcp` and `proto udp`) — this task's
    own endpoint shape (`POST`/`DELETE .../ports/{port}/block`, no
    `?protocol=` query parameter) blocks the PORT NUMBER outright, not one
    specific transport, matching the granularity the URL itself already
    commits to (the `ports` list a row was clicked from, A-31, may show
    e.g. `8080/tcp` specifically — but "block this port" is read as "block
    this port number", the more intuitive operator-facing meaning, not "и
    only this exact transport").

    Fed through a single-quoted heredoc (`<<'HRANIX_EOF'`), not a
    shell-escaped one-liner: every `port` here is always a genuine `int` by
    construction (FastAPI's own path-parameter type coercion for the
    block/unblock endpoints already rejects a non-integer `{port}` long
    before this module is ever called, see security_console.py) — there is
    no free-text/injection surface to escape in the first place, and a
    quoted heredoc is simply the more robust and readable way to hand pf a
    multi-line ruleset.

    An empty `ports` list still runs `pfctl -a <anchor> -f -` with an empty
    heredoc body — pf accepts loading an empty ruleset into an anchor
    (confirmed live while building this task, see this task's own report)
    — this is the correct "the last blocked port was just unblocked, the
    anchor should now hold zero rules" case, never skipped as a no-op.

    HONEST DISCLOSURE (this module's own "never silently overstate what a
    connector does" discipline, same as every `NOT verified live` note
    elsewhere in this file): macOS's default `/etc/pf.conf` does not
    reference `hranix-blocked-ports` from its own loaded ruleset, and this
    function deliberately never edits that file (see this section's own
    module-level comment above for why) — so on a host where nothing else
    has ever referenced this anchor name, the rules loaded here are
    present and independently readable (`pfctl -a hranix-blocked-ports -s
    rules`, exactly this task's own DoD verification command) but are NOT
    automatically consulted by the live packet-filtering path unless this
    anchor happens to already be wired in (e.g. by a one-time,
    out-of-scope-for-this-task `/etc/pf.conf` edit an operator/installer
    performs separately). This is a genuine, documented pf limitation
    (anchors are inert until referenced from a loaded ruleset), not a bug
    in this function — recorded here exactly because CLAUDE.md's own
    verification discipline requires disclosing this rather than letting a
    reader assume "anchor populated" silently means "traffic blocked"."""
    lines: list[str] = []
    for port in sorted(set(ports)):
        lines.append(f"block in proto tcp from any to any port {port}")
        lines.append(f"block in proto udp from any to any port {port}")
    body = "\n".join(lines)
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/pfctl -a {MACOS_BLOCKED_PORTS_ANCHOR} -f - <<'HRANIX_EOF'\n"
        f"{body}\n"
        "HRANIX_EOF\n"
    )


def _build_linux_block_port_script(port: int) -> str:
    """NOT verified live (this dev machine is macOS — same disclosure every
    other unverified Linux branch in this file already carries).

    Unlike macOS's anchor above (no incremental primitive), iptables
    genuinely has one: `-C` checks whether an identical rule already
    exists (so a repeat/retried block of an already-blocked port is
    idempotent — it does not insert a second, duplicate DROP rule), `-A`
    appends it only when `-C` reports it missing. A dedicated chain
    (`HRANIX-BLOCKED`, this task's own plan-document brief) rather than
    inserting straight into `INPUT` (the way `block_all_incoming`'s own
    Linux path does above) keeps this project's per-port rules trivially
    distinguishable from whatever other `INPUT` rules already exist on the
    host. `INPUT` itself only ever gets ONE permanent jump rule to this
    chain, added the same idempotent `-C`-then-`-I` way, never a second one
    on a repeat call."""
    chain = LINUX_BLOCKED_PORTS_CHAIN
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/iptables -N {chain} 2>/dev/null || true\n"
        f"/sbin/iptables -C INPUT -j {chain} 2>/dev/null || /sbin/iptables -I INPUT 1 -j {chain}\n"
        f"/sbin/iptables -C {chain} -p tcp --dport {port} -j DROP 2>/dev/null "
        f"|| /sbin/iptables -A {chain} -p tcp --dport {port} -j DROP\n"
        f"/sbin/iptables -C {chain} -p udp --dport {port} -j DROP 2>/dev/null "
        f"|| /sbin/iptables -A {chain} -p udp --dport {port} -j DROP\n"
    )


def _build_linux_unblock_port_script(port: int) -> str:
    """NOT verified live (same disclosure as the block script above). `-D`
    on a rule that is already absent (e.g. a stale/duplicate unblock click)
    exits non-zero — `|| true` on both lines keeps this idempotent instead
    of surfacing a spurious `elevation_failed` for what is really a
    harmless no-op."""
    chain = LINUX_BLOCKED_PORTS_CHAIN
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/iptables -D {chain} -p tcp --dport {port} -j DROP 2>/dev/null || true\n"
        f"/sbin/iptables -D {chain} -p udp --dport {port} -j DROP 2>/dev/null || true\n"
    )


def _windows_block_port_rule_names(port: int) -> tuple[str, str]:
    """The exact, recognisable `-DisplayName` values this task's own brief
    asks for ("New-NetFirewallRule/Remove-NetFirewallRule с распознаваемым
    -DisplayName") — shared between the block and unblock command builders
    below so the unblock side can name-match precisely what the block side
    created, never a fuzzy/wildcard match that risks touching an unrelated
    rule."""
    return (
        f"Hranix Shield - Block port {port} (TCP)",
        f"Hranix Shield - Block port {port} (UDP)",
    )


def _build_windows_block_port_command(port: int) -> str:
    """NOT verified live (this dev machine is macOS — same disclosure every
    other unverified Windows branch in this file already carries).

    Single-quoted PowerShell string literals throughout, never
    double-quoted: this whole string is embedded as ONE `-Command` argv
    element by `elevated_run`'s Windows path, which wraps any argument
    containing a space in a NAIVE, non-quote-escaping pair of double quotes
    (see elevated.py's `_quote_for_cmd` docstring) — an embedded double
    quote here would break that outer wrapping and corrupt the command
    `cmd.exe` hands to `powershell.exe`; an embedded single quote will
    not, since PowerShell's own single-quoted string literals do not need
    the outer double quotes escaped in any way."""
    tcp_name, udp_name = _windows_block_port_rule_names(port)
    return (
        f"New-NetFirewallRule -DisplayName '{tcp_name}' -Direction Inbound "
        f"-Protocol TCP -LocalPort {port} -Action Block | Out-Null; "
        f"New-NetFirewallRule -DisplayName '{udp_name}' -Direction Inbound "
        f"-Protocol UDP -LocalPort {port} -Action Block | Out-Null"
    )


def _build_windows_unblock_port_command(port: int) -> str:
    """NOT verified live (same disclosure as the block command above).
    `-ErrorAction SilentlyContinue` keeps a repeat/stale unblock idempotent
    (mirrors the Linux `-D ... || true` pattern above) instead of
    surfacing a spurious `elevation_failed` when the named rule is already
    gone."""
    tcp_name, udp_name = _windows_block_port_rule_names(port)
    return (
        f"Remove-NetFirewallRule -DisplayName '{tcp_name}' -ErrorAction SilentlyContinue; "
        f"Remove-NetFirewallRule -DisplayName '{udp_name}' -ErrorAction SilentlyContinue"
    )


async def block_port(port: int, *, all_blocked_ports: list[int]) -> dict[str, Any]:
    """A-37: blocks `port` (both TCP and UDP) via a one-shot elevated OS
    admin prompt — see this section's own docstrings for exactly what each
    platform does. `all_blocked_ports` is the FULL set of ports (including
    `port` itself) the caller's own `blocked_ports` DB table now says
    should be blocked, fetched by the caller BEFORE this call (see
    `security_console.py`'s `perimeter_block_port`) — ONLY macOS's pf
    anchor branch actually needs the complete list
    (`_build_macos_sync_blocked_ports_script`'s own docstring explains
    why: pf has no single-rule-incremental-add primitive for anchor
    content); Linux/Windows both have a genuine single-rule add primitive
    and only ever touch the one rule for `port`, ignoring the rest of
    `all_blocked_ports`.

    Raises `OSFirewallError` on anything other than a clean `ok`
    (`elevation_cancelled`/`elevation_failed`/`not_configured`) — same
    contract as `block_all_incoming`/`unblock_all_incoming` above, mapped
    by the router's shared `_raise_for_os_firewall_error`."""
    reason_ru = _BLOCK_PORT_REASON_RU.format(port=port)
    reason_en = _BLOCK_PORT_REASON_EN.format(port=port)
    system = platform.system()
    if system == "Darwin":
        result = await _run_elevated_firewall_script(
            _build_macos_sync_blocked_ports_script(all_blocked_ports),
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    elif system == "Linux":
        result = await _run_elevated_firewall_script(
            _build_linux_block_port_script(port), reason_ru=reason_ru, reason_en=reason_en
        )
    elif system == "Windows":
        result = await elevated_run(
            ["powershell.exe", "-NoProfile", "-Command", _build_windows_block_port_command(port)],
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    else:
        raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "port": port, "blocked": True}


async def unblock_port(port: int, *, all_blocked_ports: list[int]) -> dict[str, Any]:
    """A-37: the reverse of `block_port()` above — same per-platform scope
    and the same raise-on-non-ok contract. `all_blocked_ports` here is the
    desired set with `port` already REMOVED (see
    `security_console.py`'s `perimeter_unblock_port`)."""
    reason_ru = _UNBLOCK_PORT_REASON_RU.format(port=port)
    reason_en = _UNBLOCK_PORT_REASON_EN.format(port=port)
    system = platform.system()
    if system == "Darwin":
        result = await _run_elevated_firewall_script(
            _build_macos_sync_blocked_ports_script(all_blocked_ports),
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    elif system == "Linux":
        result = await _run_elevated_firewall_script(
            _build_linux_unblock_port_script(port), reason_ru=reason_ru, reason_en=reason_en
        )
    elif system == "Windows":
        result = await elevated_run(
            ["powershell.exe", "-NoProfile", "-Command", _build_windows_unblock_port_command(port)],
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    else:
        raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "port": port, "blocked": False}


# ---------------------------------------------------------------------------
# A-37: persistent `blocked_ports` table — the durable record of which ports
# `block_port()`/`unblock_port()` above have genuinely applied, surviving a
# server restart (see db/models.py's `BlockedPort` docstring for the full
# "why", and for why — UNLIKE `clamav.record_scan_history`'s deliberate
# swallow-and-log discipline — the two write functions below do NOT swallow
# their own failures: this table is not just a history log, it is also the
# source of truth `block_port`/`unblock_port` themselves read back on every
# future call to reconstruct macOS's pf anchor, so a silently-lost write
# here would be a genuine correctness bug, not just a missing history row).
# ---------------------------------------------------------------------------


async def record_blocked_port(
    session: AsyncSession, *, port: int, protocol: str | None, process_name: str | None
) -> BlockedPort:
    """Written ONLY after `block_port()` above has already returned
    `status: "ok"` (see `security_console.py`'s `perimeter_block_port`,
    this function's sole caller) — an idempotent upsert: re-blocking an
    already-blocked port (e.g. a retried click) updates the existing row's
    `protocol`/`process_name`/`blocked_at` in place rather than raising a
    unique-constraint error on `port` (see `BlockedPort.port`'s own
    `unique=True`)."""
    existing = (await session.scalars(select(BlockedPort).where(BlockedPort.port == port))).first()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if existing is not None:
        existing.protocol = protocol
        existing.process_name = process_name
        existing.blocked_at = now
        await session.commit()
        return existing
    row = BlockedPort(port=port, protocol=protocol, process_name=process_name, blocked_at=now)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_blocked_ports(session: AsyncSession) -> list[BlockedPort]:
    """Every currently-blocked port, ascending by port number. Double duty:
    the READ side `security_console.py`'s `_perimeter_payload` calls to
    enrich each `ports[]` row with `is_blocked` (A-31's per-port list, A-37
    addendum), AND the INPUT `perimeter_block_port`/`perimeter_unblock_port`
    read BEFORE every single `block_port`/`unblock_port` call, to
    reconstruct macOS's own pf anchor content in full each time (see
    `_build_macos_sync_blocked_ports_script`'s own docstring for why a full
    reconstruction, not an incremental patch, is required there)."""
    rows = (await session.scalars(select(BlockedPort).order_by(BlockedPort.port))).all()
    return list(rows)


async def delete_blocked_port(session: AsyncSession, *, port: int) -> bool:
    """Written ONLY after `unblock_port()` above has already returned
    `status: "ok"` (see `security_console.py`'s `perimeter_unblock_port`,
    this function's sole caller). Returns `True` if a row for `port`
    existed and was removed, `False` if there was nothing to remove — an
    honest, non-error outcome (unblocking an already-unblocked port is a
    legitimate no-op, not a failure), never raised as an exception."""
    existing = (await session.scalars(select(BlockedPort).where(BlockedPort.port == port))).first()
    if existing is None:
        return False
    await session.delete(existing)
    await session.commit()
    return True


# ---------------------------------------------------------------------------
# A-52: per-IP blocking — the «Сеть» console's «Заблокировать» action (see
# docs/план-спецификация-фаза-0-сеть-доработка-2026-08-17.md). Mirrors A-37's
# per-port blocking above STRUCTURALLY (own anchor/chain, "regenerate the
# full desired set" on macOS, idempotent -C/-A on Linux, named
# New-NetFirewallRule on Windows, own persisted table) — deliberately a
# SEPARATE anchor/chain from A-37's own (`hranix-blocked-ports`/
# `HRANIX-BLOCKED`), not reused: a blocked PORT and a blocked IP are
# different enforcement scopes, conflating them into one anchor would make
# either one impossible to reason about/tear down independently. Chosen
# over routing this through CrowdSec's own ban mechanism (already real,
# `ban_ip()` below in this same file's sibling `crowdsec.py`) because that
# requires a machine-level LAPI credential this operator may not have
# configured at all (see crowdsec.py's own A-29 addendum) — this path
# works unconditionally, the same "always available" reasoning A-37's own
# port block already relies on.
# ---------------------------------------------------------------------------

MACOS_BLOCKED_IPS_ANCHOR = "hranix-blocked-ips"
LINUX_BLOCKED_IPS_CHAIN = "HRANIX-BLOCKED-IPS"

_BLOCK_IP_REASON_RU = "Hranix Shield: заблокировать адрес {ip}"
_BLOCK_IP_REASON_EN = "Hranix Shield: block address {ip}"
_UNBLOCK_IP_REASON_RU = "Hranix Shield: разблокировать адрес {ip}"
_UNBLOCK_IP_REASON_EN = "Hranix Shield: unblock address {ip}"


def _validate_ip(ip: str) -> str:
    """Every function below embeds `ip` straight into a shell script/
    PowerShell command string — unlike A-37's `port` (already an `int` by
    the time FastAPI's own path-parameter coercion lets a request through
    at all, see `_build_macos_sync_blocked_ports_script`'s own docstring),
    `ip` arrives here as a bare string with no such automatic guarantee.
    `ipaddress.ip_address()` is the validation AND the sanitisation: it
    only ever succeeds on a syntactically real IPv4/IPv6 address (no shell
    metacharacters, no hostnames, no CIDR ranges), and `str(...)` on its
    result is that same address in its own canonical form — never the
    caller's original, unvalidated text. Raises `OSFirewallError` with a
    new, honest `reason="invalid_ip"` (not `not_configured`/anything
    firewall-status-shaped) on anything else, checked by every public
    function in this section before it builds a single script line."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError as exc:
        raise OSFirewallError(f"not a valid IP address: {ip!r}", reason="invalid_ip") from exc


def _build_macos_sync_blocked_ips_script(ips: list[str]) -> str:
    """Same "pf anchors have no incremental primitive, regenerate the whole
    body every time" reasoning as
    `_build_macos_sync_blocked_ports_script` above — see that function's
    own docstring for the full explanation, identical here except scoped to
    `hranix-blocked-ips` and keyed on IP addresses rather than ports. Both
    directions (`from <ip>` and `to <ip>`) are blocked — unlike a port
    (always "this host listening"), a blocked IP could be either the
    initiator (an inbound attacker) or the remote end of a connection this
    host itself opened, and an operator blocking a suspicious remote
    address from the «Сеть» console's connections table means "have
    nothing more to do with this address", not one direction only."""
    lines: list[str] = []
    for ip in sorted(set(ips)):
        lines.append(f"block in from {ip} to any")
        lines.append(f"block out from any to {ip}")
    body = "\n".join(lines)
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/pfctl -a {MACOS_BLOCKED_IPS_ANCHOR} -f - <<'HRANIX_EOF'\n"
        f"{body}\n"
        "HRANIX_EOF\n"
    )


def _build_linux_block_ip_script(ip: str) -> str:
    """NOT verified live (this dev machine is macOS — same disclosure
    every other unverified Linux branch in this file already carries).
    Same idempotent `-C`-then-`-A` primitive `_build_linux_block_port_script`
    already uses, blocking both directions for `ip` (see the macOS
    function's own docstring above for why both, not just inbound)."""
    chain = LINUX_BLOCKED_IPS_CHAIN
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/iptables -N {chain} 2>/dev/null || true\n"
        f"/sbin/iptables -C INPUT -j {chain} 2>/dev/null || /sbin/iptables -I INPUT 1 -j {chain}\n"
        f"/sbin/iptables -C OUTPUT -j {chain} 2>/dev/null || /sbin/iptables -I OUTPUT 1 -j {chain}\n"
        f"/sbin/iptables -C {chain} -s {ip} -j DROP 2>/dev/null || /sbin/iptables -A {chain} -s {ip} -j DROP\n"
        f"/sbin/iptables -C {chain} -d {ip} -j DROP 2>/dev/null || /sbin/iptables -A {chain} -d {ip} -j DROP\n"
    )


def _build_linux_unblock_ip_script(ip: str) -> str:
    """NOT verified live (same disclosure as the block script above). `-D`
    on an absent rule exits non-zero — `|| true` keeps a repeat/stale
    unblock idempotent, same as `_build_linux_unblock_port_script`."""
    chain = LINUX_BLOCKED_IPS_CHAIN
    return (
        "#!/bin/bash\nset -e\n"
        f"/sbin/iptables -D {chain} -s {ip} -j DROP 2>/dev/null || true\n"
        f"/sbin/iptables -D {chain} -d {ip} -j DROP 2>/dev/null || true\n"
    )


def _windows_block_ip_rule_name(ip: str) -> str:
    """Mirrors `_windows_block_port_rule_names` above — one recognisable,
    precisely name-matchable `-DisplayName` (a single rule covers both
    directions via `-RemoteAddress`, unlike the port case which needs
    separate TCP/UDP rules)."""
    return f"Hranix Shield - Block IP {ip}"


def _build_windows_block_ip_command(ip: str) -> str:
    """NOT verified live (same disclosure as `_build_windows_block_port_command`
    above — read that function's own docstring for why single-quoted
    PowerShell literals throughout are required here, not double-quoted).
    One rule, `-Direction` omitted (defaults to matching both — this
    project wants both directions blocked, same reasoning as the macOS/
    Linux branches above)."""
    name = _windows_block_ip_rule_name(ip)
    return (
        f"New-NetFirewallRule -DisplayName '{name}' -RemoteAddress {ip} "
        f"-Action Block | Out-Null"
    )


def _build_windows_unblock_ip_command(ip: str) -> str:
    """NOT verified live (same disclosure as the block command above)."""
    name = _windows_block_ip_rule_name(ip)
    return f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue"


async def block_ip(ip: str, *, all_blocked_ips: list[str]) -> dict[str, Any]:
    """A-52: blocks `ip` (both directions) via a one-shot elevated OS admin
    prompt — see this section's own docstrings for exactly what each
    platform does. `all_blocked_ips` mirrors `block_port`'s own
    `all_blocked_ports` — the FULL desired set, only actually needed by
    macOS's pf-anchor branch, ignored by Linux/Windows (both have a real
    single-rule primitive). Raises `OSFirewallError`
    (`elevation_cancelled`/`elevation_failed`/`not_configured`/
    `invalid_ip`) on anything other than a clean `ok`."""
    ip = _validate_ip(ip)
    all_blocked_ips = [_validate_ip(existing) for existing in all_blocked_ips]
    reason_ru = _BLOCK_IP_REASON_RU.format(ip=ip)
    reason_en = _BLOCK_IP_REASON_EN.format(ip=ip)
    system = platform.system()
    if system == "Darwin":
        result = await _run_elevated_firewall_script(
            _build_macos_sync_blocked_ips_script(all_blocked_ips),
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    elif system == "Linux":
        result = await _run_elevated_firewall_script(
            _build_linux_block_ip_script(ip), reason_ru=reason_ru, reason_en=reason_en
        )
    elif system == "Windows":
        result = await elevated_run(
            ["powershell.exe", "-NoProfile", "-Command", _build_windows_block_ip_command(ip)],
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    else:
        raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "ip": ip, "blocked": True}


async def unblock_ip(ip: str, *, all_blocked_ips: list[str]) -> dict[str, Any]:
    """A-52: the reverse of `block_ip()` above — same per-platform scope
    and raise-on-non-ok contract. `all_blocked_ips` is the desired set with
    `ip` already REMOVED."""
    ip = _validate_ip(ip)
    all_blocked_ips = [_validate_ip(existing) for existing in all_blocked_ips]
    reason_ru = _UNBLOCK_IP_REASON_RU.format(ip=ip)
    reason_en = _UNBLOCK_IP_REASON_EN.format(ip=ip)
    system = platform.system()
    if system == "Darwin":
        result = await _run_elevated_firewall_script(
            _build_macos_sync_blocked_ips_script(all_blocked_ips),
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    elif system == "Linux":
        result = await _run_elevated_firewall_script(
            _build_linux_unblock_ip_script(ip), reason_ru=reason_ru, reason_en=reason_en
        )
    elif system == "Windows":
        result = await elevated_run(
            ["powershell.exe", "-NoProfile", "-Command", _build_windows_unblock_ip_command(ip)],
            reason_ru=reason_ru,
            reason_en=reason_en,
        )
    else:
        raise OSFirewallError(f"unsupported platform: {system!r}", reason="not_configured")
    if result.status != "ok":
        _raise_for_elevated_result(result)
    return {"status": "ok", "ip": ip, "blocked": False}


# ---------------------------------------------------------------------------
# A-52: persistent `blocked_ips` table — mirrors `blocked_ports`' own
# "source of truth `block_ip`/`unblock_ip` read back on every future call,
# writes never swallowed" reasoning, see `list_blocked_ports`'s own
# docstring above for the full explanation.
# ---------------------------------------------------------------------------


async def record_blocked_ip(
    session: AsyncSession,
    *,
    ip: str,
    country: str | None,
    process_name: str | None,
    reason: str | None,
) -> BlockedIp:
    """Written ONLY after `block_ip()` above has already returned
    `status: "ok"` — same idempotent upsert as `record_blocked_port`."""
    existing = (await session.scalars(select(BlockedIp).where(BlockedIp.ip == ip))).first()
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if existing is not None:
        existing.country = country
        existing.process_name = process_name
        existing.reason = reason
        existing.blocked_at = now
        await session.commit()
        return existing
    row = BlockedIp(ip=ip, country=country, process_name=process_name, reason=reason, blocked_at=now)
    session.add(row)
    await session.commit()
    await session.refresh(row)
    return row


async def list_blocked_ips(session: AsyncSession) -> list[BlockedIp]:
    """Every currently-blocked IP — same double duty as `list_blocked_ports`
    (read side for display, input side `block_ip`/`unblock_ip` read before
    every call to reconstruct macOS's pf anchor in full)."""
    rows = (await session.scalars(select(BlockedIp).order_by(BlockedIp.ip))).all()
    return list(rows)


async def delete_blocked_ip(session: AsyncSession, *, ip: str) -> bool:
    """Written ONLY after `unblock_ip()` above has already returned
    `status: "ok"`. `True` if a row existed and was removed, `False` if
    there was nothing to remove (an honest no-op, never an error)."""
    existing = (await session.scalars(select(BlockedIp).where(BlockedIp.ip == ip))).first()
    if existing is None:
        return False
    await session.delete(existing)
    await session.commit()
    return True


def register_os_firewall_connector(registry: MCPRegistry) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as `crowdsec.register_crowdsec_connector`, see that
    function's docstring for what this is (and is not) for."""
    registry.register(
        MCPConnector(
            name=OS_FIREWALL_CONNECTOR_NAME,
            description=(
                "OS firewall status (pf/Application Firewall on macOS, "
                "Windows Defender Firewall via netsh, ufw/iptables on "
                "Linux) — read locally via subprocess, never linked into "
                "this process."
            ),
            transport="subprocess",
            endpoint="",
        )
    )
