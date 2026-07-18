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

import logging
import platform
import re
from typing import Any

from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    looks_like_permission_denied,
    run_local_command,
)

logger = logging.getLogger(__name__)

OS_FIREWALL_CONNECTOR_NAME = "os_firewall"

_SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class OSFirewallError(RuntimeError):
    """`reason` is one of `"not_configured"` / `"permission_denied"` /
    `"unreachable"` — see this module's docstring."""

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


async def _windows_firewall_active() -> bool:
    """`netsh advfirewall show allprofiles` lists the Domain/Private/Public
    profiles, each with a `State` line (`ON`/`OFF`). Reported as active only
    when *every* profile is `ON` — any profile off is a real posture gap,
    matching how Windows' own Security Center badge behaves, not a detail to
    average away.

    Not verified against a real Windows host while building this task (dev
    machine is macOS, per CLAUDE.md's own verification-discipline note this
    is disclosed rather than silently assumed) — implemented from
    documented `netsh` output; flagged in the task report as a
    verify-on-Windows follow-up.
    """
    returncode, stdout, stderr = await _run("netsh", "advfirewall", "show", "allprofiles")
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSFirewallError("netsh advfirewall requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSFirewallError(f"netsh advfirewall exited {returncode}: {stderr.strip()}", reason="unreachable")

    states = re.findall(r"State\s+(ON|OFF)", stdout, flags=re.IGNORECASE)
    if not states:
        raise OSFirewallError("could not parse netsh advfirewall output", reason="unreachable")
    return all(state.upper() == "ON" for state in states)


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
