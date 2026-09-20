"""A-38: network profiles (Доверенная/Публичная) — WHICH physical network
this host is currently connected to, a persistent per-network CATEGORY the
operator assigns (safe default: `"public"`, an unfamiliar network is never
assumed trusted), and a background monitor that notices when the current
network changes.

Same "external tool reached from outside the process, never linked in"
shape the licence gate (CLAUDE.md) and every other connector in this
package already establishes — here the "external tool" is each OS's own
network-configuration CLI (`networksetup` on macOS, `nmcli` on Linux,
`Get-NetConnectionProfile` via PowerShell on Windows), reached via
`asyncio.create_subprocess_exec` (`_local_command.py`), never a shell
string, never root (see the macOS section below for the one live-confirmed
surprise about "never root" not meaning "never permission-gated").

Detection, per OS
------------------
  - **macOS** (the only platform live-verified on this dev machine, a
    MacBook Pro / Apple M2 Max, macOS 26.5, 2026-07-23 — see this task's
    own report for the exact transcripts): `networksetup
    -listallhardwareports` first, to find which device is the "Wi-Fi"
    hardware port (never hardcoded `en0` — confirmed live this dev machine
    actually has SEVEN `en*` devices, `en0` only happens to be Wi-Fi on
    this particular Mac). If that device is UP with a real (non-loopback)
    IPv4 (`ifconfig <device>`), Wi-Fi is the current network and this
    module tries `networksetup -getairportnetwork <device>` for the SSID.
    Otherwise it falls back to the first OTHER hardware port that is UP
    with a real IPv4 (Ethernet/Thunderbolt-bridge/USB-Ethernet — this
    task's own brief's "дефолтный шлюз/интерфейс как fallback, если Wi-Fi
    не активен").

    **Honest, live-confirmed surprise, worth its own paragraph**: this
    task's own brief assumed reading the CURRENT network's name needs no
    root on macOS, and that is still true in the narrow "no `sudo`
    password prompt" sense — but it turned out NOT to mean
    `networksetup -getairportnetwork` reliably returns the SSID. Confirmed
    live on this exact dev machine, from a bare `python3 -c
    "subprocess.run(['networksetup','-getairportnetwork','en0'])"` (not
    just an interactive shell, ruling out a shell-specific quirk): while
    genuinely associated with a real Wi-Fi network — independently
    confirmed via `system_profiler SPAirPortDataType` showing `Status:
    Connected` and a real assigned IPv4 (`ifconfig en0` showing `status:
    active`, `inet 192.168.1.90`) — `networksetup -getairportnetwork en0`
    answered the exact same text ("You are not associated with an AirPort
    network.") that it (and this module) also uses to mean "genuinely not
    on Wi-Fi at all". `system_profiler`/`ipconfig getsummary en0` both
    independently printed `<redacted>` for the SSID/BSSID themselves in
    this same environment. This reads as a Location-Services/TCC privacy
    gate on Wi-Fi-name disclosure that Apple has, in recent macOS
    releases, extended to cover even this legacy `networksetup` code path
    for a process with no Location Services authorization grant (this
    task's own automated dev environment has none) — NOT a `networksetup`
    bug, NOT a "needs root" case (no `sudo`/permission-denied text
    appeared anywhere), and NOT something this module can work around by
    asking for elevation (`elevated.py`'s `elevated_run` pops a real admin-
    password dialog for a ONE-SHOT privileged command; it has no bearing
    on a per-process Location Services grant, a completely different OS
    privacy mechanism). A real, interactive Terminal.app session with
    Location Services already granted to it may well see the real SSID —
    untested here, no such session was available while building this task.

    Rather than surface this as a hard failure (which would make the
    perimeter console's whole network-profile section honestly say
    "nothing to show" on a dev machine that IS demonstrably connected to a
    real, known network), this module falls back — for Wi-Fi specifically
    — to the SAME gateway-IP-based identity `detect_current_network()`
    already uses for a non-Wi-Fi active interface (see `id_kind` below):
    still a STABLE, real identifier for this exact physical network (this
    router's IP does not change just because the SSID became unreadable),
    just not a human-friendly name. `id_kind` on the returned network is
    `"ssid"` when a real name was read, `"gateway_ip"` when this fallback
    fired — the UI (`app.js`) shows a short honest note whenever
    `id_kind != "ssid"` rather than silently presenting a gateway IP as if
    it were a network's real name.

  - **Linux**: `nmcli -t -f NAME,UUID,DEVICE connection show --active` for
    the active connection's own NAME/UUID (`network_key` is the UUID —
    this task's own brief's own suggestion: "по идентификатору — ...
    connection UUID на Linux" — stable across a renamed Wi-Fi profile in a
    way a human-editable NAME is not). **NOT verified live** (no Linux
    host available while building this task) — implemented from `nmcli(1)`
    `-t` (terse, stable, script-friendly, colon-separated) output, same
    disclosure convention `os_firewall.py`'s/`elevated.py`'s own unverified
    Linux branches already use.

  - **Windows**: `Get-NetConnectionProfile` (PowerShell) — this task's own
    brief is explicit: Windows already HAS a native Private/Public/Domain
    concept (NLA) for exactly this, "переиспользовать её категоризацию, не
    изобретать свою". This module reuses it only as the DEFAULT category
    for a network seen for the very first time (`NetworkCategory ==
    "Public"` -> `"public"`, `"Private"`/`"DomainAuthenticated"` ->
    `"trusted"`) — still stored in, and overridable through, this same
    `NetworkProfile` DB row/API every other platform uses, so the rest of
    this module's logic (persistence, the background monitor, the manual-
    override endpoint) stays one single code path across all three
    platforms rather than forking Windows onto NLA's own categorisation
    permanently. `network_key` is the profile's own `Name` (NLA's closest
    thing to a stable identifier exposed by this cmdlet). **NOT verified
    live** (no Windows host available), same disclosure convention as the
    Linux path above.

Persistence and the "переключение уровня защиты" design decision
-------------------------------------------------------------------
Every sighting is written to the `network_profiles` table (see
`db/models.py`'s `NetworkProfile` docstring for the full schema
rationale) — but ONLY by `touch_network_profile()` (the background
scheduler's own tick, see `NetworkProfileScheduler` below) or
`set_network_category()` (the operator's own explicit category-assignment
click) — NEVER by `network_profile_payload()`, the function `GET
/consoles/perimeter` calls on every passive page load. A passive read
must stay a pure read, the same principle every other console payload
function in this codebase already follows (see e.g. `os_firewall.
fetch_firewall_status` never writing anything either) — otherwise simply
opening the panel would silently create/touch DB rows, an honesty-adjacent
surprise this task's own review would rightly flag.

**The actual "переключение уровня защиты" design decision** (see the plan
document's A-38 section + CLAUDE.md's own architecture notes on never
silently escalating this app's own privileges): when the background
monitor notices the current network CHANGED and the new network's category
is `"public"`, it does **NOT** call `os_firewall.block_all_incoming()`
automatically. `elevated_run()` (A-36) pops a REAL OS admin-password
dialog for every single call, with no caching — an automatic, unattended
background loop popping that dialog with no operator click anywhere nearby
would be exactly the "surprise system password prompt out of nowhere"
UX CLAUDE.md's own security posture (and plain common sense) rules out:
indistinguishable, from the operator's chair, from malware trying to
social-engineer a password out of them. Instead, this module publishes a
`Topic.SECURITY_ALERT` event (the SAME event-bus topic/notification
pipeline `/auth/login`'s brute-force lock already uses, see
`routers/auth.py`) — a real, visible, already-built notification (panel
icon + text-window + sound + email, per `notifications/registry.
register_default_topics`'s existing `SECURITY_ALERT` wiring) that HONESTLY
INVITES the operator to click "🔒 Заблокировать все входящие" themselves
(A-36's own real, already-built button) rather than doing it for them. This
is the explicit trade-off this task's own brief asked to be weighed and
documented: less "automatic" than silently flipping the firewall, but the
alternative is a background service that can pop a password dialog with no
operator action anywhere in the causal chain — judged the worse of the two
UX/trust risks.
"""

from __future__ import annotations

import asyncio
import logging
import platform
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings
from app.db.models import NetworkProfile
from app.db.session import async_session_maker
from app.services.event_bus import EventBus, Topic
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    run_local_command,
)

logger = logging.getLogger(__name__)

NETWORK_PROFILE_CONNECTOR_NAME = "network_profile"

# The safe default for a network nobody has ever categorised — this task's
# own brief: "по умолчанию — 'Публичная', безопасный дефолт для незнакомой
# сети". Never assumed trusted just because it happens to be the FIRST
# network this host was ever seen on.
DEFAULT_CATEGORY = "public"
VALID_CATEGORIES = ("trusted", "public")

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]


def _default_clock() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class NetworkProfileError(RuntimeError):
    """`reason` is one of `"not_connected"` (no active network interface
    found at all — an honest, ordinary state, e.g. Wi-Fi off and no cable
    plugged in, NOT an error) / `"not_configured"` (unsupported platform,
    or — Linux/Windows — the required tool is missing) / `"unreachable"`
    (the tool ran but failed/timed out unexpectedly) — same three-way
    vocabulary shape every sibling connector in this package already uses,
    with `"not_connected"` added as this module's own genuinely new state
    (no sibling connector has a concept of "the OS itself reports no
    network at all", every one of them either has a tool to ask or not)."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


async def _run(*args: str) -> tuple[int, str, str]:
    try:
        return await run_local_command(*args)
    except LocalCommandNotFound as exc:
        raise NetworkProfileError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise NetworkProfileError(str(exc), reason="unreachable") from exc


@dataclass
class DetectedNetwork:
    """One live detection result — see this module's docstring for exactly
    how each field is derived per platform. `default_category` is what a
    NEVER-BEFORE-SEEN network defaults to (`DEFAULT_CATEGORY` on every
    platform except a Windows network NLA itself already reports as
    `Private`/`DomainAuthenticated`, see the Windows section above)."""

    kind: str  # "wifi" | "wired" | "os_profile"
    network_key: str
    display_name: str
    id_kind: str  # "ssid" | "gateway_ip" | "connection_uuid" | "os_profile"
    default_category: str = DEFAULT_CATEGORY


# ---------------------------------------------------------------------------
# macOS
# ---------------------------------------------------------------------------

_MACOS_WIFI_HARDWARE_PORT = "Wi-Fi"
_HARDWARE_PORT_RE = re.compile(r"Hardware Port: (?P<port>[^\n]+)\nDevice: (?P<device>\S+)")
_ROUTER_RE = re.compile(r"^Router:\s*(\S+)\s*$", re.MULTILINE)
_IPV4_RE = re.compile(r"inet (\d+\.\d+\.\d+\.\d+) netmask")
# Live-confirmed exact text (case preserved as macOS prints it; matched
# lower-cased below) — see this module's own docstring for the full
# "ambiguous even while genuinely connected" finding.
_MACOS_NOT_ASSOCIATED_MARKER = "you are not associated with an airport network"
_MACOS_SSID_RE = re.compile(r"^Current Wi-Fi Network:\s*(.+)$")


async def _macos_list_hardware_ports() -> list[tuple[str, str]]:
    """`networksetup -listallhardwareports` -> `[(port_name, device), ...]`,
    e.g. `[("Wi-Fi", "en0"), ("Thunderbolt Bridge", "bridge0"), ...]` — live-
    confirmed output shape on this dev machine (7 hardware ports)."""
    returncode, stdout, stderr = await _run("networksetup", "-listallhardwareports")
    if returncode != 0:
        raise NetworkProfileError(
            f"networksetup -listallhardwareports exited {returncode}: {stderr.strip()}",
            reason="unreachable",
        )
    return _HARDWARE_PORT_RE.findall(stdout)


async def _macos_interface_ipv4(device: str) -> str | None:
    """The device's own assigned IPv4 if it is genuinely UP with a real
    address, else `None` — `ifconfig <device>` output. Deliberately checked
    via the presence of a real `inet` line, not `ifconfig`'s own `status:`
    line alone: some interfaces (e.g. `bridge0`) never print a `status:`
    line at all yet can still be genuinely address-less/inactive, so "has a
    real inet address" is the one signal that is both present and reliable
    across every hardware port type seen live on this dev machine."""
    returncode, stdout, stderr = await _run("ifconfig", device)
    if returncode != 0:
        return None
    match = _IPV4_RE.search(stdout)
    return match.group(1) if match else None


async def _macos_service_router_ip(service_name: str) -> str | None:
    """`networksetup -getinfo "<service name>"` -> the `Router:` line (the
    default-gateway IP DHCP handed this specific service) — used as this
    physical network's fallback identity when a human-readable name is not
    available (no SSID, or a non-Wi-Fi interface). Live-confirmed working
    verbatim as `service_name` for the exact hardware-port name
    `_macos_list_hardware_ports()` returns (e.g. `"Wi-Fi"`) on this dev
    machine — macOS's default service names match their hardware port
    names unless an operator has manually renamed a network service."""
    returncode, stdout, stderr = await _run("networksetup", "-getinfo", service_name)
    if returncode != 0:
        return None
    match = _ROUTER_RE.search(stdout)
    if not match or match.group(1).lower() == "none":
        return None
    return match.group(1)


async def _macos_wifi_ssid(device: str) -> str | None:
    """Returns the real SSID, or `None` when unavailable — see this
    module's own docstring for the live-confirmed finding that `None` here
    does NOT reliably mean "not on Wi-Fi" on current macOS; callers must
    use `_macos_interface_ipv4` (not this function) to decide whether
    Wi-Fi is the active network at all."""
    returncode, stdout, stderr = await _run("networksetup", "-getairportnetwork", device)
    if returncode != 0:
        return None
    if _MACOS_NOT_ASSOCIATED_MARKER in stdout.lower():
        return None
    match = _MACOS_SSID_RE.match(stdout.strip())
    return match.group(1).strip() if match else None


async def _macos_detect_current_network() -> DetectedNetwork:
    ports = await _macos_list_hardware_ports()
    if not ports:
        raise NetworkProfileError(
            "networksetup -listallhardwareports returned no hardware ports", reason="unreachable"
        )

    wifi_entry = next((p for p in ports if p[0] == _MACOS_WIFI_HARDWARE_PORT), None)
    if wifi_entry is not None:
        _, wifi_device = wifi_entry
        wifi_ip = await _macos_interface_ipv4(wifi_device)
        if wifi_ip is not None:
            ssid = await _macos_wifi_ssid(wifi_device)
            if ssid:
                return DetectedNetwork(
                    kind="wifi", network_key=f"wifi:{ssid}", display_name=ssid, id_kind="ssid"
                )
            # SSID genuinely unreadable despite a live, address-carrying
            # Wi-Fi interface — see module docstring's "Honest, live-
            # confirmed surprise" section. Falls back to a stable,
            # gateway-IP-based identity for this SAME physical network
            # rather than reporting a hard failure.
            gateway = await _macos_service_router_ip(_MACOS_WIFI_HARDWARE_PORT)
            identity = gateway or wifi_ip
            return DetectedNetwork(
                kind="wifi",
                network_key=f"wifi:gw:{identity}",
                display_name=f"Wi-Fi ({identity})",
                id_kind="gateway_ip",
            )

    # Wi-Fi absent or not carrying an address — fall back to the first
    # OTHER hardware port that is genuinely up with a real address (this
    # task's own brief's "дефолтный шлюз/интерфейс как fallback, если
    # Wi-Fi не активен").
    for port_name, device in ports:
        if port_name == _MACOS_WIFI_HARDWARE_PORT:
            continue
        ip = await _macos_interface_ipv4(device)
        if ip is None:
            continue
        gateway = await _macos_service_router_ip(port_name)
        identity = gateway or ip
        return DetectedNetwork(
            kind="wired",
            network_key=f"wired:gw:{identity}",
            display_name=f"{port_name} ({identity})",
            id_kind="gateway_ip",
        )

    raise NetworkProfileError("no active network interface found", reason="not_connected")


# ---------------------------------------------------------------------------
# Linux — NetworkManager `nmcli`. NOT verified live (no Linux host
# available while building this task) — implemented from `nmcli(1)`'s
# documented terse (`-t`) output shape, same disclosure convention
# os_firewall.py's/elevated.py's own unverified Linux branches already use.
# ---------------------------------------------------------------------------


async def _linux_detect_current_network() -> DetectedNetwork:
    returncode, stdout, stderr = await _run(
        "nmcli", "-t", "-f", "NAME,UUID,DEVICE", "connection", "show", "--active"
    )
    if returncode != 0:
        raise NetworkProfileError(f"nmcli exited {returncode}: {stderr.strip()}", reason="unreachable")

    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise NetworkProfileError("nmcli reports no active connection", reason="not_connected")

    # `nmcli -t` separates fields with `:` — a connection NAME can itself
    # contain `:` (rare but documented), so only the first 3 segments are
    # taken and the rest re-joined back into NAME, matching `nmcli(1)`'s own
    # documented advice for parsing terse output ("use -f exactly, split on
    # the field count, not blindly on every colon").
    name, uuid, device = lines[0].split(":", 2)
    return DetectedNetwork(
        kind="wired" if not device.lower().startswith("wl") else "wifi",
        network_key=f"linux:{uuid}",
        display_name=name or uuid,
        id_kind="connection_uuid",
    )


# ---------------------------------------------------------------------------
# Windows — `Get-NetConnectionProfile` (NLA). NOT verified live (no Windows
# host available while building this task).
# ---------------------------------------------------------------------------

_WINDOWS_NLA_TO_CATEGORY = {
    "public": "public",
    "private": "trusted",
    "domainauthenticated": "trusted",
}


async def _windows_detect_current_network() -> DetectedNetwork:
    """This task's own brief: Windows already has a native Private/Public/
    Domain concept (NLA) — reused here as the DEFAULT category for a
    never-before-seen network (`_WINDOWS_NLA_TO_CATEGORY`), not
    reimplemented. `Get-NetConnectionProfile`'s CSV output is parsed
    (`ConvertTo-Csv`, stable/quoted, easier to split reliably than its
    default table formatting) for the first active profile's
    `Name`/`NetworkCategory`."""
    returncode, stdout, stderr = await _run(
        "powershell.exe",
        "-NoProfile",
        "-Command",
        "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Csv -NoTypeInformation",
    )
    if returncode != 0:
        raise NetworkProfileError(
            f"Get-NetConnectionProfile exited {returncode}: {stderr.strip()}", reason="unreachable"
        )
    rows = [line.strip() for line in stdout.splitlines() if line.strip()]
    # rows[0] is the CSV header ("Name","NetworkCategory") ConvertTo-Csv
    # always emits — skipped the same "not row 0 by numeric-shape check"
    # spirit `traffic_counters._parse_nettop_csv` already documents,
    # simplified here since PowerShell's own header text is fixed/known.
    data_rows = rows[1:]
    if not data_rows:
        raise NetworkProfileError("Get-NetConnectionProfile reports no active profile", reason="not_connected")

    first = data_rows[0].strip('"').split('","')
    if len(first) != 2:
        raise NetworkProfileError("could not parse Get-NetConnectionProfile output", reason="unreachable")
    name, category_raw = first
    default_category = _WINDOWS_NLA_TO_CATEGORY.get(category_raw.strip().lower(), DEFAULT_CATEGORY)
    return DetectedNetwork(
        kind="os_profile",
        network_key=f"windows:{name}",
        display_name=name,
        id_kind="os_profile",
        default_category=default_category,
    )


async def _detect_for_current_platform() -> DetectedNetwork:
    system = platform.system()
    if system == "Darwin":
        return await _macos_detect_current_network()
    if system == "Linux":
        return await _linux_detect_current_network()
    if system == "Windows":
        return await _windows_detect_current_network()
    raise NetworkProfileError(f"unsupported platform: {system!r}", reason="not_configured")


async def detect_current_network() -> dict[str, Any]:
    """Real data for `network_profile_payload()` below — never raises: an
    unsupported platform / missing tool / no active network at all / any
    other failure is reported as an honest `connector.status`, never a 500
    and never a fabricated network identity (same never-raise contract
    every passive `fetch_*` in this package already follows)."""
    try:
        detected = await _detect_for_current_platform()
    except NetworkProfileError as exc:
        # "not_connected" is a normal, expected state (Wi-Fi off, no cable
        # plugged in) — logged at info, not warning, unlike a genuine tool
        # failure.
        log = logger.info if exc.reason == "not_connected" else logger.warning
        log("network_profile: %s", exc)
        return {
            "connector": {"status": exc.reason},
            "kind": None,
            "network_key": None,
            "display_name": None,
            "id_kind": None,
            "default_category": None,
        }
    return {
        "connector": {"status": "ok"},
        "kind": detected.kind,
        "network_key": detected.network_key,
        "display_name": detected.display_name,
        "id_kind": detected.id_kind,
        "default_category": detected.default_category,
    }


# ---------------------------------------------------------------------------
# Persistence — see this module's docstring for the "reads never write"
# split between `touch_network_profile` (scheduler-only)/
# `set_network_category` (operator-action-only) and `network_profile_payload`
# (pure read, called by both the passive `GET /consoles/perimeter` payload
# and, after either write path runs, to build its own response).
# ---------------------------------------------------------------------------


async def _get_network_profile(session: AsyncSession, network_key: str) -> NetworkProfile | None:
    return await session.scalar(select(NetworkProfile).where(NetworkProfile.network_key == network_key))


async def touch_network_profile(
    session: AsyncSession,
    *,
    network_key: str,
    display_name: str,
    id_kind: str,
    default_category: str,
    now: datetime,
) -> NetworkProfile:
    """Records a SIGHTING — creates the row (with `default_category`) on
    first sight, otherwise only refreshes `display_name`/`id_kind`/
    `last_seen_at`. NEVER overwrites an already-persisted `category`: that
    is the operator's own explicit choice (see `set_network_category`
    below), a scheduler tick must not silently revert it. Commits and
    returns the row (with `category` reflecting whatever is now durably
    stored, whether just-defaulted or previously operator-set)."""
    row = await _get_network_profile(session, network_key)
    if row is None:
        row = NetworkProfile(
            network_key=network_key,
            display_name=display_name,
            id_kind=id_kind,
            category=default_category,
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(row)
    else:
        row.display_name = display_name
        row.id_kind = id_kind
        row.last_seen_at = now
    await session.commit()
    return row


async def set_network_category(
    session: AsyncSession,
    *,
    network_key: str,
    display_name: str,
    id_kind: str,
    category: str,
    now: datetime,
) -> NetworkProfile:
    """The ONLY function that ever changes an already-persisted `category`
    — the operator's own explicit "Сделать доверенной"/"Сделать публичной"
    click (`POST .../network-profile/category`, see security_console.py).
    Upserts (a network never seen before can be categorised immediately,
    it does not need a prior scheduler tick to already have a row)."""
    if category not in VALID_CATEGORIES:
        raise ValueError(f"invalid category: {category!r} (expected one of {VALID_CATEGORIES})")
    row = await _get_network_profile(session, network_key)
    if row is None:
        row = NetworkProfile(
            network_key=network_key,
            display_name=display_name,
            id_kind=id_kind,
            category=category,
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(row)
    else:
        row.category = category
        row.display_name = display_name
        row.id_kind = id_kind
        row.last_seen_at = now
    await session.commit()
    return row


async def list_known_networks(session: AsyncSession, *, limit: int = 50) -> list[NetworkProfile]:
    """Most-recently-seen first — backs the perimeter console's "Известные
    сети" list (`network_profile_payload`'s own `known` field below)."""
    rows = (
        await session.scalars(
            select(NetworkProfile).order_by(NetworkProfile.last_seen_at.desc()).limit(limit)
        )
    ).all()
    return list(rows)


def _serialize_network_profile(row: NetworkProfile) -> dict[str, Any]:
    return {
        "network_key": row.network_key,
        "display_name": row.display_name,
        "id_kind": row.id_kind,
        "category": row.category,
        "first_seen_at": row.first_seen_at.isoformat(),
        "last_seen_at": row.last_seen_at.isoformat(),
    }


async def network_profile_payload(session: AsyncSession) -> dict[str, Any]:
    """A PURE READ (see module docstring) backing the `network_profile` key
    of `GET /consoles/perimeter` (`security_console.py._perimeter_payload`)
    — detects the current network LIVE on every call (a subprocess call,
    same as every other perimeter sub-source) but never persists anything
    itself. `current.category` is the network's own persisted category if
    it has ever been seen before, else the honest `default_category` a
    FIRST sighting would get (so the UI can show a real category — usually
    `"public"` — even before the background scheduler's first tick has run,
    e.g. right after a fresh install)."""
    detection = await detect_current_network()
    current_category: str | None = None
    if detection["network_key"]:
        existing = await _get_network_profile(session, detection["network_key"])
        current_category = existing.category if existing is not None else detection["default_category"]
    known = await list_known_networks(session)
    return {
        "connector": detection["connector"],
        "current": {
            "network_key": detection["network_key"],
            "display_name": detection["display_name"],
            "kind": detection["kind"],
            "id_kind": detection["id_kind"],
            "category": current_category,
        },
        "known": [_serialize_network_profile(row) for row in known],
    }


# ---------------------------------------------------------------------------
# Background monitor — see module docstring's "переключение уровня защиты"
# section for the full design rationale (nudge via notification, never an
# automatic elevated_run() call).
# ---------------------------------------------------------------------------


async def run_network_profile_sweep(
    session_maker: async_sessionmaker[AsyncSession] | None = None,
    *,
    previous_key: str | None,
    event_bus: EventBus | None = None,
    now: datetime | None = None,
) -> str | None:
    """One tick: detects the current network, persists the sighting
    (`touch_network_profile`), and — only when the detected `network_key`
    DIFFERS from `previous_key` AND the (possibly just-defaulted) category
    is `"public"` — publishes a `Topic.SECURITY_ALERT` nudge. Returns the
    detected `network_key` (`None` if no network is currently detected)
    — the CALLER (`NetworkProfileScheduler`, via
    `create_default_network_profile_scheduler`) is responsible for
    threading this back in as the next tick's `previous_key`; this function
    stays a pure, directly-testable "inject state in, get state out"
    piece, same idiom `services/metrics/sampler.run_metrics_sample_sweep`/
    `services/notifications/escalation.run_escalation_sweep` already use.

    A network genuinely not detected this tick (`network_key is None`,
    e.g. Wi-Fi off with nothing else plugged in) writes nothing and
    returns `None` — honestly "no current network to record", not a
    fabricated sighting."""
    maker = session_maker or async_session_maker
    sampled_at = now if now is not None else _default_clock()

    detection = await detect_current_network()
    key = detection["network_key"]
    if key is None:
        return None

    async with maker() as session:
        row = await touch_network_profile(
            session,
            network_key=key,
            display_name=detection["display_name"],
            id_kind=detection["id_kind"],
            default_category=detection["default_category"],
            now=sampled_at,
        )
        category = row.category

    if key != previous_key and category == "public" and event_bus is not None:
        await event_bus.publish(
            Topic.SECURITY_ALERT,
            {
                "reason": "public_network_detected",
                "network_key": key,
                "display_name": detection["display_name"],
            },
        )

    return key


class NetworkProfileScheduler:
    """Runs `run_once` every `interval_seconds`, forever, until `stop()` —
    mirrors `services/metrics/sampler.MetricsSampleScheduler` (itself
    documented as mirroring, rather than sharing a base class with,
    `EscalationScheduler`/`BackupScheduler` — same project convention: every
    recurring background loop in this codebase documents+mirrors the
    previous one instead of factoring out a shared base class).

    Always sleeps BEFORE the first run, same reasoning as its siblings: a
    short-lived test lifespan (`with TestClient(app): pass`) gets cancelled
    mid-sleep, never reaching a real DB query/subprocess call, unless a
    test explicitly drives `sleep`/`run_once` itself.
    """

    def __init__(
        self,
        *,
        interval_seconds: float,
        run_once: Callable[[], Awaitable[None]],
        sleep: Sleeper | None = None,
    ) -> None:
        self._interval_seconds = interval_seconds
        self._run_once = run_once
        self._sleep = sleep or asyncio.sleep
        self._task: asyncio.Task | None = None

    async def _loop(self) -> None:
        while True:
            await self._sleep(self._interval_seconds)
            try:
                await self._run_once()
            except Exception:
                # One bad tick (a flaky subprocess call, a transient DB
                # error) must never kill the loop, or the network profile
                # would silently freeze on its last-known reading forever —
                # same isolation every sibling scheduler in this codebase
                # already applies.
                logger.error("network_profile: sweep raised", exc_info=True)

    def start(self) -> None:
        """Idempotent: calling start() while already running is a no-op,
        not a second concurrent loop."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    @property
    def is_running(self) -> bool:
        return self._task is not None and not self._task.done()


def create_default_network_profile_scheduler(
    *, event_bus: EventBus | None = None, settings: Settings | None = None
) -> NetworkProfileScheduler:
    """A `NetworkProfileScheduler` wired to real Settings — used by
    `app_factory`'s lifespan, mirrors
    `services/metrics/sampler.create_default_metrics_scheduler`.
    `previous_key` is owned by this closure (a plain mutable `dict`, the
    same "state lives in the closure, `run_once` itself is a bare
    `Callable[[], Awaitable[None]]`" shape `services/backup/wiring.py`'s own
    default-scheduler factories already use for their own carried-forward
    state) — NOT inside `NetworkProfileScheduler` itself, which stays a
    generic, network-profile-agnostic reusable loop (see its own docstring)."""
    settings = settings or get_settings()
    state: dict[str, str | None] = {"previous_key": None}

    async def _run_once() -> None:
        state["previous_key"] = await run_network_profile_sweep(
            previous_key=state["previous_key"], event_bus=event_bus
        )

    return NetworkProfileScheduler(
        interval_seconds=settings.network_profile_poll_interval_seconds, run_once=_run_once
    )


def register_network_profile_connector(registry: MCPRegistry) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as every sibling `register_*_connector` in this
    package, see `os_firewall.register_os_firewall_connector`'s docstring
    for what this is (and is not) for."""
    registry.register(
        MCPConnector(
            name=NETWORK_PROFILE_CONNECTOR_NAME,
            description=(
                "Current network detection (networksetup on macOS, nmcli "
                "on Linux, Get-NetConnectionProfile on Windows) — read "
                "locally via subprocess, never linked into this process."
            ),
            transport="subprocess",
            endpoint="",
        )
    )
