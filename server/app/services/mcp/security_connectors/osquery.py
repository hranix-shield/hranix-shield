"""A-15: osquery EDR telemetry — the first real data source for two consoles
at once: `network` (active connections/listening ports — its single source,
same "one source" shape as `ids`'s CrowdSec) and `av` (process telemetry +
optional FIM, the first of several eventual sources under `av`'s
`connectors` dict — see `security_console.py._av_payload`).

Same "external tool reached from outside the process, never linked in" shape
the licence gate (CLAUDE.md) and A-11/A-18's connectors already established.
osquery itself is Apache-2.0 (cleaner than A-16/A-17's GPLv2 tools), but this
module still treats it as a fully separate host process, per the same §0.1
"each module owns a full API" principle A-18's task brief calls out — not
only a licence requirement here.

Mechanism choice (this task's brief left it to the implementer, two options
compatible with "never linked in, only reached via subprocess/socket"):

  1. A persistent `osqueryd` process + Thrift `--extensions_socket` API.
  2. Batch `osqueryi --json "SELECT ..."` one-shot queries via subprocess.

This module uses (2), same shape as A-18's `run_local_command` helper
(`_local_command.py`), for three reasons:
  - Consistency: A-18 already established "one local binary invocation via
    `asyncio.create_subprocess_exec`, argv list, never a shell string" as
    this codebase's house style for local-tool connectors. (1) would need a
    second, unrelated integration shape (a long-lived daemon this process
    must supervise/restart, plus a Thrift client dependency) for no benefit
    this dashboard-polling use case needs.
  - No new dependency: (1) requires a `thrift` Python package (or osquery's
    own `osquery-python` SDK) just to speak the extensions socket protocol;
    (2) needs nothing beyond `osqueryi` itself being on `PATH`, exactly like
    `pfctl`/`ufw`/`fdesetup` before it.
  - No daemon lifecycle to own: (1) requires `osqueryd` to already be
    running as a supervised background service (a whole extra piece of
    process-management this task's brief does not ask for) before this
    module could reach it at all. (2) needs nothing running ahead of time —
    each poll is a fresh, self-contained one-shot query, closer in spirit to
    how a periodic dashboard refresh actually uses this data (see
    `security_console.py`'s per-request fetch pattern for every other
    connector so far).

  Trade-off, stated honestly: each poll pays `osqueryi`'s own startup cost
  (schema load, SQLite virtual tables) instead of reusing one warm daemon
  connection — measured in the hundreds of milliseconds per osquery's own
  documentation, not instant. Acceptable for a dashboard refreshed on a
  human timescale (seconds), not acceptable for anything needing
  sub-second/streaming telemetry — a future task that needs that can revisit
  option (1) without this module's callers (`security_console.py`) needing
  to change, since they only see this module's `fetch_*` functions.

Three honest non-`ok` states, same vocabulary as every other connector in
this stack:
  - `"not_configured"`: `osqueryi` is not installed / not on `PATH` on this
    host — see `infra/security/osquery/README.md` for per-OS install steps.
  - `"permission_denied"`: `osqueryi` ran but a query needs privileges this
    process does not have (e.g. seeing other users' open sockets on some
    platforms) and this service must not acquire wholesale, same
    "never sudo the whole process" principle as A-18.
  - `"unreachable"`: `osqueryi` ran but exited non-zero for some other
    reason, its JSON output could not be parsed, or it timed out.

Not verified live against a real running `osqueryd`/`osqueryi` while
building A-15: `brew install --cask osquery` was attempted on this macOS dev
machine and failed — the cask's installer needs an interactive `sudo`
password prompt this non-interactive environment cannot supply (see the
A-15 task report for the exact error). Every SQL query/column name below is
taken from osquery's own published schema (https://osquery.io/schema/current,
tables `listening_ports`, `process_open_sockets`, `processes`, `file_events`,
`osquery_flags`), not empirically confirmed against a live instance at the
time — flagged in the A-15 task report as a genuine gap, same disclosure
style A-18 used for its unverified Windows paths. **A-24 has since verified
this module live against a real vendored `osqueryi` binary on this same
machine** — see `_resolve_osqueryi()` below and the A-24 task report for the
exact commands run and their output.

A-24: `_OSQUERYI` (a hardcoded `"osqueryi"` string, resolved purely through
whatever `PATH` this process happens to inherit) used to be this module's one
soft spot in the "works out of the box" promise A-19..A-22's native
installers otherwise make: none of those installers put `osqueryi` anywhere,
they only documented a manual `brew`/`apt`/MSI install for a developer
(`infra/security/osquery/README.md`) — a non-technical end user's fresh
install would silently show `not_configured` on both consoles this module
feeds, forever, never having been told an extra step was needed.
`_resolve_osqueryi()` fixes this by preferring a vendored `osqueryi` binary
shipped *inside* the native installer itself (`packaging/{macos,linux}/
vendor/osquery/`, `packaging/windows/vendor/osquery/`, populated at BUILD
time by each OS's `vendor-osquery.sh`/`.github/workflows/windows-build.yml`
step — never downloaded/installed at runtime, see this task's brief for why
that line matters: never escalate privileges or hit the network in the
background of an already-running app) when running packaged
(`app.config.is_packaged()`, A-19), falling back to the exact same bare
`"osqueryi"` `PATH` lookup as before A-24 in every other case (dev/Docker/
venv, or a packaged build that for some reason shipped without the vendored
binary — e.g. the Linux path, see `packaging/linux/README.md`'s A-24
section) — so a developer who already has `osqueryi` on `PATH` keeps working
completely unchanged.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

from app.config import is_packaged
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    looks_like_permission_denied,
    run_local_command,
)

logger = logging.getLogger(__name__)

OSQUERY_CONNECTOR_NAME = "osquery"

# A-24: fallback binary name, unchanged from before this task — resolved
# through whatever `PATH` this process inherits (dev machine with `osqueryi`
# installed by hand, Docker image with it apt-installed, ...), exactly as
# `_OSQUERYI` behaved pre-A-24. Kept as a module-level constant (not a
# literal repeated at each call site) so a stray direct reference elsewhere
# still has one name to look at.
_OSQUERYI_FALLBACK = "osqueryi"


def _vendored_osqueryi_path() -> Path:
    """Where each OS's native installer places its bundled `osqueryi`
    binary, IF this build vendors one (see `_resolve_osqueryi()`'s
    docstring) — `<PyInstaller bundle root>/vendor/osquery/osqueryi[.exe]`.

    Deliberately duplicates (does not import) the exact "`sys._MEIPASS` in
    packaged mode" detection `server/launcher.py`'s `bundled_root()`
    already established for A-20 rather than reusing that function
    directly: `launcher.py` imports `app.app_factory.create_app`, which —
    via `security_console.py` -> `security_connectors/__init__.py` — imports
    this very module, so `from launcher import bundled_root` here would be
    a real circular import (`launcher` would still be mid-way through
    executing its own top-level imports, before `bundled_root` is even
    defined, the first time this module needed it) — confirmed by tracing
    the import chain while building this task, not assumed. Copying the
    three-line pattern (`Path(sys._MEIPASS)`, only ever reached when
    `is_packaged()` is already True) avoids that without touching
    `launcher.py` at all, per this task's own brief ("не меняй сам файл").

    Each OS's `.spec` places the vendored binary at this exact
    `vendor/osquery/` path via its own `datas=[...]` row (see
    `packaging/{macos,linux,windows}/hranix-shield.spec`) — the `.exe`
    suffix on Windows mirrors how this same bundle's own entry point is
    named `Hranix Shield.exe`, not a guess.
    """
    root = Path(sys._MEIPASS)  # type: ignore[attr-defined]  # only called when is_packaged()
    exe_name = "osqueryi.exe" if sys.platform == "win32" else "osqueryi"
    return root / "vendor" / "osquery" / exe_name


def _resolve_osqueryi() -> str:
    """What `_query()` should actually invoke for this call — re-resolved
    on every call (never cached at import time), same "`is_packaged()` is
    re-checked on every access" discipline `app/config.py`'s own
    `resolved_*` properties already document, so a test can monkeypatch
    `sys.frozen`/`sys._MEIPASS` per-test without needing to reload this
    module.

    Packaged AND the vendored binary is actually present on disk: returns
    its absolute path — this is the "works out of the box" case A-24 exists
    for. Otherwise (not packaged, OR packaged but the vendored binary is
    missing — e.g. a Linux build that chose not to vendor one, see
    `packaging/linux/README.md`): returns the bare `"osqueryi"` fallback,
    letting `run_local_command`/`asyncio.create_subprocess_exec` resolve it
    through this process's own `PATH` exactly as `_OSQUERYI` always did
    before A-24 — never removed, only made second-priority.
    """
    if is_packaged():
        vendored = _vendored_osqueryi_path()
        if vendored.is_file():
            return str(vendored)
    return _OSQUERYI_FALLBACK

# `listening_ports`/`process_open_sockets` are both process-scoped osquery
# tables; joining against `processes` (LEFT JOIN so a socket whose owning
# process has already exited between osquery's two internal scans still
# comes back with a null process name, rather than vanishing the whole row)
# is what turns a bare pid into the human-readable "process/address/port"
# shape this task's brief asks for.
_LISTENING_PORTS_SQL = (
    "SELECT p.name AS process_name, l.pid AS pid, l.port AS port, "
    "l.protocol AS protocol, l.address AS address "
    "FROM listening_ports l LEFT JOIN processes p ON p.pid = l.pid;"
)

# `remote_port > 0` is this module's "this is a real established/connected
# socket, not a bare unconnected/unix-domain one" filter — unix-domain and
# not-yet-connected sockets report remote_port 0 in osquery's schema, and
# are not "active connections" in the sense this console's DoD means.
_ACTIVE_CONNECTIONS_SQL = (
    "SELECT p.name AS process_name, s.pid AS pid, s.local_address AS local_address, "
    "s.local_port AS local_port, s.remote_address AS remote_address, "
    "s.remote_port AS remote_port, s.protocol AS protocol, s.state AS state "
    "FROM process_open_sockets s LEFT JOIN processes p ON p.pid = s.pid "
    "WHERE s.remote_port > 0;"
)

_PROCESS_COUNT_SQL = "SELECT count(*) AS process_count FROM processes;"

# osquery always registers the `file_events` virtual table, even when FIM is
# never enabled — a bare `SELECT` against it would silently return `[]`
# forever whether FIM is off or just quiet, which is indistinguishable from
# "not configured" without also checking whether the feature is even on.
# `osquery_flags` is osquery's own introspection table for its own runtime
# flags (name/value/default_value/...) — checking `enable_file_events` here
# first is what lets this module tell "not enabled" (honest
# `not_configured`) apart from "enabled, nothing changed recently" (honest
# `ok` with `count: 0`), rather than reporting a guessed status either way.
_FIM_FLAG_SQL = "SELECT value FROM osquery_flags WHERE name = 'enable_file_events';"
_FILE_EVENTS_SQL = "SELECT target_path, action, time FROM file_events ORDER BY time DESC LIMIT 20;"


class OsqueryError(RuntimeError):
    """`reason` is one of `"not_configured"` / `"permission_denied"` /
    `"unreachable"` — see this module's docstring."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _to_int(value: Any) -> int | None:
    """osquery's `--json` output represents every column as a string,
    integers included — this coerces back, honestly `None` (not a guessed
    `0`) when a value is missing or not actually numeric."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


async def _query(sql: str) -> list[dict[str, Any]]:
    """Runs one `osqueryi --json "<sql>"` one-shot query and returns its
    decoded rows. Never returns anything but a `list[dict]` — raises
    `OsqueryError` (see class docstring for `reason` values) on every other
    outcome, translated from the shared `_local_command.py` helper the same
    way `os_firewall.py`/`os_disk_encryption.py` already do.

    `osqueryi = _resolve_osqueryi()` (A-24) — re-resolved on every call, not
    hoisted to a module-level constant, so that a vendored binary appearing/
    disappearing (or `is_packaged()` being monkeypatched mid-test-suite)
    never needs a process restart or module reload to take effect — the
    same reasoning `app/config.py`'s own `resolved_*` properties already
    document for why they check `is_packaged()` fresh each time too."""
    osqueryi = _resolve_osqueryi()
    try:
        returncode, stdout, stderr = await run_local_command(osqueryi, "--json", sql)
    except LocalCommandNotFound as exc:
        raise OsqueryError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise OsqueryError(str(exc), reason="unreachable") from exc

    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OsqueryError(f"{osqueryi} denied access for this query", reason="permission_denied")
    if returncode != 0:
        raise OsqueryError(f"{osqueryi} exited {returncode}: {stderr.strip()}", reason="unreachable")

    try:
        rows = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise OsqueryError(f"{osqueryi} returned unparseable JSON: {exc}", reason="unreachable") from exc
    if not isinstance(rows, list):
        raise OsqueryError(f"{osqueryi} returned an unexpected JSON shape", reason="unreachable")
    return rows


async def fetch_network_console_data() -> dict[str, Any]:
    """Real data for the `network` console (see
    `security_console.py._network_payload`) — this console's single source,
    same "one connector" shape `ids` already uses. Never raises: a missing
    `osqueryi`/a permission problem/any other failure is reported as an
    honest `connector.status`, never a 500 and never a fabricated empty-but-
    confident connections list."""
    try:
        listening_rows = await _query(_LISTENING_PORTS_SQL)
        connection_rows = await _query(_ACTIVE_CONNECTIONS_SQL)
    except OsqueryError as exc:
        logger.warning("osquery (network): %s", exc)
        return {
            "connector": {"status": exc.reason},
            "connections": [],
            "listening_ports": [],
            "active_connections": None,
        }

    connections = [
        {
            "process": row.get("process_name") or None,
            "pid": _to_int(row.get("pid")),
            "local_address": row.get("local_address") or None,
            "local_port": _to_int(row.get("local_port")),
            "remote_address": row.get("remote_address") or None,
            "remote_port": _to_int(row.get("remote_port")),
            "protocol": row.get("protocol"),
            "state": row.get("state") or None,
        }
        for row in connection_rows
    ]
    listening_ports = [
        {
            "process": row.get("process_name") or None,
            "pid": _to_int(row.get("pid")),
            "port": _to_int(row.get("port")),
            "protocol": row.get("protocol"),
            "address": row.get("address") or None,
        }
        for row in listening_rows
    ]
    return {
        "connector": {"status": "ok"},
        "connections": connections,
        "listening_ports": listening_ports,
        "active_connections": len(connections),
    }


def _distinct_real_ports(rows: list[dict[str, Any]]) -> set[tuple[int, Any]]:
    """What `fetch_listening_ports()` actually counts — NOT `len(rows)`.

    Architect review of A-28's live Playwright check found `len(rows)` is
    exactly the same "technically-real but misleading raw number" mistake
    A-23 already fixed for CrowdSec's community-vs-local ban counts
    (`crowdsec.py`'s own "A-23 addendum"), just newly discovered here rather
    than known in advance:

      - `listening_ports` returns many rows with `port: "0"` — confirmed
        live (architect's own direct `osqueryi` query, this dev machine):
        155 of ~194 rows. These are unbound/ephemeral sockets osquery still
        lists in this table, not a real port a human would recognise as
        "open" — excluded here, same as a missing/unparseable port value.
      - the SAME real port is often listed twice — confirmed live: a
        process bound dual-stack (IPv4 `0.0.0.0` + IPv6 `::`) gets one row
        per address, but a user thinks of that as ONE open port, not two.
        Deduplicated here by `(port, protocol)` — same port on TWO
        DIFFERENT protocols (e.g. 8080/tcp AND 8080/udp) still counts as
        two, matching how security tooling (e.g. `nmap`) already reports
        "8080/tcp open" and "8080/udp open" as separate findings, not one.

    `rows` is exactly what `_LISTENING_PORTS_SQL` returns (raw osquery JSON,
    string-typed columns) — this coerces `port` through `_to_int()` itself
    rather than requiring a caller to pre-clean it.

    A-31: `_dedup_listening_ports()` below is the "same key, but return a
    representative row instead of only counting the key" sibling this
    function's own docstring already asked a future task for — kept
    side-by-side (not merged into one function) so `len(_distinct_real_ports(rows))`
    stays a trivially-cheap set-of-tuples operation for any future caller
    that only ever needed the count."""
    return {
        (port, row.get("protocol"))
        for row in rows
        if (port := _to_int(row.get("port")))
    }


# A-31: `"6"`/`"17"` are the raw IP-protocol-number strings osquery's
# `--json` output always uses for `listening_ports.protocol` — the two this
# module actually expects to see in practice (TCP/UDP are the only
# transports a `listening_ports` row can name). A human-readable label is
# what the "Периметр" console's new ports table needs instead of a bare
# digit a non-technical user cannot interpret (this task's own brief).
_PROTOCOL_LABELS = {"6": "tcp", "17": "udp"}


def _protocol_label(value: Any) -> str | None:
    """Human-readable transport name for a raw osquery `protocol` column —
    `None` only when the column itself is missing (never guessed); any
    protocol number outside `_PROTOCOL_LABELS` is returned as-is (the raw
    string) rather than hidden, so an unusual value is still visible to the
    user instead of silently disappearing."""
    if value is None:
        return None
    return _PROTOCOL_LABELS.get(str(value), str(value))


def _dedup_listening_ports(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A-31: the `ports` list `fetch_listening_ports()` now returns
    alongside its `open_ports` count — same `(port, protocol)`
    de-duplication `_distinct_real_ports()` already established (port-"0"
    placeholder rows excluded, one row per unique real `(port, protocol)`
    pair, not one per network address a dual-stack listener happens to also
    be bound on — see that function's docstring for the live-confirmed
    reasoning), but keeping a representative *row* per key instead of only
    the key itself, since the console now needs to show WHICH ports (and
    whose process) are open, not only how many.

    First-seen row wins for a given `(port, protocol)` key: rows sharing a
    key differ only in `address` (the dual-stack IPv4-vs-IPv6 bind case
    `_distinct_real_ports` documents) never in `pid`/`process_name`, so any
    one of them is an equally representative answer — no data is lost by
    picking the first.

    Returned sorted by `(port, protocol)` for a stable, deterministic
    ordering across polls (osquery's own row order is not guaranteed to be
    stable call-to-call) — the same reason a human scanning a ports table
    expects it not to visibly reshuffle on every refresh."""
    seen: dict[tuple[int, Any], dict[str, Any]] = {}
    for row in rows:
        port = _to_int(row.get("port"))
        # Falsy check (not just `is None`), matching `_distinct_real_ports()`
        # above exactly: `port: "0"` (unbound/ephemeral sockets) must be
        # excluded here too, not just when it fails to parse at all.
        if not port:
            continue
        key = (port, row.get("protocol"))
        if key in seen:
            continue
        seen[key] = {
            "port": port,
            "protocol": _protocol_label(row.get("protocol")),
            "pid": _to_int(row.get("pid")),
            "process_name": row.get("process_name") or None,
        }
    return sorted(seen.values(), key=lambda item: (item["port"], item["protocol"] or ""))


async def fetch_listening_ports() -> dict[str, Any]:
    """Real data for `perimeter`'s `open_ports` metric (A-28, see
    `security_console.py._perimeter_payload`) — reuses `_LISTENING_PORTS_SQL`
    and `_query()` verbatim, the exact same query
    `fetch_network_console_data()` already runs for `network`'s
    `listening_ports` field, so this module keeps exactly one query against
    `listening_ports`, never two independently-maintained copies (this
    task's own brief: "переиспользуй функцию/запрос ... не дублируй SQL
    заново").

    A standalone function rather than a call into
    `fetch_network_console_data()` on purpose: `perimeter` only ever needs
    the port *count* (and, since A-31, the deduplicated rows themselves) —
    not `network`'s separate `process_open_sockets` query too — routing
    through the network function would pay for a second, unrelated osquery
    invocation just to discard its result.

    A-31: also returns `ports` — the deduplicated, human-readable rows
    themselves (`_dedup_listening_ports()`), not only their count. Before
    this task the real per-port detail `_LISTENING_PORTS_SQL` always read
    (process/pid/port/protocol) was thrown away here, leaving the
    "Периметр" console able to show only a bare number ("31 открытых
    портов") with no way for the user to see which ports or whose process —
    exactly the gap this task's brief (and the user's own complaint) called
    out. `open_ports` stays `len(ports)` (identical to the old
    `len(_distinct_real_ports(rows))` — same dedup key, just counted via the
    now-materialized list instead of a bare set), so this is not a behaviour
    change for the metric, only an addition alongside it.

    Never raises: same honest-`connector.status` contract as every other
    `fetch_*` in this module — a missing `osqueryi`/a permission problem is
    reported honestly, never a fabricated `0` or empty-but-confident list."""
    try:
        rows = await _query(_LISTENING_PORTS_SQL)
    except OsqueryError as exc:
        logger.warning("osquery (perimeter open_ports): %s", exc)
        return {"connector": {"status": exc.reason}, "open_ports": None, "ports": []}
    ports = _dedup_listening_ports(rows)
    return {"connector": {"status": "ok"}, "open_ports": len(ports), "ports": ports}


async def _fetch_file_events() -> dict[str, Any]:
    """The optional FIM slice of `av`'s osquery data — see this module's
    docstring for why the `osquery_flags` check comes first. Deliberately
    swallows its own `OsqueryError` rather than propagating it: per this
    task's brief, a FIM-specific problem must report this one metric as
    `not_configured` without taking down the rest of the (otherwise healthy)
    osquery connector — the caller (`fetch_av_osquery_data`) never sees this
    function raise."""
    try:
        flag_rows = await _query(_FIM_FLAG_SQL)
    except OsqueryError:
        return {"status": "not_configured", "count": None, "recent": []}

    enabled = bool(flag_rows) and flag_rows[0].get("value") in ("1", "true", "True")
    if not enabled:
        return {"status": "not_configured", "count": None, "recent": []}

    try:
        rows = await _query(_FILE_EVENTS_SQL)
    except OsqueryError:
        return {"status": "not_configured", "count": None, "recent": []}

    return {
        "status": "ok",
        "count": len(rows),
        "recent": [
            {"path": row.get("target_path"), "action": row.get("action"), "time": row.get("time")}
            for row in rows
        ],
    }


async def fetch_av_osquery_data() -> dict[str, Any]:
    """Real data for the `osquery` slice of `av`'s `connectors` dict (see
    `security_console.py._av_payload`) — the first of `av`'s eventual
    sources, `wazuh`/`clamav` (A-16/A-17) each add one more key to that same
    dict later without this shape needing to change. Never raises: a missing
    `osqueryi`/a permission problem is reported as an honest
    `connector.status`; a FIM-specific problem alone never takes down the
    whole connector (see `_fetch_file_events`)."""
    try:
        process_rows = await _query(_PROCESS_COUNT_SQL)
    except OsqueryError as exc:
        logger.warning("osquery (av): %s", exc)
        return {
            "connector": {"status": exc.reason},
            "process_count": None,
            "file_events": {"status": "not_configured", "count": None, "recent": []},
        }

    process_count = _to_int(process_rows[0].get("process_count")) if process_rows else None
    file_events = await _fetch_file_events()

    return {
        "connector": {"status": "ok"},
        "process_count": process_count,
        "file_events": file_events,
    }


def register_osquery_connector(registry: MCPRegistry) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as `crowdsec.register_crowdsec_connector` /
    `os_firewall.register_os_firewall_connector`, see the former's docstring
    for what this is (and is not) for."""
    registry.register(
        MCPConnector(
            name=OSQUERY_CONNECTOR_NAME,
            description=(
                "osquery — EDR-телеметрия (процессы, сетевые сокеты, "
                "опционально FIM через file_events) — читается локально "
                "через `osqueryi --json`, никогда не линкуется в этот "
                "процесс."
            ),
            transport="subprocess",
            endpoint="",
        )
    )
