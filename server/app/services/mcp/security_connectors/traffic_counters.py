"""A-39 (11б): per-process network traffic VOLUME — the piece `network`'s
sole real source (osquery's `process_open_sockets`, see `osquery.py`) never
had: it can say a socket exists, never how many bytes crossed it (osquery has
no such table/column on any of the three OSes this stack targets).
`app.js`'s `TOOL_LABELS.os_counters` and `security_console.py._network_payload`'s
`"engine": ["osquery", "os_counters"]` have named this second source since
A-10 — this module is what finally backs it with real data instead of an
unused placeholder string.

Same "external tool reached from outside the process, never linked in" shape
the licence gate (CLAUDE.md) and every other connector in this package
already establishes — here the "external tool" is each OS's own per-process
network-accounting facility, reached via `asyncio.create_subprocess_exec`
(`_local_command.py`), never a shell string.

Mechanism per OS (this task's own brief names `nettop -x -l 1` / `netstat
-ib` as macOS examples and explicitly leaves the exact shape to the
implementer — "или диффы netstat -ib", "на твоё усмотрение"):

  - **macOS** (verified live on this dev machine, see the A-39 task report
    for the exact commands/output): `nettop -P -L 1 -J bytes_in,bytes_out`,
    NOT the plan's literal `nettop -x -l 1` example. `-P` collapses each
    process's connections into one summary line (this task's brief title is
    "объём трафика ПО ПРОЦЕССУ", not per-socket); `-L 1 -J ...` switches
    nettop into its one-shot CSV logging mode with only the two columns this
    module needs, e.g.:
        ```
        ,bytes_in,bytes_out,
        launchd.1,0,0,
        mDNSResponder.661,5415775,4180759,
        ```
    — a stable `<name>.<pid>,<bytes_in>,<bytes_out>,` shape confirmed live,
    dramatically easier and less fragile to parse than `-x -l 1`'s
    interactive/tree-shaped text report (one line per process summary, one
    *indented* line per individual connection under it, many columns most of
    them blank on the process-summary line) — same "prefer the tool's own
    machine-readable output mode over scraping a human-formatted table"
    reasoning `osquery.py`'s own docstring gives for choosing `--json` batch
    queries over screen-scraping.

  - **Linux**: `ss -tiepn` (iproute2 — present by default on virtually every
    distro, unlike `nethogs`, which would need an extra package install AND
    root/packet-capture privileges this service must not acquire). Each TCP
    socket's tcp_info line carries cumulative `bytes_acked`/`bytes_received`
    counters the kernel itself maintains; `-p` resolves the owning pid so
    per-socket values can be summed per process, matching macOS's `-P`
    aggregation. **NOT verified live** (no Linux machine available on this
    dev box) — implemented from `ss(8)`'s documented `-i`/tcp_info output
    shape, same disclosure style `os_firewall.py`'s Windows/Linux paths and
    A-15/A-18/A-20/A-21/A-28 already use for their own unverified paths.

  - **Windows**: deliberately **not implemented** — investigated and no
    reliable, stock, non-admin CLI/perf-counter mechanism for genuinely
    PER-PROCESS *network-only* byte counters was found (see
    `_windows_cumulative_counters()`'s own docstring for what was checked
    and why each candidate was rejected). Reports `not_configured` rather
    than a fabricated number built from a counter that is not actually
    network-specific — this is the "никогда не фабриковать число" rule
    (CLAUDE.md) applied to "don't fabricate a *mechanism* either", not a
    laziness shortcut.

Diffing model — the actual "как только два опроса случились, посчитай
дельту" logic this task's brief asks for: every OS above only ever reports a
**cumulative** counter (bytes since the process/socket was created), never a
delta. `TrafficCounterRegistry` is the per-`create_app()`-instance stateful
object that remembers the previous cumulative reading per pid and computes
the delta on each subsequent `sample()` call — same "fresh instance per
create_app(), attached to `app.state`, no state leaks between app instances/
tests" non-singleton discipline `app_factory.py` already applies to
`ClamAvScanJobRegistry`/`SecurityConsoleRegistry`/every other stateful
registry in this codebase (deliberately NOT a module-level dict, unlike this
package's other, stateless `fetch_*` functions). A pid seen for the first
time this poll has no baseline to diff against — honestly `None`
("не опрошено ещё", not a fabricated 0 and not its lifetime total mislabeled
as a delta). The polling *cadence* itself is not this module's concern: it is
driven by whatever calls `sample()` — in practice `network`'s own A-39 (11а)
auto-refresh interval — so the delta window is naturally "however often the
network console actually refreshed", not a fixed internal timer this module
would need to own.
"""

from __future__ import annotations

import csv
import io
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

# A-10's `TOOL_LABELS.os_counters` / `_network_payload`'s `engine` list
# already named this connector before it existed — reused verbatim, not
# reinvented, so the console's engine badge and connector-status banner
# (app.js's generic `connectors` dict rendering, see `_network_payload`)
# both resolve a human label for it with zero frontend changes.
TRAFFIC_COUNTERS_CONNECTOR_NAME = "os_counters"

_NETTOP_ARGS = ("nettop", "-P", "-L", "1", "-J", "bytes_in,bytes_out")

# `ss`'s tcp_info line embeds `pid=<n>` inside the owning process descriptor
# (`users:(("chrome",pid=1234,fd=52))`) on the SAME line as the socket
# addresses, and `bytes_acked:<n>`/`bytes_received:<n>` on the FOLLOWING
# (indented) tcp_info line — two different lines per socket, which is why
# `_parse_ss_output` below is a small line-by-line state machine (`pending_pid`)
# rather than a single regex.
_SS_ARGS = ("ss", "-tiepn")
_SS_PID_RE = re.compile(r"pid=(\d+)")
_SS_BYTES_ACKED_RE = re.compile(r"bytes_acked:(\d+)")
_SS_BYTES_RECEIVED_RE = re.compile(r"bytes_received:(\d+)")


class TrafficCounterError(RuntimeError):
    """`reason` is one of `"not_configured"` / `"permission_denied"` /
    `"unreachable"` — same vocabulary as every other connector in this
    package (see `osquery.py`/`os_firewall.py`'s identical sibling
    exceptions)."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


async def _run(*args: str) -> tuple[int, str, str]:
    """Translates the shared local-command helper's exceptions into this
    module's own `TrafficCounterError` reasons — identical shape to
    `os_firewall.py`'s own `_run()`."""
    try:
        return await run_local_command(*args)
    except LocalCommandNotFound as exc:
        raise TrafficCounterError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise TrafficCounterError(str(exc), reason="unreachable") from exc


def _parse_nettop_csv(stdout: str) -> dict[int, tuple[int, int]]:
    """`<process-name>.<pid>,<bytes_in>,<bytes_out>,` rows (see module
    docstring for a real captured sample) -> `{pid: (bytes_in, bytes_out)}`.

    The pid is taken from the LAST `.`-separated segment of the first column
    (never the process name itself, which routinely contains dots of its own
    on macOS, e.g. "Google Chrome H.37034" truncated display names, "com.docker.
    ...") — a row whose last segment is not purely numeric is skipped rather
    than guessed at, same "never crash/never fabricate on an unexpected-but-
    real value" rule `osquery.py`'s own parsing helpers already follow. The
    header row (`,bytes_in,bytes_out,` — an EMPTY first column) is skipped by
    this exact same numeric check, not by a hardcoded "skip row 0", so a
    stray blank/malformed line anywhere in the output is equally harmless.
    """
    counters: dict[int, tuple[int, int]] = {}
    for row in csv.reader(io.StringIO(stdout)):
        if len(row) < 3:
            continue
        name_pid = row[0]
        pid_str = name_pid.rsplit(".", 1)[-1] if "." in name_pid else ""
        if not pid_str.isdigit():
            continue
        try:
            bytes_in = int(row[1])
            bytes_out = int(row[2])
        except ValueError:
            continue
        pid = int(pid_str)
        prev_in, prev_out = counters.get(pid, (0, 0))
        counters[pid] = (prev_in + bytes_in, prev_out + bytes_out)
    return counters


async def _macos_cumulative_counters() -> dict[int, tuple[int, int]]:
    returncode, stdout, stderr = await _run(*_NETTOP_ARGS)
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise TrafficCounterError("nettop denied access", reason="permission_denied")
    if returncode != 0:
        raise TrafficCounterError(f"nettop exited {returncode}: {stderr.strip()}", reason="unreachable")
    return _parse_nettop_csv(stdout)


def _parse_ss_output(stdout: str) -> dict[int, tuple[int, int]]:
    """See `_SS_PID_RE`/`_SS_BYTES_*_RE` above for the two-line-per-socket
    shape this walks. `pending_pid` carries the most recently seen pid
    forward from a socket's address line to its following tcp_info line;
    reset to `None` once consumed so a tcp_info-less line (a socket `ss`
    could not fetch extended info for) never gets silently attributed to the
    wrong, stale pid."""
    counters: dict[int, tuple[int, int]] = {}
    pending_pid: int | None = None
    for line in stdout.splitlines():
        pid_match = _SS_PID_RE.search(line)
        if pid_match:
            pending_pid = int(pid_match.group(1))
            continue
        if pending_pid is None:
            continue
        acked_match = _SS_BYTES_ACKED_RE.search(line)
        received_match = _SS_BYTES_RECEIVED_RE.search(line)
        if acked_match or received_match:
            bytes_out = int(acked_match.group(1)) if acked_match else 0
            bytes_in = int(received_match.group(1)) if received_match else 0
            prev_in, prev_out = counters.get(pending_pid, (0, 0))
            counters[pending_pid] = (prev_in + bytes_in, prev_out + bytes_out)
            pending_pid = None
    return counters


async def _linux_cumulative_counters() -> dict[int, tuple[int, int]]:
    returncode, stdout, stderr = await _run(*_SS_ARGS)
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise TrafficCounterError("ss denied access", reason="permission_denied")
    if returncode != 0:
        raise TrafficCounterError(f"ss exited {returncode}: {stderr.strip()}", reason="unreachable")
    return _parse_ss_output(stdout)


async def _windows_cumulative_counters() -> dict[int, tuple[int, int]]:
    """Deliberately raises, never calls a subprocess — see module docstring.

    Candidates investigated and rejected, for the record (same "state the
    honest gap, don't silently skip it" discipline as this module's
    docstring):
      - `netstat -ib`/`netstat -e`: this task's own brief's second named
        example, but on Windows `netstat -e` reports GLOBAL interface
        totals only, not per-process (`-b` on Windows shows the owning
        EXECUTABLE per connection, no byte counts at all — the opposite gap
        from macOS's `-b`-less `netstat -ib`, which DOES have per-interface
        bytes but still not per-process either way).
      - PowerShell `Get-Counter '\\Process(*)\\...'`: the "Process" perf-
        counter object has no network-byte counter at all (CPU/handles/
        working-set/page-faults/generic IO — see the ones it does have in
        this module's own docstring — but no send/receive bytes).
      - PowerShell `Get-Counter '\\Process(*)\\IO Data Bytes/sec'` (or the
        Read/Write/Other variants): real counters, but they total ALL I/O
        (disk + device + network) for the process, not network alone —
        using one as a stand-in for "network bytes" would be exactly the
        fabricated-number CLAUDE.md forbids, just laundered through a
        real-looking perf counter instead of a made-up literal.
      - `Get-NetAdapterStatistics`/`Win32_PerfFormattedData_Tcpip_
        NetworkInterface`: real, but per-NETWORK-INTERFACE, the same
        wrong granularity as `netstat -e` above.
      - The mechanism Task Manager/Resource Monitor's own per-process
        "Network" column actually uses is an ETW (Event Tracing for
        Windows) consumer of the `Microsoft-Windows-Kernel-Network`
        provider — technically real, but needs an elevated trace session
        (`netsh trace start` or an ETW API) this service must not acquire
        (same "never escalate privileges for a background/always-on
        service" principle A-36's `elevated_run()` design note states for
        the whole platform), plus binary ETL parsing — out of proportion to
        this task's scope.
    """
    raise TrafficCounterError(
        "no reliable non-admin per-process network byte counter exists via stock Windows tools",
        reason="not_configured",
    )


async def _cumulative_counters_for_current_platform() -> dict[int, tuple[int, int]]:
    system = platform.system()
    if system == "Darwin":
        return await _macos_cumulative_counters()
    if system == "Linux":
        return await _linux_cumulative_counters()
    if system == "Windows":
        return await _windows_cumulative_counters()
    raise TrafficCounterError(f"unsupported platform: {system!r}", reason="not_configured")


class TrafficCounterRegistry:
    """Per-`create_app()`-instance holder of the previous cumulative sample —
    see this module's docstring ("Diffing model") for why this must be
    stateful and instance-scoped rather than a bare stateless function like
    every other `fetch_*` in this package.

    Attached at `app.state.traffic_counter_registry` (`app_factory.py`),
    reached through `security/security_console.py`'s
    `get_traffic_counter_registry()` FastAPI dependency — identical wiring
    shape to `ClamAvScanJobRegistry`/`get_clamav_scan_job_registry`.
    """

    def __init__(self) -> None:
        self._last_sample: dict[int, tuple[int, int]] = {}

    async def sample(self) -> dict[str, Any]:
        """Never raises: an unsupported platform / missing tool / permission
        problem / any other failure is reported as an honest
        `connector.status`, same never-a-500 contract as every other
        connector's `fetch_*` in this package. Returns
        `{"connector": {"status": ...}, "by_pid": {pid: {"bytes_sent": int|None,
        "bytes_received": int|None}}}` — `by_pid` covers every pid this
        poll's cumulative read found (not only ones with a computable delta),
        so a caller can still tell "process exists, no baseline yet" (`None`)
        apart from "process not seen by this connector at all" (key absent).
        """
        try:
            cumulative = await _cumulative_counters_for_current_platform()
        except TrafficCounterError as exc:
            logger.warning("traffic_counters: %s", exc)
            return {"connector": {"status": exc.reason}, "by_pid": {}}

        by_pid: dict[int, dict[str, int | None]] = {}
        for pid, (bytes_in, bytes_out) in cumulative.items():
            previous = self._last_sample.get(pid)
            if previous is None:
                by_pid[pid] = {"bytes_sent": None, "bytes_received": None}
            else:
                prev_in, prev_out = previous
                sent = bytes_out - prev_out
                received = bytes_in - prev_in
                # A negative delta means the process restarted (pid reused)
                # or the OS's own counter wrapped/reset between polls — never
                # a real "negative traffic" answer, so treated the same as
                # "no usable baseline this round" rather than surfaced as a
                # fabricated negative number.
                by_pid[pid] = {
                    "bytes_sent": sent if sent >= 0 else None,
                    "bytes_received": received if received >= 0 else None,
                }
        self._last_sample = cumulative
        return {"connector": {"status": "ok"}, "by_pid": by_pid}


async def fetch_traffic_counters(registry: TrafficCounterRegistry) -> dict[str, Any]:
    """Thin module-level wrapper around `registry.sample()` — exists purely
    so `security_console.py` can `monkeypatch.setattr(security_console_module,
    "fetch_traffic_counters", ...)` in tests, the exact same bare-name-import
    monkeypatch technique every other connector's `fetch_*` in this stack
    already relies on (see test_security_console_network_av.py), despite
    this one needing a stateful registry argument the others don't."""
    return await registry.sample()


def register_traffic_counters_connector(registry: MCPRegistry) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as every sibling `register_*_connector` in this
    package, see `os_firewall.register_os_firewall_connector`'s docstring
    for what this is (and is not) for."""
    registry.register(
        MCPConnector(
            name=TRAFFIC_COUNTERS_CONNECTOR_NAME,
            description=(
                "Per-process network traffic volume (nettop -P on macOS, "
                "ss -ti on Linux — cumulative kernel counters diffed "
                "between polls; not implemented on Windows, see module "
                "docstring) — read locally via subprocess, never linked "
                "into this process."
            ),
            transport="subprocess",
            endpoint="",
        )
    )
