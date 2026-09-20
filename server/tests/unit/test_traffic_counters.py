"""A-39 (11б): `traffic_counters.py` — platform dispatch + parsing + the
diff-across-polls logic, fully offline (the shared `run_local_command`
helper is monkeypatched here, same "inject a fake transport" technique
test_os_firewall_connector.py/test_osquery_connector.py already use) — no
real `nettop`/`ss` invocation, and no dependency on which OS the test suite
itself happens to run on.

The macOS CSV fixtures below are trimmed, VERBATIM captures from a real
`nettop -P -L 1 -J bytes_in,bytes_out` run on this dev machine (see the A-39
task report for the full output) — not invented data. The Linux `ss -tiepn`
fixture is NOT verified live (no Linux machine on this dev box) — built from
`ss(8)`'s documented tcp_info output shape, same disclosure this module's own
docstring already makes.
"""

import pytest

import app.services.mcp.security_connectors.traffic_counters as traffic_counters_module
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
)
from app.services.mcp.security_connectors.traffic_counters import (
    TRAFFIC_COUNTERS_CONNECTOR_NAME,
    TrafficCounterRegistry,
    _parse_nettop_csv,
    _parse_ss_output,
    fetch_traffic_counters,
    register_traffic_counters_connector,
)

# Verbatim (trimmed) capture, this dev machine, 2026-07-23 — see module
# docstring above / A-39 task report.
_REAL_NETTOP_CSV = (
    ",bytes_in,bytes_out,\n"
    "launchd.1,0,0,\n"
    "syslogd.558,0,4080,\n"
    "apsd.564,6901,52187,\n"
    "mDNSResponder.661,5415775,4180759,\n"
    "Notes.1228,10221,2819,\n"
)


def _fake_run(responses: dict[str, tuple[int, str, str]]):
    """`responses` maps the first argv element (the binary name) to a fixed
    `(returncode, stdout, stderr)` reply; a binary not in the map raises
    `LocalCommandNotFound`, matching a real missing-binary `PATH` lookup —
    identical helper shape to test_os_firewall_connector.py's own."""

    async def _run(*args: str, timeout: float = 5.0):
        if args[0] not in responses:
            raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")
        return responses[args[0]]

    return _run


# ---------------------------------------------------------------------------
# macOS CSV parsing (_parse_nettop_csv) — pure function, no subprocess at all
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_parse_nettop_csv_reads_real_captured_output():
    result = _parse_nettop_csv(_REAL_NETTOP_CSV)

    assert result == {
        1: (0, 0),
        558: (0, 4080),
        564: (6901, 52187),
        661: (5415775, 4180759),
        1228: (10221, 2819),
    }


@pytest.mark.unit
def test_parse_nettop_csv_skips_header_row_via_the_same_numeric_check_as_everything_else():
    """The header row's first column is empty (`""`), which fails the
    "last `.`-segment is numeric" check exactly like any other malformed
    row would — no hardcoded "skip row 0", proven here by a header-only
    input producing zero rows."""
    result = _parse_nettop_csv(",bytes_in,bytes_out,\n")

    assert result == {}


@pytest.mark.unit
def test_parse_nettop_csv_skips_a_name_with_no_numeric_suffix():
    """A process name with no `.pid` suffix at all (defensive — not observed
    live, but the parser must not crash/guess on it) is dropped, not
    fabricated a pid for."""
    result = _parse_nettop_csv("kernel_task,100,200,\n")

    assert result == {}


@pytest.mark.unit
def test_parse_nettop_csv_sums_duplicate_pids():
    """Defensive: if the same pid legitimately appears twice (not observed
    live for `-P` aggregated output, but this module must not silently drop
    one row if it ever does), both rows' bytes are summed, not overwritten."""
    result = _parse_nettop_csv("proc.42,100,200,\nproc.42,10,20,\n")

    assert result == {42: (110, 220)}


# ---------------------------------------------------------------------------
# Linux `ss -tiepn` parsing (_parse_ss_output) — NOT verified live, see
# module docstring.
# ---------------------------------------------------------------------------


_SS_SAMPLE = (
    "State  Recv-Q Send-Q   Local Address:Port    Peer Address:Port  Process\n"
    "ESTAB  0      0        192.168.1.5:52428     140.82.121.3:443   "
    'users:(("chrome",pid=1234,fd=52))\n'
    "\t cubic wscale:7,7 rto:204 rtt:1.5/0.75 bytes_acked:15200 bytes_received:98234 "
    "segs_out:120 segs_in:110\n"
    "ESTAB  0      0        192.168.1.5:52500     1.1.1.1:443        "
    'users:(("chrome",pid=1234,fd=60))\n'
    "\t cubic bytes_acked:3000 bytes_received:4000\n"
    "ESTAB  0      0        192.168.1.5:52600     8.8.8.8:443        "
    'users:(("curl",pid=9999,fd=3))\n'
    "\t cubic bytes_acked:500 bytes_received:100\n"
)


@pytest.mark.unit
def test_parse_ss_output_sums_per_pid_across_multiple_sockets():
    """Two `chrome` (pid 1234) sockets must aggregate into one per-process
    total — same "per PROCESS, not per connection" aggregation macOS's
    `nettop -P` does natively, computed here by hand since `ss` reports
    per-socket."""
    result = _parse_ss_output(_SS_SAMPLE)

    assert result == {
        1234: (98234 + 4000, 15200 + 3000),
        9999: (100, 500),
    }


@pytest.mark.unit
def test_parse_ss_output_ignores_lines_with_no_pid_context():
    result = _parse_ss_output("State  Recv-Q Send-Q   Local Address:Port    Peer Address:Port  Process\n")

    assert result == {}


# ---------------------------------------------------------------------------
# Platform dispatch + honest connector-status contract
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_ok_reports_real_parsed_counters(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (0, _REAL_NETTOP_CSV, "")}),
    )
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result["connector"] == {"status": "ok"}
    # First-ever poll for every pid — honestly no baseline yet (see the
    # "Diffing model" section of the module docstring).
    assert result["by_pid"][1228] == {"bytes_sent": None, "bytes_received": None}
    assert set(result["by_pid"].keys()) == {1, 558, 564, 661, 1228}


@pytest.mark.unit
async def test_macos_permission_denied_is_reported_honestly(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (1, "", "Permission denied")}),
    )
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "permission_denied"}, "by_pid": {}}


@pytest.mark.unit
async def test_macos_unreachable_on_nonzero_exit_without_permission_marker(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (64, "", "nettop: illegal option -- Z")}),
    )
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "unreachable"}, "by_pid": {}}


@pytest.mark.unit
async def test_macos_not_configured_when_nettop_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound("'nettop' is not installed on this host")

    monkeypatch.setattr(traffic_counters_module, "run_local_command", _run)
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "not_configured"}, "by_pid": {}}


@pytest.mark.unit
async def test_macos_unreachable_on_timeout(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut("'nettop' timed out")

    monkeypatch.setattr(traffic_counters_module, "run_local_command", _run)
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "unreachable"}, "by_pid": {}}


@pytest.mark.unit
async def test_linux_ok_reports_real_parsed_counters(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"ss": (0, _SS_SAMPLE, "")}),
    )
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result["connector"] == {"status": "ok"}
    assert set(result["by_pid"].keys()) == {1234, 9999}
    assert result["by_pid"][9999] == {"bytes_sent": None, "bytes_received": None}


@pytest.mark.unit
async def test_linux_not_configured_when_ss_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Linux")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound("'ss' is not installed on this host")

    monkeypatch.setattr(traffic_counters_module, "run_local_command", _run)
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "not_configured"}, "by_pid": {}}


@pytest.mark.unit
async def test_windows_is_honestly_not_configured_never_a_fabricated_number(monkeypatch: pytest.MonkeyPatch):
    """No subprocess mock needed at all — `_windows_cumulative_counters()`
    deliberately never spawns one, see its own docstring for the
    investigated-and-rejected candidates (netstat -e, IO Data Bytes/sec,
    per-NIC counters, ETW)."""
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Windows")
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "not_configured"}, "by_pid": {}}


@pytest.mark.unit
async def test_unsupported_platform_is_honestly_not_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "FreeBSD")
    registry = TrafficCounterRegistry()

    result = await fetch_traffic_counters(registry)

    assert result == {"connector": {"status": "not_configured"}, "by_pid": {}}


# ---------------------------------------------------------------------------
# TrafficCounterRegistry — the diff-across-polls logic itself, the actual
# point of this whole module (see "Diffing model" in traffic_counters.py's
# own docstring).
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_second_poll_reports_a_real_delta_against_the_first(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    registry = TrafficCounterRegistry()

    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (0, "proc.42,1000,2000,\n", "")}),
    )
    first = await fetch_traffic_counters(registry)
    assert first["by_pid"][42] == {"bytes_sent": None, "bytes_received": None}

    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (0, "proc.42,1500,2600,\n", "")}),
    )
    second = await fetch_traffic_counters(registry)

    assert second["connector"] == {"status": "ok"}
    assert second["by_pid"][42] == {"bytes_sent": 600, "bytes_received": 500}


@pytest.mark.unit
async def test_a_pid_seen_for_the_first_time_on_the_second_poll_is_also_honestly_none(
    monkeypatch: pytest.MonkeyPatch,
):
    """Pid 42 has a baseline from poll 1; pid 99 (a brand-new process) shows
    up only on poll 2 — pid 99 must be `None` (no baseline for IT
    specifically), not accidentally inherit pid 42's real delta."""
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    registry = TrafficCounterRegistry()

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,1000,2000,\n", "")})
    )
    await fetch_traffic_counters(registry)

    monkeypatch.setattr(
        traffic_counters_module,
        "run_local_command",
        _fake_run({"nettop": (0, "proc.42,1200,2100,\nnew.99,500,500,\n", "")}),
    )
    second = await fetch_traffic_counters(registry)

    assert second["by_pid"][42] == {"bytes_sent": 100, "bytes_received": 200}
    assert second["by_pid"][99] == {"bytes_sent": None, "bytes_received": None}


@pytest.mark.unit
async def test_a_negative_delta_pid_restart_is_honestly_none_not_a_fabricated_negative(
    monkeypatch: pytest.MonkeyPatch,
):
    """The OS reused pid 42 for a brand-new process (or the kernel counter
    wrapped) — the raw cumulative value went DOWN between polls, which is
    never a real "negative traffic" answer. Must be `None`, not surfaced as
    a fabricated negative number."""
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    registry = TrafficCounterRegistry()

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,9000,9000,\n", "")})
    )
    await fetch_traffic_counters(registry)

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,10,20,\n", "")})
    )
    second = await fetch_traffic_counters(registry)

    assert second["by_pid"][42] == {"bytes_sent": None, "bytes_received": None}


@pytest.mark.unit
async def test_a_failed_poll_does_not_corrupt_the_baseline_for_the_next_successful_one(
    monkeypatch: pytest.MonkeyPatch,
):
    """A transient failure between two good polls must not reset/lose the
    real baseline the first good poll already established."""
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    registry = TrafficCounterRegistry()

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,1000,2000,\n", "")})
    )
    await fetch_traffic_counters(registry)

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (1, "", "Permission denied")})
    )
    failed = await fetch_traffic_counters(registry)
    assert failed["connector"]["status"] == "permission_denied"

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,1100,2300,\n", "")})
    )
    recovered = await fetch_traffic_counters(registry)

    assert recovered["by_pid"][42] == {"bytes_sent": 300, "bytes_received": 100}


@pytest.mark.unit
async def test_two_independent_registries_never_share_state(monkeypatch: pytest.MonkeyPatch):
    """The non-singleton discipline this module's own docstring commits to
    (mirrors ClamAvScanJobRegistry/SecurityConsoleRegistry) — one registry's
    baseline must never leak into another's, exactly the "no state leaks
    between app instances/tests" reasoning app_factory.py documents for
    every other registry."""
    monkeypatch.setattr(traffic_counters_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,1000,2000,\n", "")})
    )
    registry_a = TrafficCounterRegistry()
    registry_b = TrafficCounterRegistry()
    await fetch_traffic_counters(registry_a)  # establishes a baseline in A only

    monkeypatch.setattr(
        traffic_counters_module, "run_local_command", _fake_run({"nettop": (0, "proc.42,5000,5000,\n", "")})
    )
    result_b = await fetch_traffic_counters(registry_b)

    # Registry B's own first-ever poll — honestly None, unaffected by A's
    # already-established baseline.
    assert result_b["by_pid"][42] == {"bytes_sent": None, "bytes_received": None}


# ---------------------------------------------------------------------------
# MCP registry metadata
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_register_traffic_counters_connector_registers_the_expected_metadata():
    registry = MCPRegistry()

    register_traffic_counters_connector(registry)

    connector = registry.get(TRAFFIC_COUNTERS_CONNECTOR_NAME)
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "subprocess"
    assert connector.endpoint == ""
