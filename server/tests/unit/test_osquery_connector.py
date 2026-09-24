"""A-15: `osquery.py` — platform-agnostic, fully offline (the shared
`run_local_command` helper is monkeypatched here, same "inject a fake
transport" technique test_os_firewall_connector.py already uses) — no real
`osqueryi` invocation, and no dependency on whether osquery happens to be
installed on the machine running this test suite.

A-24 adds `_resolve_osqueryi()`'s own packaged-vs-not-packaged tests near
the bottom of this file, same `monkeypatch.setattr(<module>.sys, "frozen",
..., raising=False)` technique `server/tests/unit/test_config_packaging.py`
already established for `app/config.py`'s `is_packaged()` — copied here,
not reinvented, since this module now checks the exact same PyInstaller
bootloader attributes.
"""

import json
import sys
from pathlib import Path

import pytest

import app.services.mcp.security_connectors.osquery as osquery_module
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
)
from app.services.mcp.security_connectors.osquery import (
    OSQUERY_CONNECTOR_NAME,
    _resolve_osqueryi,
    fetch_av_osquery_data,
    fetch_listening_ports,
    fetch_network_console_data,
    register_osquery_connector,
)


def _set_packaged(monkeypatch: pytest.MonkeyPatch, meipass: str) -> None:
    """Mocks the exact PyInstaller bootloader detection pattern
    `app.config.is_packaged()` checks (see that function's own docstring
    for the citation) — same helper shape as
    `test_config_packaging.py`'s `_set_packaged()`, duplicated here rather
    than imported since it needs to patch `osquery_module.sys`
    specifically, not `app.config.sys`."""
    monkeypatch.setattr(osquery_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(osquery_module.sys, "_MEIPASS", meipass, raising=False)


def _fake_osqueryi(sql_responses: dict[str, tuple[int, str, str]]):
    """`sql_responses` maps a substring of the SQL text to a fixed
    `(returncode, stdout, stderr)` reply — every query this module issues
    uses a distinct `FROM <table>` clause, so matching by substring is
    enough to tell them apart without hard-coding the exact SQL string."""

    async def _run(*args: str, timeout: float = 5.0):
        assert args[0] == "osqueryi"
        assert args[1] == "--json"
        sql = args[2]
        for needle, response in sql_responses.items():
            if needle in sql:
                return response
        raise AssertionError(f"no fake response configured for SQL: {sql!r}")

    return _run


def _json_rows(rows: list[dict]) -> str:
    return json.dumps(rows)


# ---------------------------------------------------------------------------
# network console (fetch_network_console_data)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_network_data_ok_parses_listening_ports_and_connections(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM listening_ports": (
                    0,
                    _json_rows(
                        [
                            {
                                "process_name": "uvicorn",
                                "pid": "4242",
                                "port": "8000",
                                "protocol": "6",
                                "address": "127.0.0.1",
                            }
                        ]
                    ),
                    "",
                ),
                "FROM process_open_sockets": (
                    0,
                    _json_rows(
                        [
                            {
                                "process_name": "python3",
                                "pid": "4321",
                                "local_address": "127.0.0.1",
                                "local_port": "51000",
                                "remote_address": "93.184.216.34",
                                "remote_port": "443",
                                "protocol": "6",
                                "state": "ESTABLISHED",
                            }
                        ]
                    ),
                    "",
                ),
            }
        ),
    )

    result = await fetch_network_console_data()

    assert result["connector"] == {"status": "ok"}
    assert result["active_connections"] == 1
    assert result["connections"] == [
        {
            "process": "python3",
            "pid": 4321,
            "local_address": "127.0.0.1",
            "local_port": 51000,
            "remote_address": "93.184.216.34",
            "remote_port": 443,
            "protocol": "6",
            "state": "ESTABLISHED",
        }
    ]
    assert result["listening_ports"] == [
        {"process": "uvicorn", "pid": 4242, "port": 8000, "protocol": "6", "address": "127.0.0.1"}
    ]


@pytest.mark.unit
async def test_network_data_not_configured_when_osqueryi_is_missing(monkeypatch: pytest.MonkeyPatch):
    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound("'osqueryi' is not installed on this host")

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await fetch_network_console_data()

    assert result == {
        "connector": {"status": "not_configured"},
        "connections": [],
        "listening_ports": [],
        "active_connections": None,
    }


@pytest.mark.unit
async def test_network_data_unreachable_on_timeout(monkeypatch: pytest.MonkeyPatch):
    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut("'osqueryi' timed out")

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await fetch_network_console_data()

    assert result["connector"] == {"status": "unreachable"}
    assert result["active_connections"] is None


@pytest.mark.unit
async def test_network_data_unreachable_on_unparseable_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi({"FROM listening_ports": (0, "not actually json", "")}),
    )

    result = await fetch_network_console_data()

    assert result["connector"] == {"status": "unreachable"}


@pytest.mark.unit
async def test_network_data_permission_denied_is_reported_honestly(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi({"FROM listening_ports": (1, "", "Permission denied")}),
    )

    result = await fetch_network_console_data()

    assert result["connector"] == {"status": "permission_denied"}
    assert result["connections"] == []


@pytest.mark.unit
async def test_network_data_unreachable_on_nonzero_exit(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi({"FROM listening_ports": (1, "", "no such table: listening_ports")}),
    )

    result = await fetch_network_console_data()

    assert result["connector"] == {"status": "unreachable"}


# ---------------------------------------------------------------------------
# A-28: perimeter's `open_ports` metric (fetch_listening_ports) — reuses the
# same `_LISTENING_PORTS_SQL`/`_query()` the network tests above already
# exercise, so these tests only need to prove the counting/error-shape
# contract, not re-verify the SQL itself.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fetch_listening_ports_ok_counts_distinct_real_ports(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM listening_ports": (
                    0,
                    _json_rows(
                        [
                            {"process_name": "uvicorn", "pid": "1", "port": "8000", "protocol": "6", "address": "127.0.0.1"},
                            {"process_name": "sshd", "pid": "2", "port": "22", "protocol": "6", "address": "0.0.0.0"},
                        ]
                    ),
                    "",
                ),
            }
        ),
    )

    result = await fetch_listening_ports()

    assert result == {
        "connector": {"status": "ok"},
        "open_ports": 2,
        # A-31: the deduplicated rows themselves — human-readable protocol
        # ("6" -> "tcp"), sorted by (port, protocol) for a stable order.
        "ports": [
            {"port": 22, "protocol": "tcp", "pid": 2, "process_name": "sshd"},
            {"port": 8000, "protocol": "tcp", "pid": 1, "process_name": "uvicorn"},
        ],
    }


@pytest.mark.unit
async def test_fetch_listening_ports_excludes_port_zero_and_collapses_dual_stack_duplicates(
    monkeypatch: pytest.MonkeyPatch,
):
    """Architect review of A-28's live Playwright+`lsof` cross-check found
    the original `len(rows)` implementation massively overcounted: real
    `listening_ports` data on the dev machine had ~155 of ~194 rows with
    `port: "0"` (unbound/ephemeral sockets, not real open ports) plus the
    same real port listed twice for a dual-stack (IPv4 `0.0.0.0` + IPv6
    `::`) listener. This test pins both fixes at once with a small,
    representative fixture — not just re-running the same two-distinct-
    ports case the original (buggy) test above already covered."""
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM listening_ports": (
                    0,
                    _json_rows(
                        [
                            # Real port, listed twice (dual-stack) — counts once.
                            {"process_name": "ControlCenter", "pid": "1", "port": "5000", "protocol": "6", "address": "0.0.0.0"},
                            {"process_name": "ControlCenter", "pid": "1", "port": "5000", "protocol": "6", "address": "::"},
                            # Same port number, but a DIFFERENT protocol — counts separately.
                            {"process_name": "something", "pid": "2", "port": "5000", "protocol": "17", "address": "0.0.0.0"},
                            # port "0" rows — unbound/ephemeral, excluded entirely, however many there are.
                            {"process_name": None, "pid": "3", "port": "0", "protocol": "17", "address": "0.0.0.0"},
                            {"process_name": None, "pid": "4", "port": "0", "protocol": "17", "address": "0.0.0.0"},
                            {"process_name": None, "pid": "5", "port": "0", "protocol": "17", "address": "::"},
                            # A genuinely distinct second real port.
                            {"process_name": "sshd", "pid": "6", "port": "22", "protocol": "6", "address": "0.0.0.0"},
                        ]
                    ),
                    "",
                ),
            }
        ),
    )

    result = await fetch_listening_ports()

    # 5000/tcp (deduped from 2 rows) + 5000/udp (distinct protocol) + 22/tcp
    # = 3 real open ports, the three port-"0" rows excluded entirely.
    assert result == {
        "connector": {"status": "ok"},
        "open_ports": 3,
        "ports": [
            # 22/tcp sorts before 5000/tcp and 5000/udp (port ascending first).
            {"port": 22, "protocol": "tcp", "pid": 6, "process_name": "sshd"},
            # First-seen of the two dual-stack 5000/tcp rows wins (address is
            # the only field that differs between them) — pid 1/ControlCenter.
            {"port": 5000, "protocol": "tcp", "pid": 1, "process_name": "ControlCenter"},
            {"port": 5000, "protocol": "udp", "pid": 2, "process_name": "something"},
        ],
    }


@pytest.mark.unit
async def test_fetch_listening_ports_maps_protocol_numbers_and_handles_missing_process(
    monkeypatch: pytest.MonkeyPatch,
):
    """A-31: `protocol` must be a human-readable name ("tcp"/"udp"), never
    the raw IP-protocol-number string osquery's `--json` output uses — the
    exact complaint this task exists to fix ("31 — а какие, кем?"). Also
    pins two honesty edges: an unrecognised protocol number (neither "6" nor
    "17") is passed through as-is rather than hidden, and a socket whose
    owning process already exited (LEFT JOIN finds no match, `pid`/
    `process_name` both null in the raw row) must not fabricate a pid/name —
    `None`, not `0`/`""`."""
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM listening_ports": (
                    0,
                    _json_rows(
                        [
                            {"process_name": "uvicorn", "pid": "10", "port": "8000", "protocol": "6", "address": "127.0.0.1"},
                            {"process_name": "dns", "pid": "11", "port": "53", "protocol": "17", "address": "127.0.0.1"},
                            # ICMP (protocol 1) — not one of the two mapped
                            # labels, must be shown as-is, not dropped/hidden.
                            {"process_name": "ping-ish", "pid": "12", "port": "9999", "protocol": "1", "address": "0.0.0.0"},
                            # Owning process already exited between osquery's
                            # two internal scans — pid/process_name both null.
                            {"process_name": None, "pid": None, "port": "7777", "protocol": "6", "address": "0.0.0.0"},
                        ]
                    ),
                    "",
                ),
            }
        ),
    )

    result = await fetch_listening_ports()

    assert result == {
        "connector": {"status": "ok"},
        "open_ports": 4,
        "ports": [
            {"port": 53, "protocol": "udp", "pid": 11, "process_name": "dns"},
            {"port": 7777, "protocol": "tcp", "pid": None, "process_name": None},
            {"port": 8000, "protocol": "tcp", "pid": 10, "process_name": "uvicorn"},
            {"port": 9999, "protocol": "1", "pid": 12, "process_name": "ping-ish"},
        ],
    }


@pytest.mark.unit
async def test_fetch_listening_ports_not_configured_when_osqueryi_is_missing(monkeypatch: pytest.MonkeyPatch):
    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound("'osqueryi' is not installed on this host")

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await fetch_listening_ports()

    assert result == {"connector": {"status": "not_configured"}, "open_ports": None, "ports": []}


@pytest.mark.unit
async def test_fetch_listening_ports_permission_denied_is_reported_honestly(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi({"FROM listening_ports": (1, "", "Permission denied")}),
    )

    result = await fetch_listening_ports()

    assert result == {"connector": {"status": "permission_denied"}, "open_ports": None, "ports": []}


# ---------------------------------------------------------------------------
# av console (fetch_av_osquery_data)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_av_data_ok_with_process_count_and_fim_disabled_by_default(monkeypatch: pytest.MonkeyPatch):
    """FIM is opt-in (osquery_flags.enable_file_events) — absent/false flag
    reports `file_events.status: not_configured` without breaking the rest
    of the connector, exactly this task's DoD wording."""
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM processes": (0, _json_rows([{"process_count": "312"}]), ""),
                "FROM osquery_flags": (0, _json_rows([{"value": "false"}]), ""),
            }
        ),
    )

    result = await fetch_av_osquery_data()

    assert result == {
        "connector": {"status": "ok"},
        "process_count": 312,
        "file_events": {"status": "not_configured", "count": None, "recent": []},
    }


@pytest.mark.unit
async def test_av_data_fim_enabled_returns_real_events(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM processes": (0, _json_rows([{"process_count": "200"}]), ""),
                "FROM osquery_flags": (0, _json_rows([{"value": "1"}]), ""),
                "FROM file_events": (
                    0,
                    _json_rows(
                        [{"target_path": "/Users/demo/Documents/report.docx", "action": "UPDATED", "time": "1700000000"}]
                    ),
                    "",
                ),
            }
        ),
    )

    result = await fetch_av_osquery_data()

    assert result["connector"] == {"status": "ok"}
    assert result["file_events"] == {
        "status": "ok",
        "count": 1,
        "recent": [
            {"path": "/Users/demo/Documents/report.docx", "action": "UPDATED", "time": "1700000000"}
        ],
    }


@pytest.mark.unit
async def test_av_data_fim_query_failure_falls_back_to_not_configured_without_breaking_connector(
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: a FIM-specific problem must not take down the whole osquery
    connector — process telemetry (an independent query) stays `ok`."""
    monkeypatch.setattr(
        osquery_module,
        "run_local_command",
        _fake_osqueryi(
            {
                "FROM processes": (0, _json_rows([{"process_count": "50"}]), ""),
                "FROM osquery_flags": (1, "", "no such table: osquery_flags"),
            }
        ),
    )

    result = await fetch_av_osquery_data()

    assert result["connector"] == {"status": "ok"}
    assert result["process_count"] == 50
    assert result["file_events"] == {"status": "not_configured", "count": None, "recent": []}


@pytest.mark.unit
async def test_av_data_not_configured_when_osqueryi_is_missing(monkeypatch: pytest.MonkeyPatch):
    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandNotFound("'osqueryi' is not installed on this host")

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await fetch_av_osquery_data()

    assert result == {
        "connector": {"status": "not_configured"},
        "process_count": None,
        "file_events": {"status": "not_configured", "count": None, "recent": []},
    }


@pytest.mark.unit
def test_register_osquery_connector_registers_the_expected_metadata():
    registry = MCPRegistry()

    register_osquery_connector(registry)

    connector = registry.get(OSQUERY_CONNECTOR_NAME)
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "subprocess"
    assert connector.endpoint == ""


# ---------------------------------------------------------------------------
# A-24: _resolve_osqueryi() — packaged (vendored binary) vs not-packaged
# (bare PATH lookup, dev/Docker/venv's pre-A-24 behaviour) resolution.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_osqueryi_not_packaged_returns_bare_fallback():
    """Every environment this whole test suite otherwise runs in (pytest
    itself never sets `sys.frozen`) — must resolve to the exact same bare
    `"osqueryi"` string as before A-24, so a developer with `osqueryi`
    installed via `brew`/`apt` keeps working unchanged."""
    assert _resolve_osqueryi() == "osqueryi"


@pytest.mark.unit
def test_resolve_osqueryi_packaged_but_vendored_binary_missing_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Packaged, but nothing was actually vendored at build time (e.g. a
    Linux build that chose the apt-install path instead, see
    packaging/linux/README.md) — must not raise, must not fabricate a path
    that doesn't exist, just fall back exactly like the not-packaged case."""
    _set_packaged(monkeypatch, str(tmp_path))

    assert _resolve_osqueryi() == "osqueryi"


# A-65-0 (из промпта A-64): оба теста ждут macOS/POSIX-layout vendored-пути
# (`vendor/osquery/osqueryi` без суффикса); на Windows вендорится
# `osqueryi.exe` — Windows-раскладка покрыта соседними тестами ниже.
_WIN32_SKIP = pytest.mark.skipif(
    sys.platform == "win32",
    reason="требует macOS-layout vendored-путей; на Windows вендорится osqueryi.exe",
)


@_WIN32_SKIP
@pytest.mark.unit
def test_resolve_osqueryi_packaged_with_vendored_binary_returns_its_absolute_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The A-24 happy path: a native installer vendored a real `osqueryi`
    file at `<bundle root>/vendor/osquery/osqueryi` — this must be preferred
    over the bare `PATH` lookup."""
    vendor_dir = tmp_path / "vendor" / "osquery"
    vendor_dir.mkdir(parents=True)
    binary = vendor_dir / "osqueryi"
    binary.write_text("#!/bin/sh\necho fake-osqueryi\n")
    _set_packaged(monkeypatch, str(tmp_path))

    assert _resolve_osqueryi() == str(binary)


@pytest.mark.unit
def test_resolve_osqueryi_packaged_windows_looks_for_exe_suffix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Windows' vendored binary is named `osqueryi.exe` (see
    packaging/windows/hranix-shield.spec) — `_vendored_osqueryi_path()`
    must look for that suffix specifically on `sys.platform == "win32"`,
    not the bare Unix name, and not find a same-named-but-wrong-suffix
    file that happens to sit next to it."""
    _set_packaged(monkeypatch, str(tmp_path))
    monkeypatch.setattr(osquery_module.sys, "platform", "win32")
    vendor_dir = tmp_path / "vendor" / "osquery"
    vendor_dir.mkdir(parents=True)
    # A bare `osqueryi` (no `.exe`) sitting here must NOT be picked up on
    # a "win32" resolve — proves the suffix branch is actually exercised,
    # not just that some file in the directory happens to satisfy it.
    (vendor_dir / "osqueryi").write_text("not the windows binary")

    assert _resolve_osqueryi() == "osqueryi"

    exe = vendor_dir / "osqueryi.exe"
    exe.write_bytes(b"fake-pe-binary")

    assert _resolve_osqueryi() == str(exe)


@_WIN32_SKIP
@pytest.mark.unit
async def test_query_invokes_the_resolved_vendored_binary_not_the_bare_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """End-to-end within this module (not just `_resolve_osqueryi()` in
    isolation): a packaged run with a vendored binary present must pass
    THAT path as `run_local_command`'s argv[0], not the bare `"osqueryi"`
    name — this is what actually makes the "Сеть"/"Вирусная активность"
    consoles work out of the box after A-24, not just an internal helper
    returning the right string in a vacuum."""
    vendor_dir = tmp_path / "vendor" / "osquery"
    vendor_dir.mkdir(parents=True)
    binary = vendor_dir / "osqueryi"
    binary.write_text("#!/bin/sh\necho fake\n")
    _set_packaged(monkeypatch, str(tmp_path))

    seen_argv0: list[str] = []

    async def _run(*args: str, timeout: float = 5.0):
        seen_argv0.append(args[0])
        return 0, json.dumps([{"process_count": "1"}]), ""

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await fetch_av_osquery_data()

    assert result["connector"] == {"status": "ok"}
    assert seen_argv0 and all(seen == str(binary) for seen in seen_argv0)
