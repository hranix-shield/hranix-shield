"""A-15: `osquery.py` — platform-agnostic, fully offline (the shared
`run_local_command` helper is monkeypatched here, same "inject a fake
transport" technique test_os_firewall_connector.py already uses) — no real
`osqueryi` invocation, and no dependency on whether osquery happens to be
installed on the machine running this test suite.
"""

import json

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
    fetch_av_osquery_data,
    fetch_network_console_data,
    register_osquery_connector,
)


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
                        [{"target_path": "/Users/vvl/Documents/report.docx", "action": "UPDATED", "time": "1700000000"}]
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
            {"path": "/Users/vvl/Documents/report.docx", "action": "UPDATED", "time": "1700000000"}
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
