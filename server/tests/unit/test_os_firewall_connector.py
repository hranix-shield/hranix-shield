"""A-18: `os_firewall.py` — platform dispatch + honest not_configured/
permission_denied/unreachable/ok states, fully offline (the shared
`run_local_command` helper is monkeypatched here, same "inject a fake
transport" technique test_crowdsec_client.py already uses for `httpx`) — no
real `pfctl`/`netsh`/`ufw` invocation, and no dependency on which OS the
test suite itself happens to run on.
"""

import pytest

import app.services.mcp.security_connectors._local_command as local_command_module
import app.services.mcp.security_connectors.os_firewall as os_firewall_module
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
)
from app.services.mcp.security_connectors.os_firewall import (
    OS_FIREWALL_CONNECTOR_NAME,
    fetch_firewall_rules,
    fetch_firewall_status,
    register_os_firewall_connector,
)


def _fake_run(responses: dict[str, tuple[int, str, str]]):
    """`responses` maps the first argv element (the binary name) to a fixed
    `(returncode, stdout, stderr)` reply; a binary not in the map raises
    `LocalCommandNotFound`, matching a real missing-binary `PATH` lookup."""

    async def _run(*args: str, timeout: float = 5.0):
        if args[0] not in responses:
            raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")
        return responses[args[0]]

    return _run


@pytest.mark.unit
async def test_macos_ok_when_socketfilterfw_reports_enabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({os_firewall_module._SOCKETFILTERFW: (0, "Firewall is enabled. (State = 1)", "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_macos_ok_when_socketfilterfw_reports_disabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({os_firewall_module._SOCKETFILTERFW: (0, "Firewall is disabled. (State = 0)", "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": False}


@pytest.mark.unit
async def test_macos_falls_back_to_pfctl_when_socketfilterfw_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"pfctl": (0, "Status: Enabled for 3 days\n", "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_macos_pfctl_without_sudo_reports_permission_denied(monkeypatch: pytest.MonkeyPatch):
    """Confirmed live while building this task: `pfctl -s info` without sudo
    answers exactly this stderr — this is the DoD's own "insufficient
    privileges" scenario for the os_firewall source."""
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        if args[0] == os_firewall_module._SOCKETFILTERFW:
            raise LocalCommandNotFound("socketfilterfw not installed")
        assert args[0] == "pfctl"
        return (1, "", "pfctl: /dev/pf: Permission denied\n")

    monkeypatch.setattr(os_firewall_module, "run_local_command", _run)

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "permission_denied"}, "active": None}


# Локале-независимый CIM-путь (Get-NetFirewallProfile через powershell.exe)
# вместо парсинга netsh-текста: «State ON» существует только в en-US выводе,
# ru-RU печатает «Состояние ВКЛЮЧИТЬ» — старый парсер на русской Windows
# давал unreachable на здоровой машине (поймано живой Windows-приёмкой
# 2026-09-19). Форма JSON-ответа — как у реального хоста: Enabled
# сериализуется как 1/0, не true/false (Windows PowerShell 5.1).
@pytest.mark.unit
async def test_windows_ok_only_when_every_profile_is_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    ps_output = (
        '[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":0}]'
    )
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (0, ps_output, "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": False}


@pytest.mark.unit
async def test_windows_ok_when_every_profile_is_enabled(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    ps_output = (
        '[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]'
    )
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (0, ps_output, "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_windows_active_never_consults_localized_netsh_text(
    monkeypatch: pytest.MonkeyPatch,
):
    """Регрессионный якорь A-18-фикса: активность читается из
    Get-NetFirewallProfile, а НЕ из netsh-текста — даже если «English netsh
    output» где-то в окружении существует, коннектор не должен его
    спрашивать (на локализованной Windows этот текст непарсибелен в
    принципе)."""
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    ps_output = '[{"Name":"Domain","Enabled":1},{"Name":"Private","Enabled":1},{"Name":"Public","Enabled":1}]'
    captured: list[tuple[str, ...]] = []

    async def _spy_run(*args: str, timeout: float = 5.0):
        captured.append(args)
        if args[0] not in ("powershell.exe",):
            raise AssertionError(f"connector must not shell out to {args[0]!r} on Windows any more")
        return (0, ps_output, "")

    monkeypatch.setattr(os_firewall_module, "run_local_command", _spy_run)

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}
    assert captured and captured[0][0] == "powershell.exe"
    assert "Get-NetFirewallProfile" in captured[0][-1]


@pytest.mark.unit
async def test_windows_unparseable_profile_output_is_unreachable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (0, "unexpected garbage", "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "unreachable"}, "active": None}


@pytest.mark.unit
async def test_linux_uses_ufw_when_installed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"ufw": (0, "Status: active\n", "")}),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_linux_falls_back_to_iptables_when_ufw_is_not_installed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    iptables_output = (
        "Chain INPUT (policy DROP)\ntarget     prot opt source               destination\n"
    )
    monkeypatch.setattr(
        os_firewall_module, "run_local_command", _fake_run({"iptables": (0, iptables_output, "")})
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_linux_not_configured_when_neither_ufw_nor_iptables_is_installed(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_firewall_module, "run_local_command", _fake_run({}))

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_unsupported_platform_is_not_configured_not_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_timeout_is_reported_as_unreachable_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut(f"{args[0]!r} timed out")

    monkeypatch.setattr(os_firewall_module, "run_local_command", _run)

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "unreachable"}, "active": None}


@pytest.mark.unit
async def test_unparseable_output_is_reported_as_unreachable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({
            os_firewall_module._SOCKETFILTERFW: (0, "unexpected garbage", ""),
            "pfctl": (0, "also unexpected garbage", ""),
        }),
    )

    result = await fetch_firewall_status()

    assert result == {"connector": {"status": "unreachable"}, "active": None}


# ---------------------------------------------------------------------------
# A-28: fetch_firewall_rules() — a distinct pf/netsh/iptables invocation
# (ruleset listing) from fetch_firewall_status() above (on/off toggle),
# with its own independently-failing permission requirement — confirmed
# live on this dev machine (macOS): `pfctl -s rules` denies without sudo
# even though `socketfilterfw --getglobalstate` (the toggle) does not.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_firewall_rules_ok_counts_non_comment_lines(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    pf_output = (
        "# comment line, must not count\n"
        "scrub-anchor \"com.apple/*\" all fragment reassemble\n"
        "anchor \"com.apple/*\" all\n"
        "\n"
    )
    monkeypatch.setattr(
        os_firewall_module, "run_local_command", _fake_run({"pfctl": (0, pf_output, "")})
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "ok"}, "count": 2}


@pytest.mark.unit
async def test_macos_firewall_rules_pfctl_without_sudo_reports_permission_denied(
    monkeypatch: pytest.MonkeyPatch,
):
    """Confirmed live while building A-28 (this dev machine, plain user, no
    sudo, no cached credential): `pfctl -s rules` answers exactly this
    stderr and exits 1 — the same `/dev/pf` wall A-18 already documented
    for `pfctl -s info`, now confirmed for `-s rules` too. This is the
    exact scenario that disables the perimeter console's "Правила
    фаервола" button (principle 10, see app.js's CONSOLE_META.perimeter)."""
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"pfctl": (1, "", "pfctl: /dev/pf: Permission denied\n")}),
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "permission_denied"}, "count": None}


@pytest.mark.unit
async def test_windows_firewall_rule_count_from_measure_object(monkeypatch: pytest.MonkeyPatch):
    """CIM-подсчёт (Get-NetFirewallRule | Measure-Object) вместо парсинга
    строк «Rule Name:» en-US-вывода netsh (на ru-RU их нет — живая находка
    приёмки 2026-09-19). Число приходит просто текстом в stdout."""
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (0, "680\n", "")}),
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "ok"}, "count": 680}


@pytest.mark.unit
async def test_windows_firewall_rule_count_unparseable_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (0, "not a number\n", "")}),
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "unreachable"}, "count": None}


@pytest.mark.unit
async def test_windows_firewall_rules_permission_denied(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"powershell.exe": (1, "", "Access is denied.\n")}),
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "permission_denied"}, "count": None}


@pytest.mark.unit
async def test_linux_firewall_rules_counts_append_lines(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    iptables_output = (
        "-P INPUT DROP\n"
        "-N DOCKER\n"
        "-A INPUT -i lo -j ACCEPT\n"
        "-A INPUT -p tcp --dport 22 -j ACCEPT\n"
    )
    monkeypatch.setattr(
        os_firewall_module, "run_local_command", _fake_run({"iptables": (0, iptables_output, "")})
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "ok"}, "count": 2}


@pytest.mark.unit
async def test_linux_firewall_rules_permission_denied(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        os_firewall_module,
        "run_local_command",
        _fake_run({"iptables": (1, "", "iptables: Permission denied (you must be root)\n")}),
    )

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "permission_denied"}, "count": None}


@pytest.mark.unit
async def test_firewall_rules_unsupported_platform_is_not_configured_not_a_crash(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "not_configured"}, "count": None}


@pytest.mark.unit
async def test_firewall_rules_timeout_is_reported_as_unreachable_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut(f"{args[0]!r} timed out")

    monkeypatch.setattr(os_firewall_module, "run_local_command", _run)

    result = await fetch_firewall_rules()

    assert result == {"connector": {"status": "unreachable"}, "count": None}


@pytest.mark.unit
def test_register_os_firewall_connector_registers_the_expected_metadata():
    registry = MCPRegistry()

    register_os_firewall_connector(registry)

    connector = registry.get(OS_FIREWALL_CONNECTOR_NAME)
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "subprocess"
    assert connector.endpoint == ""
