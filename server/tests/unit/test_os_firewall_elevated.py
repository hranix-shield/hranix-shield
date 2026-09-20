"""A-36: `os_firewall.py`'s three new ELEVATED functions
(`read_firewall_rules`/`block_all_incoming`/`unblock_all_incoming`) —
fully offline: `elevated_run` itself is monkeypatched here (same "inject a
fake transport" technique test_os_firewall_connector.py already uses for
`run_local_command`), so none of this pops a real OS dialog and none of it
depends on which OS the test suite itself happens to run on.

Unlike `fetch_firewall_status`/`fetch_firewall_rules` (never raise, honest
dict return — see test_os_firewall_connector.py), these three RAISE
`OSFirewallError` on anything other than a clean `ok` — see os_firewall.py's
"A-36" section docstring for why, and this file's own tests for the exact
`elevation_cancelled`/`elevation_failed`/`not_configured` reasons."""

import pytest

import app.services.mcp.security_connectors.os_firewall as os_firewall_module
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from app.services.mcp.security_connectors.os_firewall import (
    OSFirewallError,
    block_all_incoming,
    read_firewall_rules,
    unblock_all_incoming,
)


def _fake_elevated_run(result: ElevatedRunResult, *, captured: dict | None = None):
    async def _run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        if captured is not None:
            captured["command"] = command
            captured["reason_ru"] = reason_ru
            captured["reason_en"] = reason_en
        return result

    return _run


# ---------------------------------------------------------------------------
# read_firewall_rules()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_read_firewall_rules_ok_returns_raw_non_empty_lines(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}
    pf_output = "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n\n"
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout=pf_output, stderr=""), captured=captured),
    )

    result = await read_firewall_rules()

    assert result == {
        "status": "ok",
        "rules": [
            'scrub-anchor "com.apple/*" all fragment reassemble',
            'anchor "com.apple/*" all',
        ],
    }
    assert captured["command"] == ["pfctl", "-s", "rules"]
    assert "Hranix Shield" in captured["reason_ru"]


@pytest.mark.unit
async def test_macos_read_firewall_rules_cancelled_raises_elevation_cancelled(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await read_firewall_rules()

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
async def test_macos_read_firewall_rules_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="pfctl: some real error")),
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await read_firewall_rules()

    assert exc_info.value.reason == "elevation_failed"


@pytest.mark.unit
async def test_linux_read_firewall_rules_calls_iptables_dash_s(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(
            ElevatedRunResult(status="ok", stdout="-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n"), captured=captured
        ),
    )

    result = await read_firewall_rules()

    assert captured["command"] == ["iptables", "-S"]
    assert result["rules"] == ["-P INPUT DROP", "-A INPUT -i lo -j ACCEPT"]


@pytest.mark.unit
async def test_windows_read_firewall_rules_calls_netsh_show_rule(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="ok", stdout="Rule Name: Core Networking\n"), captured=captured),
    )

    result = await read_firewall_rules()

    assert captured["command"] == ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
    assert result["rules"] == ["Rule Name: Core Networking"]


@pytest.mark.unit
async def test_read_firewall_rules_unsupported_platform_raises_not_configured(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSFirewallError) as exc_info:
        await read_firewall_rules()

    assert exc_info.value.reason == "not_configured"
    assert called["count"] == 0


# ---------------------------------------------------------------------------
# block_all_incoming() / unblock_all_incoming()
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_block_all_incoming_ok_runs_a_bash_script_via_bin_bash(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        # Read the real script file WHILE it still exists — `elevated_run`
        # is called from inside a `with tempfile.TemporaryDirectory()`
        # block (see `_run_elevated_firewall_script`), which deletes the
        # directory the instant this call returns.
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await block_all_incoming()

    assert result == {"status": "ok", "blocked": True}
    assert captured["command"][0] == "/bin/bash"
    # The real script file this module wrote to disk — proves the actual
    # pf commands (not just the dispatch) are what gets run elevated.
    script_text = captured["script_text"]
    assert "block in all" in script_text
    assert "/sbin/pfctl -f -" in script_text
    assert "/sbin/pfctl -e" in script_text


@pytest.mark.unit
async def test_macos_unblock_all_incoming_ok_reloads_the_default_pf_conf(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await unblock_all_incoming()

    assert result == {"status": "ok", "blocked": False}
    assert "/sbin/pfctl -f /etc/pf.conf" in captured["script_text"]


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_all_incoming, unblock_all_incoming])
async def test_macos_block_unblock_cancelled_raises_elevation_cancelled(
    monkeypatch: pytest.MonkeyPatch, func
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func()

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_all_incoming, unblock_all_incoming])
async def test_macos_block_unblock_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch, func):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="pfctl: syntax error")),
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func()

    assert exc_info.value.reason == "elevation_failed"


@pytest.mark.unit
async def test_linux_block_all_incoming_inserts_a_tagged_iptables_rule(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    result = await block_all_incoming()

    assert result == {"status": "ok", "blocked": True}
    assert captured["command"] == [
        "iptables",
        "-I",
        "INPUT",
        "1",
        "-m",
        "comment",
        "--comment",
        "hranix-shield-block-all-incoming",
        "-j",
        "DROP",
    ]


@pytest.mark.unit
async def test_linux_unblock_all_incoming_deletes_the_same_tagged_rule(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    result = await unblock_all_incoming()

    assert result == {"status": "ok", "blocked": False}
    assert captured["command"] == [
        "iptables",
        "-D",
        "INPUT",
        "-m",
        "comment",
        "--comment",
        "hranix-shield-block-all-incoming",
        "-j",
        "DROP",
    ]


@pytest.mark.unit
async def test_windows_block_all_incoming_sets_blockinboundalways(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await block_all_incoming()

    assert captured["command"] == [
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinboundalways,allowoutbound",
    ]


@pytest.mark.unit
async def test_windows_unblock_all_incoming_restores_blockinbound(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await unblock_all_incoming()

    assert captured["command"] == [
        "netsh",
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,allowoutbound",
    ]


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_all_incoming, unblock_all_incoming])
async def test_block_unblock_unsupported_platform_raises_not_configured(
    monkeypatch: pytest.MonkeyPatch, func
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSFirewallError) as exc_info:
        await func()

    assert exc_info.value.reason == "not_configured"
    assert called["count"] == 0
