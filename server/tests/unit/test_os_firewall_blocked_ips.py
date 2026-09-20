"""A-52: `os_firewall.py`'s per-IP block/unblock — mirrors
tests/unit/test_os_firewall_blocked_ports.py's own A-37 test suite 1-to-1
(same offline `elevated_run` monkeypatching technique, same real-migrated-
tmp-SQLite-DB technique for the persistent side) — see that file's own
docstring for why none of this pops a real OS dialog and none of it
depends on which OS the test suite itself runs on.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.mcp.security_connectors.os_firewall as os_firewall_module
from app.db.models import BlockedIp
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from app.services.mcp.security_connectors.os_firewall import (
    LINUX_BLOCKED_IPS_CHAIN,
    MACOS_BLOCKED_IPS_ANCHOR,
    OSFirewallError,
    block_ip,
    delete_blocked_ip,
    list_blocked_ips,
    record_blocked_ip,
    unblock_ip,
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
# _validate_ip — the injection/sanitisation guard every public function
# below runs `ip` (and `all_blocked_ips`) through first.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_validate_ip_accepts_real_ipv4_and_ipv6():
    assert os_firewall_module._validate_ip("1.2.3.4") == "1.2.3.4"
    assert os_firewall_module._validate_ip("::1") == "::1"


@pytest.mark.unit
@pytest.mark.parametrize("bad", ["not-an-ip", "1.2.3.4; rm -rf /", "8.8.8.8'", "", "300.1.1.1"])
def test_validate_ip_rejects_anything_not_a_real_address(bad):
    with pytest.raises(OSFirewallError) as exc_info:
        os_firewall_module._validate_ip(bad)
    assert exc_info.value.reason == "invalid_ip"


# ---------------------------------------------------------------------------
# _build_macos_sync_blocked_ips_script
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_macos_sync_script_blocks_both_directions_for_every_ip():
    script = os_firewall_module._build_macos_sync_blocked_ips_script(["8.8.8.8", "1.1.1.1"])

    assert f"pfctl -a {MACOS_BLOCKED_IPS_ANCHOR} -f -" in script
    assert "block in from 1.1.1.1 to any" in script
    assert "block out from any to 1.1.1.1" in script
    assert "block in from 8.8.8.8 to any" in script
    assert "block out from any to 8.8.8.8" in script
    # Sorted, deterministic ordering.
    assert script.index("1.1.1.1") < script.index("8.8.8.8")


@pytest.mark.unit
def test_macos_sync_script_dedupes_repeated_ips():
    script = os_firewall_module._build_macos_sync_blocked_ips_script(["8.8.8.8", "8.8.8.8"])

    assert script.count("8.8.8.8") == 2  # exactly one "in from" + one "out to", not four


@pytest.mark.unit
def test_macos_sync_script_with_empty_list_still_loads_an_empty_ruleset():
    script = os_firewall_module._build_macos_sync_blocked_ips_script([])

    assert f"pfctl -a {MACOS_BLOCKED_IPS_ANCHOR} -f -" in script
    assert "block in from" not in script


# ---------------------------------------------------------------------------
# block_ip() / unblock_ip() — per-platform elevated dispatch
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_block_ip_runs_the_anchor_sync_script_via_bin_bash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["reason_ru"] = reason_ru
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await block_ip("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert result == {"status": "ok", "ip": "8.8.8.8", "blocked": True}
    assert captured["command"][0] == "/bin/bash"
    assert "8.8.8.8" in captured["reason_ru"]
    assert "block in from 8.8.8.8 to any" in captured["script_text"]


@pytest.mark.unit
async def test_macos_block_ip_passes_the_full_desired_ip_set_to_the_script(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    await block_ip("9.9.9.9", all_blocked_ips=["1.1.1.1", "9.9.9.9"])

    assert "1.1.1.1" in captured["script_text"]
    assert "9.9.9.9" in captured["script_text"]


@pytest.mark.unit
async def test_macos_unblock_ip_reconstructs_the_anchor_without_the_removed_ip(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await unblock_ip("9.9.9.9", all_blocked_ips=["1.1.1.1"])

    assert result == {"status": "ok", "ip": "9.9.9.9", "blocked": False}
    assert "1.1.1.1" in captured["script_text"]
    assert "9.9.9.9" not in captured["script_text"]


@pytest.mark.unit
async def test_block_ip_rejects_an_invalid_address_before_touching_elevated_run(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSFirewallError) as exc_info:
        await block_ip("1.2.3.4; rm -rf /", all_blocked_ips=[])

    assert exc_info.value.reason == "invalid_ip"
    assert called["count"] == 0


@pytest.mark.unit
@pytest.mark.parametrize("func,kwargs", [(block_ip, {}), (unblock_ip, {})])
async def test_macos_block_unblock_ip_cancelled_raises_elevation_cancelled(
    monkeypatch: pytest.MonkeyPatch, func, kwargs
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_ip, unblock_ip])
async def test_macos_block_unblock_ip_failed_raises_elevation_failed(monkeypatch: pytest.MonkeyPatch, func):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="pfctl: syntax error")),
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert exc_info.value.reason == "elevation_failed"


@pytest.mark.unit
async def test_linux_block_ip_creates_the_chain_and_both_direction_rules(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await block_ip("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert result == {"status": "ok", "ip": "8.8.8.8", "blocked": True}
    script = captured["script_text"]
    assert f"iptables -N {LINUX_BLOCKED_IPS_CHAIN}" in script
    assert f"-A {LINUX_BLOCKED_IPS_CHAIN} -s 8.8.8.8 -j DROP" in script
    assert f"-A {LINUX_BLOCKED_IPS_CHAIN} -d 8.8.8.8 -j DROP" in script


@pytest.mark.unit
async def test_linux_unblock_ip_deletes_both_direction_rules(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await unblock_ip("8.8.8.8", all_blocked_ips=[])

    assert result == {"status": "ok", "ip": "8.8.8.8", "blocked": False}
    script = captured["script_text"]
    assert f"-D {LINUX_BLOCKED_IPS_CHAIN} -s 8.8.8.8 -j DROP" in script
    assert f"-D {LINUX_BLOCKED_IPS_CHAIN} -d 8.8.8.8 -j DROP" in script


@pytest.mark.unit
async def test_windows_block_ip_uses_a_recognisable_display_name(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await block_ip("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert captured["command"][0] == "powershell.exe"
    ps_command = captured["command"][-1]
    assert "New-NetFirewallRule" in ps_command
    assert "Hranix Shield - Block IP 8.8.8.8" in ps_command
    assert '"' not in ps_command


@pytest.mark.unit
async def test_windows_unblock_ip_removes_the_same_named_rule(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await unblock_ip("8.8.8.8", all_blocked_ips=[])

    ps_command = captured["command"][-1]
    assert "Remove-NetFirewallRule" in ps_command
    assert "Hranix Shield - Block IP 8.8.8.8" in ps_command


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_ip, unblock_ip])
async def test_block_unblock_ip_unsupported_platform_raises_not_configured(
    monkeypatch: pytest.MonkeyPatch, func
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSFirewallError) as exc_info:
        await func("8.8.8.8", all_blocked_ips=["8.8.8.8"])

    assert exc_info.value.reason == "not_configured"
    assert called["count"] == 0


# ---------------------------------------------------------------------------
# record_blocked_ip / list_blocked_ips / delete_blocked_ip
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_record_blocked_ip_writes_a_new_row(migrated_session_maker: async_sessionmaker[AsyncSession]):
    async with migrated_session_maker() as session:
        row = await record_blocked_ip(session, ip="8.8.8.8", country="US", process_name="curl", reason="test")

    assert row.ip == "8.8.8.8"
    assert row.country == "US"
    assert row.process_name == "curl"
    assert row.reason == "test"
    assert isinstance(row.blocked_at, datetime)

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert len(rows) == 1
    assert rows[0].ip == "8.8.8.8"


@pytest.mark.unit
async def test_record_blocked_ip_is_idempotent_and_updates_in_place(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        await record_blocked_ip(session, ip="8.8.8.8", country="US", process_name="curl", reason=None)
    async with migrated_session_maker() as session:
        await record_blocked_ip(
            session, ip="8.8.8.8", country="US", process_name="curl-updated", reason="Подозрительный узел"
        )

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert len(rows) == 1
    assert rows[0].process_name == "curl-updated"
    assert rows[0].reason == "Подозрительный узел"


@pytest.mark.unit
async def test_record_blocked_ip_accepts_none_context_fields(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        row = await record_blocked_ip(session, ip="1.1.1.1", country=None, process_name=None, reason=None)

    assert row.country is None
    assert row.process_name is None
    assert row.reason is None


@pytest.mark.unit
async def test_list_blocked_ips_orders_alphabetically(migrated_session_maker: async_sessionmaker[AsyncSession]):
    async with migrated_session_maker() as session:
        await record_blocked_ip(session, ip="9.9.9.9", country=None, process_name=None, reason=None)
    async with migrated_session_maker() as session:
        await record_blocked_ip(session, ip="1.1.1.1", country=None, process_name=None, reason=None)

    async with migrated_session_maker() as session:
        rows = await list_blocked_ips(session)

    assert [row.ip for row in rows] == ["1.1.1.1", "9.9.9.9"]


@pytest.mark.unit
async def test_delete_blocked_ip_removes_an_existing_row_and_returns_true(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        await record_blocked_ip(session, ip="8.8.8.8", country=None, process_name=None, reason=None)

    async with migrated_session_maker() as session:
        removed = await delete_blocked_ip(session, ip="8.8.8.8")
    assert removed is True

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedIp))).all()
    assert rows == []


@pytest.mark.unit
async def test_delete_blocked_ip_returns_false_when_nothing_to_remove(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        removed = await delete_blocked_ip(session, ip="1.2.3.4")

    assert removed is False
