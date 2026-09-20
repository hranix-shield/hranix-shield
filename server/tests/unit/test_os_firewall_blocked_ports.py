"""A-37: `os_firewall.py`'s per-port block/unblock — both the ELEVATED
dispatch side (`block_port`/`unblock_port`, offline via a monkeypatched
`elevated_run`, same technique tests/unit/test_os_firewall_elevated.py
already uses for A-36's block-all/unblock-all) and the persistent
`blocked_ports` DB side (`record_blocked_port`/`list_blocked_ports`/
`delete_blocked_port`, against the real migrated tmp SQLite DB, same
technique tests/unit/test_scan_history.py already uses for `scan_history`).

None of this pops a real OS dialog and none of it depends on which OS the
test suite itself happens to run on — the real macOS-only live coverage
(real `osascript` spawned with the exact expected command/prompt for a
real, disposable listener port; the exact generated pf-anchor script read
back from disk; persistence across a real `kill -9` + relaunch of the
server process) is this task's own report — see that report for the one
piece that could NOT be completed live (entering the actual macOS admin
password: this dev environment has no interactive TTY and no Accessibility
automation permission for `osascript`, the same wall A-36's own report
already hit and documented, `osascript: ... is not allowed`/"Функции
Упрощённого доступа... не разрешены", code -1728).
"""

from __future__ import annotations

from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.mcp.security_connectors.os_firewall as os_firewall_module
from app.db.models import BlockedPort
from app.services.mcp.security_connectors.elevated import ElevatedRunResult
from app.services.mcp.security_connectors.os_firewall import (
    LINUX_BLOCKED_PORTS_CHAIN,
    MACOS_BLOCKED_PORTS_ANCHOR,
    OSFirewallError,
    block_port,
    delete_blocked_port,
    list_blocked_ports,
    record_blocked_port,
    unblock_port,
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
# _build_macos_sync_blocked_ports_script — the pf-anchor full-reconstruction
# builder (see its own docstring for why a full rebuild, not an incremental
# patch, is required for pf anchors).
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_macos_sync_script_blocks_both_tcp_and_udp_for_every_port():
    script = os_firewall_module._build_macos_sync_blocked_ports_script([8080, 22])

    assert f"pfctl -a {MACOS_BLOCKED_PORTS_ANCHOR} -f -" in script
    assert "block in proto tcp from any to any port 22" in script
    assert "block in proto udp from any to any port 22" in script
    assert "block in proto tcp from any to any port 8080" in script
    assert "block in proto udp from any to any port 8080" in script
    # Sorted, deterministic ordering — 22 before 8080 regardless of input order.
    assert script.index("port 22") < script.index("port 8080")


@pytest.mark.unit
def test_macos_sync_script_dedupes_repeated_port_numbers():
    script = os_firewall_module._build_macos_sync_blocked_ports_script([443, 443, 443])

    assert script.count("port 443") == 2  # exactly one tcp + one udp line, not three of each


@pytest.mark.unit
def test_macos_sync_script_with_empty_list_still_loads_an_empty_ruleset():
    """The 'last blocked port was just unblocked' case — must still run
    `pfctl -a <anchor> -f -` (clearing the anchor), never skipped as a
    no-op, or a previously-blocked port would stay blocked forever."""
    script = os_firewall_module._build_macos_sync_blocked_ports_script([])

    assert f"pfctl -a {MACOS_BLOCKED_PORTS_ANCHOR} -f -" in script
    assert "block in proto" not in script


# ---------------------------------------------------------------------------
# block_port() / unblock_port() — per-platform elevated dispatch
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_block_port_runs_the_anchor_sync_script_via_bin_bash(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["reason_ru"] = reason_ru
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await block_port(8080, all_blocked_ports=[8080])

    assert result == {"status": "ok", "port": 8080, "blocked": True}
    assert captured["command"][0] == "/bin/bash"
    assert "8080" in captured["reason_ru"]
    assert "block in proto tcp from any to any port 8080" in captured["script_text"]


@pytest.mark.unit
async def test_macos_block_port_passes_the_full_desired_port_set_to_the_script(
    monkeypatch: pytest.MonkeyPatch,
):
    """The whole point of `all_blocked_ports`: blocking a NEW port must not
    silently drop a port that was already blocked before this call — pf's
    anchor content is fully replaced on every write (see
    `_build_macos_sync_blocked_ports_script`'s own docstring)."""
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    await block_port(9090, all_blocked_ports=[22, 9090])

    assert "port 22" in captured["script_text"]
    assert "port 9090" in captured["script_text"]


@pytest.mark.unit
async def test_macos_unblock_port_reconstructs_the_anchor_without_the_removed_port(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await unblock_port(9090, all_blocked_ports=[22])

    assert result == {"status": "ok", "port": 9090, "blocked": False}
    assert "port 22" in captured["script_text"]
    assert "port 9090" not in captured["script_text"]


@pytest.mark.unit
@pytest.mark.parametrize("func,kwargs", [(block_port, {}), (unblock_port, {})])
async def test_macos_block_unblock_port_cancelled_raises_elevation_cancelled(
    monkeypatch: pytest.MonkeyPatch, func, kwargs
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="cancelled"))
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func(8080, all_blocked_ports=[8080])

    assert exc_info.value.reason == "elevation_cancelled"


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_port, unblock_port])
async def test_macos_block_unblock_port_failed_raises_elevation_failed(
    monkeypatch: pytest.MonkeyPatch, func
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_firewall_module,
        "elevated_run",
        _fake_elevated_run(ElevatedRunResult(status="failed", stderr="pfctl: syntax error")),
    )

    with pytest.raises(OSFirewallError) as exc_info:
        await func(8080, all_blocked_ports=[8080])

    assert exc_info.value.reason == "elevation_failed"


@pytest.mark.unit
async def test_linux_block_port_creates_the_chain_and_two_tagged_rules(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["command"] = command
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await block_port(8080, all_blocked_ports=[8080])

    assert result == {"status": "ok", "port": 8080, "blocked": True}
    script = captured["script_text"]
    assert f"iptables -N {LINUX_BLOCKED_PORTS_CHAIN}" in script
    assert f"-j {LINUX_BLOCKED_PORTS_CHAIN}" in script
    assert f"-A {LINUX_BLOCKED_PORTS_CHAIN} -p tcp --dport 8080 -j DROP" in script
    assert f"-A {LINUX_BLOCKED_PORTS_CHAIN} -p udp --dport 8080 -j DROP" in script


@pytest.mark.unit
async def test_linux_unblock_port_deletes_both_tagged_rules(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Linux")
    captured: dict = {}

    async def fake_elevated_run(command, *, reason_ru, reason_en, timeout=120.0, runner=None):
        captured["script_text"] = open(command[1], encoding="utf-8").read()
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", fake_elevated_run)

    result = await unblock_port(8080, all_blocked_ports=[])

    assert result == {"status": "ok", "port": 8080, "blocked": False}
    script = captured["script_text"]
    assert f"-D {LINUX_BLOCKED_PORTS_CHAIN} -p tcp --dport 8080 -j DROP" in script
    assert f"-D {LINUX_BLOCKED_PORTS_CHAIN} -p udp --dport 8080 -j DROP" in script


@pytest.mark.unit
async def test_windows_block_port_uses_a_recognisable_display_name(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await block_port(3389, all_blocked_ports=[3389])

    assert captured["command"][0] == "powershell.exe"
    ps_command = captured["command"][-1]
    assert "New-NetFirewallRule" in ps_command
    assert "Hranix Shield - Block port 3389 (TCP)" in ps_command
    assert "Hranix Shield - Block port 3389 (UDP)" in ps_command
    assert '"' not in ps_command  # no embedded double quotes — see _build_windows_block_port_command's docstring


@pytest.mark.unit
async def test_windows_unblock_port_removes_the_same_named_rules(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "Windows")
    captured: dict = {}
    monkeypatch.setattr(
        os_firewall_module, "elevated_run", _fake_elevated_run(ElevatedRunResult(status="ok"), captured=captured)
    )

    await unblock_port(3389, all_blocked_ports=[])

    ps_command = captured["command"][-1]
    assert "Remove-NetFirewallRule" in ps_command
    assert "Hranix Shield - Block port 3389 (TCP)" in ps_command
    assert "Hranix Shield - Block port 3389 (UDP)" in ps_command


@pytest.mark.unit
@pytest.mark.parametrize("func", [block_port, unblock_port])
async def test_block_unblock_port_unsupported_platform_raises_not_configured(
    monkeypatch: pytest.MonkeyPatch, func
):
    monkeypatch.setattr(os_firewall_module.platform, "system", lambda: "PlanNine")
    called = {"count": 0}

    async def _should_not_be_called(*args, **kwargs):
        called["count"] += 1
        return ElevatedRunResult(status="ok")

    monkeypatch.setattr(os_firewall_module, "elevated_run", _should_not_be_called)

    with pytest.raises(OSFirewallError) as exc_info:
        await func(8080, all_blocked_ports=[8080])

    assert exc_info.value.reason == "not_configured"
    assert called["count"] == 0


# ---------------------------------------------------------------------------
# record_blocked_port / list_blocked_ports / delete_blocked_port — the
# persistent `blocked_ports` table, against the real migrated tmp SQLite DB.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_record_blocked_port_writes_a_new_row(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        row = await record_blocked_port(session, port=8080, protocol="tcp", process_name="nginx")

    assert row.port == 8080
    assert row.protocol == "tcp"
    assert row.process_name == "nginx"
    assert isinstance(row.blocked_at, datetime)

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert len(rows) == 1
    assert rows[0].port == 8080


@pytest.mark.unit
async def test_record_blocked_port_is_idempotent_and_updates_in_place(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """A retried/duplicate block click must not raise a unique-constraint
    error on `port` — it updates the existing row instead (see
    `BlockedPort.port`'s own `unique=True`)."""
    async with migrated_session_maker() as session:
        await record_blocked_port(session, port=8080, protocol="tcp", process_name="nginx")
    async with migrated_session_maker() as session:
        await record_blocked_port(session, port=8080, protocol="udp", process_name="nginx-updated")

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert len(rows) == 1
    assert rows[0].protocol == "udp"
    assert rows[0].process_name == "nginx-updated"


@pytest.mark.unit
async def test_record_blocked_port_accepts_none_protocol_and_process_name(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        row = await record_blocked_port(session, port=53, protocol=None, process_name=None)

    assert row.protocol is None
    assert row.process_name is None


@pytest.mark.unit
async def test_list_blocked_ports_orders_by_port_ascending(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        await record_blocked_port(session, port=9090, protocol="tcp", process_name=None)
    async with migrated_session_maker() as session:
        await record_blocked_port(session, port=22, protocol="tcp", process_name=None)

    async with migrated_session_maker() as session:
        rows = await list_blocked_ports(session)

    assert [row.port for row in rows] == [22, 9090]


@pytest.mark.unit
async def test_delete_blocked_port_removes_an_existing_row_and_returns_true(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        await record_blocked_port(session, port=8080, protocol="tcp", process_name=None)

    async with migrated_session_maker() as session:
        removed = await delete_blocked_port(session, port=8080)
    assert removed is True

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(BlockedPort))).all()
    assert rows == []


@pytest.mark.unit
async def test_delete_blocked_port_returns_false_when_nothing_to_remove(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        removed = await delete_blocked_port(session, port=12345)

    assert removed is False
