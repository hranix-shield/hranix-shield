"""A-63-2 regression anchor (первое живое тестирование с полным стеком,
2026-09-21): консоль «Сеть» 500-ила, когда osqueryi не уложился в таймаут.

Две корневые причины — обе зафиксированы здесь:

  1. `run_local_command` в таймаут-ветке звал `process.kill()` без защиты:
     ребёнок, успевший умереть между срабатыванием таймаута и kill'ом,
     бросал ProcessLookupError (на Windows asyncio тот же мёртвый ребёнок
     может проявиться и как ChildProcessError) — необработанное исключение
     роняло и эндпоинт `/security/consoles/network`, и `_loop` сэмплера
     метрик. Пин: kill в таймаут-ветке НЕ бросает наружу ни при каком
     исходе, наружу уходит только `LocalCommandTimedOut`.

  2. Таймаут osquery (5с) был мал для реальной машины: ~294 живых
     соединения занимают у osqueryi 3–6с, на нагруженной машине больше.
     Пин: медленные сканы сокетов (`fetch_network_console_data` /
     `fetch_listening_ports`) передают `OSQUERY_NETWORK_SCAN_TIMEOUT_S`
     (15с), а мелкие introspection-запросы (av/processes) — прежний
     дефолт.

Интеграционный тест внизу прогоняет сценарий владельца через реальный
HTTP-слой (мок osqueryi «завис навсегда» на уровне `run_local_command`,
самый нижний уровень, — не заглушка `fetch_network_console_data`):
честная деградация `unreachable`, 200, не 500.
"""

import asyncio

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.mcp.security_connectors.osquery as osquery_module
from app.services.mcp.security_connectors._local_command import (
    LocalCommandTimedOut,
    run_local_command,
)
from tests.common.factories import create_user


class _DyingChildProcess:
    """Фейковый потомок, повторяющий живой сценарий: `communicate()` висит
    дольше любого таймаута, а к моменту kill'а процесс уже умер — kill
    бросает заданное исключение (ProcessLookupError / ChildProcessError)."""

    def __init__(self, kill_exc: Exception):
        self._kill_exc = kill_exc
        self.returncode = None

    async def communicate(self):
        await asyncio.sleep(3600)
        return (b"", b"")

    def kill(self):
        raise self._kill_exc

    async def wait(self):
        self.returncode = -9
        return self.returncode


@pytest.mark.unit
async def test_kill_race_process_already_dead_still_raises_timeout_only(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", _fake_exec(_DyingChildProcess(ProcessLookupError()))
    )

    with pytest.raises(LocalCommandTimedOut):
        await run_local_command("some-binary", "--flag", timeout=0.05)


@pytest.mark.unit
async def test_kill_race_windows_child_process_error_still_raises_timeout_only(
    monkeypatch: pytest.MonkeyPatch,
):
    """Windows-ветка спеки: asyncio на Windows может показать того же
    мёртвого ребёнка как ChildProcessError — гасится так же."""
    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", _fake_exec(_DyingChildProcess(ChildProcessError()))
    )

    with pytest.raises(LocalCommandTimedOut):
        await run_local_command("some-binary", "--flag", timeout=0.05)


def _fake_exec(process):
    async def _exec(*args, **kwargs):
        return process

    return _exec


@pytest.mark.unit
async def test_network_console_socket_scans_get_the_extended_timeout(
    monkeypatch: pytest.MonkeyPatch,
):
    seen_timeouts: list[float] = []

    async def _run(*args: str, timeout: float = 5.0):
        seen_timeouts.append(timeout)
        if "process_open_sockets" in args[2]:
            raise LocalCommandTimedOut("'osqueryi' timed out")
        return 0, "[]", ""

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    network = await osquery_module.fetch_network_console_data()
    ports = await osquery_module.fetch_listening_ports()

    # Оба скана network (listening_ports, затем process_open_sockets) и
    # единственный скан listening_ports для perimeter — все с расширенным
    # таймаутом A-63-2 (мок роняет только process_open_sockets, чтобы оба
    # network-запроса реально дошли до run_local_command).
    assert seen_timeouts == [
        osquery_module.OSQUERY_NETWORK_SCAN_TIMEOUT_S,
        osquery_module.OSQUERY_NETWORK_SCAN_TIMEOUT_S,
        osquery_module.OSQUERY_NETWORK_SCAN_TIMEOUT_S,
    ]
    assert osquery_module.OSQUERY_NETWORK_SCAN_TIMEOUT_S == 15.0
    assert network["connector"] == {"status": "unreachable"}
    assert ports["connector"] == {"status": "ok"}


@pytest.mark.unit
async def test_av_introspection_queries_keep_the_default_timeout(
    monkeypatch: pytest.MonkeyPatch,
):
    """Мелкие introspection-запросы av-консоли (processes/osquery_flags) не
    должны незаметно удлиняться вместе со сканами сокетов — прежний дефолт
    5с остаётся их бюджетом."""
    seen_timeouts: list[float] = []

    async def _run(*args: str, timeout: float = 5.0):
        seen_timeouts.append(timeout)
        raise LocalCommandTimedOut("'osqueryi' timed out")

    monkeypatch.setattr(osquery_module, "run_local_command", _run)

    result = await osquery_module.fetch_av_osquery_data()

    assert result["connector"] == {"status": "unreachable"}
    assert seen_timeouts == [5.0]


# ---------------------------------------------------------------------------
# Интеграционный уровень: сценарий владельца через реальный HTTP-слой.
# ---------------------------------------------------------------------------


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_network_endpoint_degrades_honestly_when_osqueryi_hangs_past_the_timeout(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Мок на самом нижнем уровне (`osquery.run_local_command`), не на
    `fetch_network_console_data`: исключение проходит через реальный
    `_query` → реальный роутер → обязано превратиться в честный
    `unreachable`-статус с 200, а не в 500 (живой симптом владельца)."""

    async def _hanging_osqueryi(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut(f"'osqueryi' timed out after {timeout}s")

    monkeypatch.setattr(osquery_module, "run_local_command", _hanging_osqueryi)
    headers = await _admin_headers(client, migrated_session_maker, "a63_network_timeout")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connector"] == {"status": "unreachable"}
    assert body["connections"] == []
    assert body["metrics"]["active_connections"] is None
