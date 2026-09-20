"""Windows-приёмка 2026-09-19: GUI-процесс (трей без своей консоли) без
CREATE_NO_WINDOW даёт каждому консольному потомку — netsh, powershell,
osqueryi, restic — новое видимое окно терминала; на каденции обновления
панели и метрик это делает рабочий стол непригодным (живая находка, сразу
после первой установки). Тесты фиксируют: (1) общий хелпер всегда передаёт
creationflags, (2) на Windows это ровно CREATE_NO_WINDOW, на POSIX — 0."""

import asyncio
import subprocess
import sys

import pytest

import app.services.mcp.security_connectors._local_command as local_command_module
from app.services.mcp.security_connectors._local_command import (
    WINDOWS_CREATE_NO_WINDOW,
    run_local_command,
)


class _FakeProcess:
    def __init__(self):
        self.returncode = 0

    async def communicate(self):
        return (b"ok", b"")

    def kill(self):
        pass

    async def wait(self):
        return 0


@pytest.mark.unit
async def test_run_local_command_always_passes_creationflags(monkeypatch: pytest.MonkeyPatch):
    captured: dict = {}

    async def _fake_exec(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return _FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    stdout = await run_local_command("some-binary", "--flag")

    assert stdout == (0, "ok", "")
    assert captured["kwargs"]["creationflags"] == WINDOWS_CREATE_NO_WINDOW


@pytest.mark.unit
def test_constant_is_create_no_window_on_windows_and_zero_elsewhere():
    if sys.platform == "win32":
        assert WINDOWS_CREATE_NO_WINDOW == subprocess.CREATE_NO_WINDOW
    else:
        assert WINDOWS_CREATE_NO_WINDOW == 0
