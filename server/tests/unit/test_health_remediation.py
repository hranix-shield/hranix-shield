"""A-65-3: remediation-действия (services/health/remediation.py) на моках
run_local_command — docker-вызовов в тестах нет, живой рестарт контейнера —
живой прогон, не автотест. Кэш матрицы обслуживается autouse-фикстурой
conftest (сбрасывается до/после каждого теста)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import app.services.health.remediation as remediation_module
import app.services.health.system as health_system_module


def _override_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    response: tuple[int, str, str] = (0, "", ""),
    calls: list[tuple[str, ...]] | None = None,
    raise_not_found: bool = False,
    raise_timeout: bool = False,
):
    from app.services.mcp.security_connectors._local_command import (
        LocalCommandNotFound,
        LocalCommandTimedOut,
    )

    async def fake_run(*args: str, timeout: float = 5.0):
        if calls is not None:
            calls.append(args)
        if raise_not_found:
            raise LocalCommandNotFound(f"{args[0]!r} is not installed")
        if raise_timeout:
            raise LocalCommandTimedOut(f"{args[0]!r} timed out")
        return response

    # Один рекордер на ОБА модуля: кэш-сбор после инвалидации идёт через
    # system.run_local_command, сам рестарт — через remediation.run_local_command.
    monkeypatch.setattr(remediation_module, "run_local_command", fake_run)
    monkeypatch.setattr(health_system_module, "run_local_command", fake_run)


@pytest.mark.unit
async def test_restart_container_runs_docker_restart_and_invalidates_cache(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[tuple[str, ...]] = []
    _override_run(monkeypatch, calls=calls)
    health_system_module.invalidate_system_health_cache()
    await health_system_module.collect_system_health()  # кэш заполнен

    result = await remediation_module.restart_container("hranix-crowdsec")

    assert result == {"status": "ok", "detail": "restarted"}
    assert ("docker", "restart", "hranix-crowdsec") in calls
    # Кэш сброшен: следующий сбор реально дергает docker info, а не отдаёт
    # 30-секундной давности payload.
    info_calls = [c for c in calls if "info" in " ".join(c)]
    assert len(info_calls) == 1


@pytest.mark.unit
async def test_restart_container_rejects_unknown_names_without_docker_call(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[tuple[str, ...]] = []
    _override_run(monkeypatch, calls=calls)

    result = await remediation_module.restart_container("some-other-container")

    assert result == {"status": "error", "detail": "unknown_container"}
    assert calls == []  # произвольный контейнер пользователя не трогаем


@pytest.mark.unit
@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"raise_not_found": True}, "docker_not_installed"),
        ({"raise_timeout": True}, "timeout"),
        ({"response": (1, "", "daemon down")}, "restart_failed"),
    ],
)
async def test_restart_container_honest_failures(monkeypatch, kwargs, expected):
    _override_run(monkeypatch, **kwargs)

    result = await remediation_module.restart_container("hranix-clamav")

    assert result == {"status": "error", "detail": expected}


@pytest.mark.unit
async def test_compose_up_stack_delegates_to_bootstrap_and_invalidates_cache(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[str] = []

    async def fake_bootstrap():
        calls.append("bootstrap")
        return {"status": "ok", "steps": [], "restart_required": True}

    monkeypatch.setattr(remediation_module, "run_stack_bootstrap", fake_bootstrap)
    health_system_module.invalidate_system_health_cache()

    result = await remediation_module.compose_up_stack()

    assert result["status"] == "ok"
    assert result["restart_required"] is True
    assert calls == ["bootstrap"]
    assert health_system_module._cache is None


@pytest.mark.unit
async def test_start_docker_desktop_windows_spawns_installed_exe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    exe = tmp_path / "Docker Desktop.exe"
    exe.write_bytes(b"fake-pe")
    spawned: list[Path] = []

    async def fake_spawn(path: Path):
        spawned.append(path)

    monkeypatch.setattr(remediation_module, "_docker_desktop_installation", lambda: exe)
    monkeypatch.setattr(remediation_module, "_spawn_detached_windows", fake_spawn)

    result = await remediation_module.start_docker_desktop()

    assert result == {"status": "ok", "detail": "docker_desktop_starting"}
    assert spawned == [exe]


@pytest.mark.unit
async def test_start_docker_desktop_not_installed_is_honest_error(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(remediation_module, "_docker_desktop_installation", lambda: None)

    result = await remediation_module.start_docker_desktop()

    assert result == {"status": "error", "detail": "docker_desktop_not_found"}


@pytest.mark.unit
async def test_start_docker_desktop_spawn_failure_is_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    async def boom(path: Path):
        raise OSError("access denied")

    monkeypatch.setattr(
        remediation_module, "_docker_desktop_installation", lambda: tmp_path / "x.exe"
    )
    monkeypatch.setattr(remediation_module, "_spawn_detached_windows", boom)

    result = await remediation_module.start_docker_desktop()

    assert result == {"status": "error", "detail": "spawn_failed"}


@pytest.mark.unit
async def test_docker_desktop_installation_resolves_windows_layout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Реальный резолв установки: <ProgramFiles>\\Docker\\Docker\\Docker
    Desktop.exe (тот же приём подмены sys.platform, что test_osquery_connector)."""
    fake_pf = tmp_path / "Program Files"
    exe = fake_pf / "Docker" / "Docker" / "Docker Desktop.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"fake-pe")
    monkeypatch.setenv("ProgramFiles", str(fake_pf))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(remediation_module.sys, "platform", "win32")

    assert remediation_module._docker_desktop_installation() == exe


@pytest.mark.unit
async def test_ping_components_forces_fresh_collection(monkeypatch):
    forced: list[bool] = []

    async def fake_collect(*, force: bool = False):
        forced.append(force)
        return {"aggregate": "ok", "components": []}

    monkeypatch.setattr(remediation_module, "collect_system_health", fake_collect)
    # Кэш не пуст — ping обязан его игнорировать.
    health_system_module._cache = {"at": health_system_module._now(), "payload": {}}

    result = await remediation_module.ping_components()

    assert result == {"aggregate": "ok", "components": []}
    assert forced == [True]
    assert health_system_module._cache is None
