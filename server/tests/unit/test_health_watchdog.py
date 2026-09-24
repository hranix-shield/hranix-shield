"""A-65-6: решения трей-сторожа (services/health/watchdog.py) на моках —
зондов движка/контейнеров и резолва установки Docker Desktop. Живой прогон
самого трея — живой прогон на Windows-машине, не автотест."""

from __future__ import annotations

import pytest

import app.services.health.watchdog as watchdog_module
from app.config import REPO_ROOT


def _engine(status: str):
    return {"id": "docker_engine", "status": status, "detail": None, "action": None}


@pytest.mark.unit
async def test_engine_down_with_desktop_installed_suggests_start(monkeypatch):
    """Ключевой сценарий плана: движок лежит, Desktop установлен → вопрос
    «Запустить?»; compose не предлагаем — сначала движок."""

    async def engine_unreachable():
        return _engine("unreachable")

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_unreachable)
    monkeypatch.setattr(watchdog_module, "_docker_desktop_installation", lambda: object())

    assessment = await watchdog_module.gather_startup_assessment()

    assert assessment["engine_status"] == "unreachable"
    assert assessment["docker_desktop_installed"] is True
    assert assessment["suggest_start_docker_desktop"] is True
    assert assessment["suggest_compose_up"] is False


@pytest.mark.unit
async def test_engine_down_without_desktop_suggests_nothing(monkeypatch):
    async def engine_unreachable():
        return _engine("unreachable")

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_unreachable)
    monkeypatch.setattr(watchdog_module, "_docker_desktop_installation", lambda: None)

    assessment = await watchdog_module.gather_startup_assessment()

    assert assessment["engine_status"] == "unreachable"
    assert assessment["docker_desktop_installed"] is False
    assert assessment["suggest_start_docker_desktop"] is False
    assert assessment["suggest_compose_up"] is False


@pytest.mark.unit
async def test_engine_not_configured_suggests_nothing(monkeypatch):
    async def engine_missing():
        return _engine("not_configured")

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_missing)
    monkeypatch.setattr(watchdog_module, "_docker_desktop_installation", lambda: object())

    assessment = await watchdog_module.gather_startup_assessment()

    # Desktop «установлен», но docker-бинаря нет вовсе — запускать нечего:
    # suggest_start_docker_desktop только для unreachable.
    assert assessment["suggest_start_docker_desktop"] is False
    assert assessment["suggest_compose_up"] is False


@pytest.mark.unit
async def test_engine_ok_and_stack_running_suggests_nothing(monkeypatch):
    async def engine_ok():
        return _engine("ok")

    inspected = {
        "hranix-crowdsec": ("running", "none"),
        "hranix-clamav": ("running", "none"),
        "hranix-wazuh-manager": ("running", "healthy"),
    }

    async def inspect_ok():
        return inspected

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_ok)
    monkeypatch.setattr(watchdog_module, "_inspect_containers", inspect_ok)

    assessment = await watchdog_module.gather_startup_assessment()

    assert assessment["suggest_start_docker_desktop"] is False
    assert assessment["suggest_compose_up"] is False
    assert assessment["containers_absent_or_stopped"] == []


@pytest.mark.unit
async def test_stopped_and_absent_containers_suggest_compose_up(monkeypatch):
    async def engine_ok():
        return _engine("ok")

    inspected = {
        "hranix-crowdsec": ("exited", "none"),
        "hranix-clamav": ("running", "none"),
        # wazuh отсутствует (не создан)
    }

    async def inspect_partial():
        return inspected

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_ok)
    monkeypatch.setattr(watchdog_module, "_inspect_containers", inspect_partial)

    assessment = await watchdog_module.gather_startup_assessment()

    assert assessment["suggest_compose_up"] is True
    assert assessment["containers_absent_or_stopped"] == [
        "hranix-crowdsec",
        "hranix-wazuh-manager",
    ]


@pytest.mark.unit
async def test_wait_for_engine_returns_true_when_engine_comes_up(monkeypatch):
    states = iter(["unreachable", "ok"])

    async def engine_flaky():
        return _engine(next(states))

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_flaky)

    assert await watchdog_module.wait_for_engine(timeout=5.0, poll_interval=0.01) is True


@pytest.mark.unit
async def test_wait_for_engine_times_out_honestly(monkeypatch):
    async def engine_down():
        return _engine("unreachable")

    monkeypatch.setattr(watchdog_module, "_check_docker_engine", engine_down)

    assert await watchdog_module.wait_for_engine(timeout=0.05, poll_interval=0.01) is False


@pytest.mark.unit
def test_assistant_log_path_points_at_repo_logs_in_dev():
    assert watchdog_module.resolve_assistant_log_path() == str(
        REPO_ROOT / "logs" / "assistant.log"
    )
