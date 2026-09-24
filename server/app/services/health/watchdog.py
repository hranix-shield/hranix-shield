"""A-65-6: логика трей-сторожа — стартовая проверка машины и решение «что
предложить владельцу» (уровень 0 реанимации: работает всегда, до и без
панели). Здесь ТОЛЬКО честная async-логика и коды; окна-вопросы/уведомления
и запуск потоков — в packaging/windows/hranix_shield_tray.py (там её и
исполняют), поэтому эта логика полноценно покрыта автотестами на моках
run_local_command — живой прогон трея в pytest невозможен по определению.

Решения (план-спецификация A-65, «Уровень 0»):
  - Docker-движок лежит, НО Docker Desktop установлен → уведомление-вопрос
    «Запустить?» (suggest_start_docker_desktop); движок не установлен —
    предложения нет (запускать нечего);
  - движок жив, контейнеры стека отсутствуют/остановлены → suggest_compose_up
    (идемпотентный bootstrap, тот же код, что кнопка панели);
  - сервер не поднялся за таймаут → уведомление с путём журнала
    (resolve_assistant_log_path — путь знает только этот модуль).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.config import REPO_ROOT, _packaged_log_dir, is_packaged
from app.services.health.remediation import _docker_desktop_installation
from app.services.health.system import (
    _check_docker_engine,
    _inspect_containers,
)
from app.services.stack.bootstrap import EXPECTED_CONTAINERS

logger = logging.getLogger(__name__)

ENGINE_WAIT_TIMEOUT = 90.0
ENGINE_POLL_INTERVAL = 3.0


def resolve_assistant_log_path() -> str:
    """Путь журнала для уведомления «сервер не поднялся» (в уведомлении путь
    уместен — это локальный UI продукта, не API-контракт)."""
    if is_packaged():
        return str(_packaged_log_dir() / "assistant.log")
    return str(REPO_ROOT / "logs" / "assistant.log")


async def gather_startup_assessment() -> dict[str, Any]:
    """Один стартовый срез машины. Никогда не бросает — любое «не удалось
    спросить» это честное отсутствие предложения, а не крах сторожа."""
    assessment: dict[str, Any] = {
        "engine_status": "unknown",
        "docker_desktop_installed": False,
        "containers_absent_or_stopped": [],
        "suggest_start_docker_desktop": False,
        "suggest_compose_up": False,
    }
    try:
        engine = await _check_docker_engine()
        engine_status = engine["status"]
        assessment["engine_status"] = engine_status
    except Exception as exc:
        logger.info("watchdog: engine probe failed: %s", exc)
        return assessment

    installation = _docker_desktop_installation()
    assessment["docker_desktop_installed"] = installation is not None

    # Движок лежит, но Desktop установлен → вопрос «Запустить?»; не
    # установлен — предлагать нечего (установка вне полномочий сторожа).
    assessment["suggest_start_docker_desktop"] = (
        engine_status == "unreachable" and installation is not None
    )

    if engine_status != "ok":
        return assessment

    try:
        inspected = await _inspect_containers()
    except Exception as exc:
        logger.info("watchdog: containers probe failed: %s", exc)
        return assessment
    absent_or_stopped = [
        name
        for name in EXPECTED_CONTAINERS
        if name not in inspected or inspected[name][0] != "running"
    ]
    assessment["containers_absent_or_stopped"] = absent_or_stopped
    assessment["suggest_compose_up"] = bool(absent_or_stopped)
    return assessment


async def wait_for_engine(
    *, timeout: float = ENGINE_WAIT_TIMEOUT, poll_interval: float = ENGINE_POLL_INTERVAL
) -> bool:
    """После запуска Docker Desktop движку нужно десятки секунд — опрашиваем
    `docker info` до успеха или таймаута (безопасно отменить в любой момент)."""
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        try:
            engine = await _check_docker_engine()
            if engine["status"] == "ok":
                return True
        except Exception as exc:
            logger.info("watchdog: engine wait probe failed: %s", exc)
        await asyncio.sleep(poll_interval)
    return False
