"""A-65-3: remediation-действия реанимации (админ-уровень, уровень 2
реанимации план-спецификации A-65) — кнопки «запустить/перезапустить»
у каждого упавшего компонента матрицы /health/system.

Четыре действия, все возвращают машиночитаемые коды (текст локализует
клиент, §0.2) и НИКИКОГДА не бросают исключений наружу:
  - restart_container(name) — `docker restart` одного из ТРЁХ известных
    контейнеров стека (имя валидируется по EXPECTED_CONTAINERS —
    произвольный контейнер пользователя панель трогать не может);
  - compose_up_stack() — идемпотентный bootstrap стека (populate filebeat
    volume A-63-6b + compose up, services/stack/bootstrap.py), тот же код,
    что «Настройки → Стек защиты»;
  - start_docker_desktop() — ЗАПУСК установленного Docker Desktop (не
    установка): Windows — spawn исполняемого файла detached, macOS —
    `open -a Docker`. На Linux установленный Docker Desktop невозможен по
    определению → честный docker_desktop_not_found;
  - ping_components() — сброс кэша матрицы + свежий сбор (кнопка
    «Проверить снова»).

После restart_container/compose_up_stack кэш матрицы сбрасывается:
следующий GET /health/system видит мир после действия, а не 30-секундной
давности. Все внешние вызовы — через run_local_command (argv, не
shell-строка) — это имя мокают тесты.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path
from typing import Any

from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    run_local_command,
)
from app.services.stack.bootstrap import EXPECTED_CONTAINERS, run_stack_bootstrap
from app.services.health.system import (
    collect_system_health,
    invalidate_system_health_cache,
)

logger = logging.getLogger(__name__)

_RESTART_TIMEOUT = 60.0
_OPEN_TIMEOUT = 10.0

# DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP — Docker Desktop переживает
# наш процесс и не тянет за собой консоль (панель-процесс может быть GUI
# без консоли, см. WINDOWS_CREATE_NO_WINDOW в _local_command).
_WINDOWS_DETACHED_FLAGS = 0x00000008 | 0x00000200


def _docker_desktop_installation() -> Path | None:
    """Путь к установленному Docker Desktop, если он есть (ЗАПУСК, не
    установка: план-спецификация — «запуск установленного Docker Desktop.exe»).
    Windows: общесистемная и per-user установки; macOS: /Applications/Docker.app;
    Linux: None — панельного запуска демона там нет (systemd вне A-65)."""
    if sys.platform == "win32":
        program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
        local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
        candidates = [
            program_files / "Docker" / "Docker" / "Docker Desktop.exe",
            local_app_data / "Docker" / "Docker Desktop.exe",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        return None
    if sys.platform == "darwin":
        docker_app = Path("/Applications/Docker.app")
        return docker_app if docker_app.exists() else None
    return None


async def _spawn_detached_windows(exe_path: Path) -> None:
    """Запускает GUI-процесс Docker Desktop и НЕ ждёт его завершения —
    движок поднимается десятки секунд, статус увидит следующий опрос
    матрицы. create_subprocess_exec (argv, не shell); creationflags —
    Windows-only kwarg, POSIX-ветка его не передаёт вовсе."""
    process = await asyncio.create_subprocess_exec(
        str(exe_path),
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        creationflags=_WINDOWS_DETACHED_FLAGS,
    )
    # Сознательно не await process.wait(): detached-процесс живёт своей
    # жизнью; transport-ы pipe-ов DEVNULL, читать/закрывать нечего.
    _ = process


async def restart_container(name: str) -> dict[str, Any]:
    """`docker restart <name>` для одного из контейнеров стека. docker
    restart поднимает и остановленный контейнер — «запустить» и
    «перезапустить» здесь одно действие, как в плане («кнопки
    запуска/перезапуска»)."""
    if name not in EXPECTED_CONTAINERS:
        return {"status": "error", "detail": "unknown_container"}
    try:
        code, _stdout, stderr = await run_local_command(
            "docker", "restart", name, timeout=_RESTART_TIMEOUT
        )
    except LocalCommandNotFound:
        return {"status": "error", "detail": "docker_not_installed"}
    except LocalCommandTimedOut:
        return {"status": "error", "detail": "timeout"}
    if code != 0:
        logger.info("health: docker restart %s failed: %s", name, stderr.strip()[:200])
        return {"status": "error", "detail": "restart_failed"}
    invalidate_system_health_cache()
    return {"status": "ok", "detail": "restarted"}


async def compose_up_stack() -> dict[str, Any]:
    """Идемпотентный bootstrap всего стека (A-60/A-63-6b): ответ —
    пошаговый статус run_stack_bootstrap как есть (status/steps/
    restart_required). Кэш матрицы сбрасываем в любом исходе."""
    invalidate_system_health_cache()
    return await run_stack_bootstrap()


async def start_docker_desktop() -> dict[str, Any]:
    installation = _docker_desktop_installation()
    if installation is None:
        return {"status": "error", "detail": "docker_desktop_not_found"}
    try:
        if sys.platform == "win32":
            await _spawn_detached_windows(installation)
        else:
            await run_local_command("open", "-a", "Docker", timeout=_OPEN_TIMEOUT)
    except (OSError, LocalCommandNotFound, LocalCommandTimedOut) as exc:
        logger.info("health: docker desktop spawn failed: %s", exc)
        return {"status": "error", "detail": "spawn_failed"}
    return {"status": "ok", "detail": "docker_desktop_starting"}


async def ping_components() -> dict[str, Any]:
    """Сброс кэша + принудительный свежий сбор матрицы — «Проверить снова»."""
    invalidate_system_health_cache()
    return await collect_system_health(force=True)
