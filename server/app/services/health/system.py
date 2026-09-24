"""A-65-1: системная матрица здоровья — честный опрос ВСЕХ компонентов
машины, а не только внутренних подсистем процесса. Триггер-инцидент
2026-09-23: пилюля «Здоровье» показывала OK при лежащем Docker-стеке,
потому что HealthRegistry знал только database/event_bus; коннекторы
имели свои честные статусы внутри консолей, но агрегат на них не смотрел.
План-спецификация:
docs/план-спецификация-фаза-0-A65-реанимация-2026-09-23.md.

Матрица (порядок фиксирован, клиент локализует лейблы по id — §0.2):
  server, database, event_bus, docker_engine, hranix-crowdsec,
  hranix-clamav, hranix-wazuh-manager, wazuh_api, crowdsec_lapi, clamd,
  restic, osqueryi, disk (свободное место >= 5 ГБ на диске данных).

Статус компонента — из четырёх честных состояний (не «всё сведено к
ok/down»): ok / not_configured (не установлен/не настроен — норма свежей
установки, но агрегату это не «ok») / degraded / unreachable.
Агрегат = худшее по шкале ok(0) < not_configured=degraded(1) < unreachable(2)
→ «ok» / «degraded» / «down».

ПУБЛИЧНЫЙ контракт (GET /health/system без auth — уровня 1 реанимации,
полоса на форме входа): только статусы, коды причин и коды действий —
НИКАКИХ секретов и путей (detail — фиксированные машиночитаемые коды,
никогда не сырой текст исключения: строка исключения может содержать
путь/URL, например sqlite-ошибка).

Кэш 30с + in-flight guard (урок A-63-3: одновременные пилюля-поллинг,
форма входа, «Проверить снова» и registry-чек не должны устраивать шторм
subprocess-ов — один собирает, остальные ждут его результат). Блокировка
in-flight — на каждый цикл событий своя (сервер живёт в одном цикле, но
трей-сторож A-65-6 и pytest-тесты входят через свои asyncio.run; словарь
кэша при этом общий — атомарная подмена ссылки, дубликат работы в худшем
случае, не гонка состояния).

Все внешние вызовы — через run_local_command (argv, не shell-строка), HTTP
и clamd-зонды — через module-level функции (_probe_http/_probe_clamd),
диск — через _disk_free_bytes: ровно эти имена мокают тесты.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from app.config import REPO_ROOT, _packaged_data_dir, is_packaged
from app.services.health.checks import check_database
from app.services.health.registry import CheckResult, Status
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    run_local_command,
)
from app.services.stack.bootstrap import (
    CLAMAV_CONTAINER,
    CROWDSEC_CONTAINER,
    EXPECTED_CONTAINERS,
    WAZUH_CONTAINER,
    _default_data_dir,
    parse_env_file,
)

logger = logging.getLogger(__name__)

# Публичный эндпоинт отдаёт кэш не старше 30с (план-спецификация); после
# remediation-действий и «Проверить снова» кэш сбрасывается принудительно.
MATRIX_CACHE_TTL_SECONDS = 30.0

DISK_MIN_FREE_BYTES = 5 * 1024**3

_HTTP_PROBE_TIMEOUT = 3.0
_DOCKER_INFO_TIMEOUT = 10.0
_DOCKER_INSPECT_TIMEOUT = 10.0
_VERSION_TIMEOUT = 10.0

_SEVERITY: dict[str, int] = {"ok": 0, "not_configured": 1, "degraded": 1, "unreachable": 2}
_AGGREGATE_BY_SEVERITY = {0: "ok", 1: "degraded", 2: "down"}

# Коды remediation-действий (A-65-3); у здоровых компонентов action = None.
ACTION_START_DOCKER_DESKTOP = "start_docker_desktop"
ACTION_COMPOSE_UP_STACK = "compose_up_stack"
ACTION_RESTART_CONTAINER = "restart_container"

# docker inspect разом по трём контейнерам стека; отсутствующие в выводе =
# не созданы. .Name у docker начинается с "/", health может не быть.
_INSPECT_FORMAT = (
    "{{.Name}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}"
)


def _component(
    component_id: str, status: str, *, detail: str | None = None, action: str | None = None
) -> dict[str, Any]:
    return {"id": component_id, "status": status, "detail": detail, "action": action}


def worst_matrix_status(components: list[dict[str, Any]]) -> str:
    """Агрегат матрицы = худший статус компонента (см. шкалу в шапке)."""
    worst = 0
    for component in components:
        worst = max(worst, _SEVERITY[component["status"]])
    return _AGGREGATE_BY_SEVERITY[worst]


# ---------------------------------------------------------------------------
# Зонды. Каждая функция честно различает «не установлен», «не отвечает» и
# «отвечает, но не здоров»; исключения никогда не выходят наружу коллектора.
# ---------------------------------------------------------------------------


async def _check_docker_engine() -> dict[str, Any]:
    try:
        code, _stdout, _stderr = await run_local_command(
            "docker", "info", "--format", "{{.ServerVersion}}", timeout=_DOCKER_INFO_TIMEOUT
        )
    except LocalCommandNotFound:
        # Бинаря нет в PATH — действие «запустить Docker Desktop» бессмысленно.
        return _component("docker_engine", "not_configured", detail="docker_not_installed")
    except LocalCommandTimedOut:
        return _component(
            "docker_engine",
            "unreachable",
            detail="docker_info_timed_out",
            action=ACTION_START_DOCKER_DESKTOP,
        )
    if code != 0:
        # Бинарь есть, демон не отвечает — тот самый инцидент 2026-09-23.
        return _component(
            "docker_engine",
            "unreachable",
            detail="docker_daemon_unreachable",
            action=ACTION_START_DOCKER_DESKTOP,
        )
    return _component("docker_engine", "ok")


async def _inspect_containers() -> dict[str, tuple[str, str]]:
    """{имя: (state.status, health.status|'none')} — только НАЙДЕННЫЕ
    контейнеры; отсутствующий в выводе = не создан (not_configured).
    Сам вызов docker не удался (NotFound/TimedOut) = пустой словарь, что
    честно прочитается как «проверить нельзя» на фоне недоступного движка."""
    try:
        code, stdout, _stderr = await run_local_command(
            "docker",
            "inspect",
            "--format",
            _INSPECT_FORMAT,
            *EXPECTED_CONTAINERS,
            timeout=_DOCKER_INSPECT_TIMEOUT,
        )
    except (LocalCommandNotFound, LocalCommandTimedOut):
        return {}
    if code not in (0, 1):
        # 1 = «No such object» для части имён при валидном выводе остальных —
        # нормальный случай; всё остальное не парсим.
        return {}
    result: dict[str, tuple[str, str]] = {}
    for line in stdout.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        result[parts[0].lstrip("/")] = (parts[1], parts[2])
    return result


def _container_action(engine_ok: bool) -> str:
    return ACTION_RESTART_CONTAINER if engine_ok else ACTION_START_DOCKER_DESKTOP


def _check_container(
    name: str, engine_ok: bool, inspected: dict[str, tuple[str, str]]
) -> dict[str, Any]:
    if not engine_ok:
        # Движок лежит — про контейнер честно известно только то, что он
        # недостижим; чинить надо движок, а не контейнер.
        return _component(
            name,
            "unreachable",
            detail="docker_engine_unreachable",
            action=ACTION_START_DOCKER_DESKTOP,
        )
    if name not in inspected:
        return _component(
            name, "not_configured", detail="container_absent", action=ACTION_COMPOSE_UP_STACK
        )
    state, health = inspected[name]
    if state != "running":
        return _component(
            name,
            "unreachable",
            detail=f"container_{state}",
            action=ACTION_RESTART_CONTAINER,
        )
    if health == "unhealthy":
        return _component(
            name, "unreachable", detail="container_unhealthy", action=ACTION_RESTART_CONTAINER
        )
    if health == "starting":
        # start_period wazuh-manager 90с — контейнер поднимается, не «упал».
        return _component(name, "degraded", detail="healthcheck_starting")
    return _component(name, "ok")


async def _probe_http(url: str, *, timeout: float = _HTTP_PROBE_TIMEOUT) -> int:
    """GET без авторизации; ЛЮБОЙ HTTP-ответ = процесс жив (стоковый Wazuh
    API/LAPI без токена отвечают ровно 401 — это «жив», см. A-63-6).
    HTTPError (>=400) возвращается как код, остальные URLError/OSError —
    наверх, как «не отвечает»."""

    def _do() -> int:
        request = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "hranix-health"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 (localhost-URL из config.env, не пользовательский ввод)
                return response.status
        except urllib.error.HTTPError as exc:
            return exc.code

    return await asyncio.to_thread(_do)


def _http_unreachable_detail(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    if isinstance(reason, (ConnectionRefusedError, ConnectionError)):
        return "connection_refused"
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    return "probe_failed"


def _endpoint_action(engine_ok: bool) -> str:
    # Сервис лежит вместе с движком → чинить движок; движок жив → рестарт
    # контейнера — минимальное действие.
    return ACTION_RESTART_CONTAINER if engine_ok else ACTION_START_DOCKER_DESKTOP


async def _check_http_endpoint(
    component_id: str,
    url: str | None,
    *,
    configured: bool,
    engine_ok: bool,
) -> dict[str, Any]:
    if not configured:
        return _component(
            component_id,
            "not_configured",
            detail="not_configured",
            action=ACTION_COMPOSE_UP_STACK,
        )
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return _component(component_id, "unreachable", detail="bad_url")
    try:
        await _probe_http(url)
    except urllib.error.URLError as exc:
        return _component(
            component_id,
            "unreachable",
            detail=_http_unreachable_detail(exc),
            action=_endpoint_action(engine_ok),
        )
    except OSError as exc:  # socket.timeout/TimeoutError — подклассы OSError
        return _component(
            component_id,
            "unreachable",
            detail=_http_unreachable_detail(exc),
            action=_endpoint_action(engine_ok),
        )
    return _component(component_id, "ok")


async def _probe_clamd(host: str, port: int) -> None:
    from app.services.mcp.security_connectors.clamav import ClamdClient

    await ClamdClient(host=host, port=port, timeout=_HTTP_PROBE_TIMEOUT).ping()


async def _check_clamd(config_env: dict[str, str], engine_ok: bool) -> dict[str, Any]:
    # Тот же гейт «настроено», что у самого коннектора: CLAMAV_ENABLED +
    # host/port (bootstrap пишет их в config.env, см. _step_config_env).
    enabled = config_env.get("CLAMAV_ENABLED", "").strip().lower() in ("true", "1", "yes")
    host = config_env.get("CLAMAV_HOST", "").strip()
    port_raw = config_env.get("CLAMAV_PORT", "").strip()
    if not (enabled and host and port_raw.isdigit()):
        return _component(
            "clamd", "not_configured", detail="not_configured", action=ACTION_COMPOSE_UP_STACK
        )
    try:
        await _probe_clamd(host, int(port_raw))
    except Exception as exc:  # ClamdError и любые сетевые ошибки — не 500
        logger.info("health: clamd probe failed: %s", exc)
        return _component(
            "clamd",
            "unreachable",
            detail="clamd_unreachable",
            action=_endpoint_action(engine_ok),
        )
    return _component("clamd", "ok")


def _resolve_restic_command() -> str:
    from app.services.backup.restic_client import _resolve_restic

    return _resolve_restic()


def _resolve_osqueryi_command() -> str:
    from app.services.mcp.security_connectors.osquery import _resolve_osqueryi

    return _resolve_osqueryi()


async def _check_tool(
    component_id: str,
    resolve_command,
    *,
    version_args: list[str] | None = None,
) -> dict[str, Any]:
    """Присутствие и запуск вспомогательного бинаря (restic/osqueryi):
    резолв по тому же правилу, что у боевых вызовов (vendored в packaged,
    иначе PATH), затем version-проверка. Отсутствует → not_configured
    (ремедий-действия для установки бинарей в панели нет — это не «упало»,
    это «не ставили»); есть, но не исполняется → degraded.

    version_args: аргументы version-проверки. По умолчанию ["--version"]
    (осquery и большинство CLI-бинарей); restic 0.19+ использует подкоманду
    `version` без `--` — потому Args передаются вызывающим кодом."""
    try:
        argv0 = resolve_command()
    except Exception as exc:  # резолвер не должен уронить матрицу
        logger.info("health: %s resolve failed: %s", component_id, exc)
        return _component(component_id, "not_configured", detail=f"{component_id}_not_found")
    try:
        args = version_args or ["--version"]
        code, _stdout, _stderr = await run_local_command(
            argv0, *args, timeout=_VERSION_TIMEOUT
        )
    except LocalCommandNotFound:
        return _component(component_id, "not_configured", detail=f"{component_id}_not_found")
    except LocalCommandTimedOut:
        return _component(component_id, "degraded", detail=f"{component_id}_version_timed_out")
    if code != 0:
        return _component(component_id, "degraded", detail=f"{component_id}_version_failed")
    return _component(component_id, "ok")


def _disk_free_bytes(path: Path) -> int:
    anchor = path.anchor or str(path)
    return shutil.disk_usage(anchor).free


async def _check_disk() -> dict[str, Any]:
    try:
        free = await asyncio.to_thread(_disk_free_bytes, _default_data_dir())
    except OSError as exc:
        logger.info("health: disk probe failed: %s", exc)
        return _component("disk", "degraded", detail="disk_probe_failed")
    if free >= DISK_MIN_FREE_BYTES:
        return _component("disk", "ok")
    return _component("disk", "degraded", detail="disk_low_free_space")


async def _check_database_component() -> dict[str, Any]:
    """Тот же тривиальный SELECT 1, что у registry-чека database; в
    публичную матрицу попадает только код, никогда detail исключения
    (sqlite-ошибка содержит путь)."""
    try:
        result = await check_database()
    except Exception as exc:
        logger.info("health: database probe failed: %s", exc)
        return _component("database", "degraded", detail="database_unavailable")
    if result.status is Status.OK:
        return _component("database", "ok")
    return _component("database", "degraded", detail="database_unavailable")


# ---------------------------------------------------------------------------
# config.env — тот же файл и тот же парсер, что у stack bootstrap/status
# (A-60): гейт «настроено» читает ФАЙЛ, а не process-settings, поэтому
# матрица честно «оживает» сразу после compose_up_stack без перезапуска
# приложения (DoD «всё ok без перезапуска приложения»).
# ---------------------------------------------------------------------------


def _resolve_config_env_file() -> Path:
    if is_packaged():
        return _packaged_data_dir() / "config.env"
    return REPO_ROOT / ".env"


# ---------------------------------------------------------------------------
# Коллектор: кэш 30с + in-flight guard.
# ---------------------------------------------------------------------------

_cache_lock_for = threading.Lock()
_lock_by_loop: dict[int, asyncio.Lock] = {}
_cache: dict[str, Any] | None = None


def _now() -> float:
    return time.monotonic()


def _get_loop_lock() -> asyncio.Lock:
    """In-flight guard на цикл событий (см. докстринг модуля про трей/
    pytest). Словарь под threading.Lock — создание asyncio.Lock само по
    себе не требует живого цикла, привязка происходит при первом await,
    поэтому ключом служит id работающего цикла."""
    loop = asyncio.get_running_loop()
    with _cache_lock_for:
        lock = _lock_by_loop.get(id(loop))
        if lock is None:
            lock = asyncio.Lock()
            _lock_by_loop[id(loop)] = lock
        return lock


def invalidate_system_health_cache() -> None:
    """Сброс кэша матрицы — после remediation-действий и для «Проверить
    снова» (ping_components)."""
    global _cache
    _cache = None


async def collect_system_health(*, force: bool = False) -> dict[str, Any]:
    """Полная матрица `{"aggregate", "components": [...]}`; при force=True
    кэш игнорируется и пересобирается (одна пересборка на цикл — guard)."""
    global _cache
    if not force and _cache is not None and _now() - _cache["at"] < MATRIX_CACHE_TTL_SECONDS:
        return _cache["payload"]
    lock = _get_loop_lock()
    async with lock:
        if not force and _cache is not None and _now() - _cache["at"] < MATRIX_CACHE_TTL_SECONDS:
            # Пока ждали guard, сосед уже собрал свежую матрицу.
            return _cache["payload"]
        payload = await _collect_uncached()
        _cache = {"at": _now(), "payload": payload}
        return payload


async def _collect_uncached() -> dict[str, Any]:
    config_env = parse_env_file(_resolve_config_env_file())

    engine = await _check_docker_engine()
    engine_ok = engine["status"] == "ok"
    inspected = await _inspect_containers() if engine_ok else {}

    wazuh_url = (config_env.get("WAZUH_API_URL") or "").strip() or None
    crowdsec_url = (config_env.get("CROWDSEC_LAPI_URL") or "").strip() or None
    wazuh_configured = bool(
        wazuh_url and (config_env.get("WAZUH_API_PASSWORD") or "").strip()
    )
    crowdsec_configured = bool(
        crowdsec_url and (config_env.get("CROWDSEC_API_KEY") or "").strip()
    )

    components: list[dict[str, Any]] = [
        _component("server", "ok"),  # эндпоинт ответил — процесс жив
        await _check_database_component(),
        _component("event_bus", "ok"),  # жив, пока жив процесс (см. checks.py)
        engine,
    ]
    # Синхронные разборы уже сделанного inspect — без gather; сетевые/версионные
    # зонды — конкурентно (один сбор матрицы укладывается в секунды, а не в
    # сумму таймаутов).
    components.extend(
        [
            _check_container(CROWDSEC_CONTAINER, engine_ok, inspected),
            _check_container(CLAMAV_CONTAINER, engine_ok, inspected),
            _check_container(WAZUH_CONTAINER, engine_ok, inspected),
        ]
    )
    components.extend(
        await asyncio.gather(
            _check_http_endpoint(
                "wazuh_api", wazuh_url, configured=wazuh_configured, engine_ok=engine_ok
            ),
            _check_http_endpoint(
                "crowdsec_lapi", crowdsec_url, configured=crowdsec_configured, engine_ok=engine_ok
            ),
            _check_clamd(config_env, engine_ok),
            _check_tool("restic", _resolve_restic_command, version_args=["version"]),
            _check_tool("osqueryi", _resolve_osqueryi_command),
            _check_disk(),
        )
    )
    return {"aggregate": worst_matrix_status(components), "components": components}


# ---------------------------------------------------------------------------
# A-65-2: тот же коллектор как registry-чек — «честное здоровье»: агрегат
# /health/detailed (и пилюля) становится худшим ИЗ ВСЕХ компонентов машины.
# ---------------------------------------------------------------------------

_REGISTRY_STATUS_BY_AGGREGATE = {
    "ok": Status.OK,
    "degraded": Status.DEGRADED,
    "down": Status.DOWN,
}


async def check_system_stack() -> CheckResult:
    """Registry-чек «system_stack»: статус = агрегат матрицы, details
    несут полный список компонентов (коды, без секретов/путей) — тот же
    публичный payload виден и в /health/detailed."""
    payload = await collect_system_health()
    status = _REGISTRY_STATUS_BY_AGGREGATE[payload["aggregate"]]
    return CheckResult(status=status, details={"components": payload["components"]})
