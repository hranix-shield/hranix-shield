"""A-65-1: коллектор системной матрицы здоровья (services/health/system.py)
на фейковой среде. Все docker-вызовы мокаются на уровне run_local_command —
того же единого шлюза, что и у stack bootstrap (тот же приём, что
test_security_stack_bootstrap.py); HTTP/clamd-зонды и диск — на уровне
module-функций _probe_http/_probe_clamd/_disk_free_bytes.

Базовая «здоровая машина» ставится autouse-фикстурой
`_fake_system_health_environment` (tests/conftest.py); эти тесты
переопределяют её куски под сценарий и проверяют честность статусов,
action-кодов, агрегата, кэша 30с и in-flight guard (урок A-63-3).
Живая среда этой машины сознательно не используется.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import app.services.health.system as health_system_module
from app.services.health.registry import CheckResult, Status


@pytest.fixture(autouse=True)
def _healthy_database(monkeypatch: pytest.MonkeyPatch):
    """Матрица включает компонент database; в unit-тестах (без client-фикстуры
    с её перенаправлением session maker) подменяем сам чек —unit-тест не
    должен открывать реальный data/assistant.db."""

    async def _ok():
        return CheckResult(status=Status.OK)

    monkeypatch.setattr(health_system_module, "check_database", _ok)


def _override_run(
    monkeypatch: pytest.MonkeyPatch,
    *,
    responses: dict[str, tuple[int, str, str]] | None = None,
    calls: list[tuple[str, ...]] | None = None,
    default: tuple[int, str, str] = (0, "", ""),
):
    """Диспетчер по подстрокам argv поверх здорового дефолта conftest-фикстуры."""
    merged = responses or {}

    async def fake_run(*args: str, timeout: float = 5.0):
        if calls is not None:
            calls.append(args)
        joined = " ".join(args)
        for needle, response in merged.items():
            if needle in joined:
                return response
        return default

    monkeypatch.setattr(health_system_module, "run_local_command", fake_run)


def _ids(payload: dict) -> list[str]:
    return [component["id"] for component in payload["components"]]


def _by_id(payload: dict, component_id: str) -> dict:
    return next(c for c in payload["components"] if c["id"] == component_id)


# ---------------------------------------------------------------------------
# Форма и честные статусы
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_healthy_machine_returns_all_ok_in_fixed_order():
    payload = await health_system_module.collect_system_health(force=True)

    assert payload["aggregate"] == "ok"
    assert _ids(payload) == [
        "server",
        "database",
        "event_bus",
        "docker_engine",
        "hranix-crowdsec",
        "hranix-clamav",
        "hranix-wazuh-manager",
        "wazuh_api",
        "crowdsec_lapi",
        "clamd",
        "restic",
        "osqueryi",
        "disk",
    ]
    for component in payload["components"]:
        assert component == {
            "id": component["id"],
            "status": "ok",
            "detail": None,
            "action": None,
        }


@pytest.mark.unit
async def test_docker_engine_down_is_unreachable_and_aggregate_down(
    monkeypatch: pytest.MonkeyPatch,
):
    """Тот самый инцидент 2026-09-23: бинарь есть, демон не отвечает."""
    import urllib.error

    _override_run(
        monkeypatch,
        responses={"docker info": (1, "", "Cannot connect to the Docker daemon")},
    )

    async def refused(url: str, *, timeout: float = 3.0):
        raise urllib.error.URLError(ConnectionRefusedError(111))

    async def clamd_down(host: str, port: int):
        raise RuntimeError("clamd unreachable")

    monkeypatch.setattr(health_system_module, "_probe_http", refused)
    monkeypatch.setattr(health_system_module, "_probe_clamd", clamd_down)

    payload = await health_system_module.collect_system_health(force=True)

    engine = _by_id(payload, "docker_engine")
    assert engine == {
        "id": "docker_engine",
        "status": "unreachable",
        "detail": "docker_daemon_unreachable",
        "action": "start_docker_desktop",
    }
    for name in ("hranix-crowdsec", "hranix-clamav", "hranix-wazuh-manager"):
        assert _by_id(payload, name) == {
            "id": name,
            "status": "unreachable",
            "detail": "docker_engine_unreachable",
            "action": "start_docker_desktop",
        }
    # Сервисы стека сконфигурированы, но вместе с движком недостижимы —
    # действие ведёт к движку, а не к бессмысленному рестарту контейнера.
    for component_id in ("wazuh_api", "crowdsec_lapi", "clamd"):
        assert _by_id(payload, component_id)["status"] == "unreachable"
        assert _by_id(payload, component_id)["action"] == "start_docker_desktop"
    assert payload["aggregate"] == "down"


@pytest.mark.unit
async def test_docker_not_installed_is_not_configured_without_start_action(
    monkeypatch: pytest.MonkeyPatch,
):
    import app.services.mcp.security_connectors._local_command as local_command_module

    async def not_found(*args: str, timeout: float = 5.0):
        if args[0] == "docker":
            raise local_command_module.LocalCommandNotFound("'docker' is not installed")
        return (0, "fake 1.0\n", "")

    monkeypatch.setattr(health_system_module, "run_local_command", not_found)

    payload = await health_system_module.collect_system_health(force=True)

    engine = _by_id(payload, "docker_engine")
    assert engine["status"] == "not_configured"
    assert engine["detail"] == "docker_not_installed"
    # «Запустить Docker Desktop» бессмысленно, если он не установлен.
    assert engine["action"] is None
    assert _by_id(payload, "hranix-crowdsec")["status"] == "unreachable"
    # Неконтейнерные компоненты остаются честными: restic/osqueryi на этой
    # фейковой машине исполняются.
    assert _by_id(payload, "restic")["status"] == "ok"


@pytest.mark.unit
async def test_containers_absent_suggest_compose_up_and_aggregate_degraded(
    monkeypatch: pytest.MonkeyPatch,
):
    """Движок жив, но контейнеры не созданы — not_configured с честным
    действием compose_up_stack; не-сконфигурированные сервисы не роняют
    агрегат в down."""
    _override_run(
        monkeypatch,
        responses={"inspect": (1, "", "Error: No such object: hranix-crowdsec")},
    )
    # Сервисы стека ещё не настраивались (config.env пуст).
    empty_env = Path("/nonexistent/config.env")
    monkeypatch.setattr(
        health_system_module, "_resolve_config_env_file", lambda: empty_env
    )

    payload = await health_system_module.collect_system_health(force=True)

    for name in ("hranix-crowdsec", "hranix-clamav", "hranix-wazuh-manager"):
        assert _by_id(payload, name) == {
            "id": name,
            "status": "not_configured",
            "detail": "container_absent",
            "action": "compose_up_stack",
        }
    for component_id in ("wazuh_api", "crowdsec_lapi", "clamd"):
        assert _by_id(payload, component_id) == {
            "id": component_id,
            "status": "not_configured",
            "detail": "not_configured",
            "action": "compose_up_stack",
        }
    assert payload["aggregate"] == "degraded"


@pytest.mark.unit
async def test_exited_container_suggests_restart(monkeypatch: pytest.MonkeyPatch):
    _override_run(
        monkeypatch,
        responses={
            "inspect": (0, "/hranix-clamav|exited|none\n", ""),
        },
    )

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "hranix-clamav") == {
        "id": "hranix-clamav",
        "status": "unreachable",
        "detail": "container_exited",
        "action": "restart_container",
    }
    assert _by_id(payload, "hranix-crowdsec") == {
        "id": "hranix-crowdsec",
        "status": "not_configured",
        "detail": "container_absent",
        "action": "compose_up_stack",
    }
    assert payload["aggregate"] == "down"


@pytest.mark.unit
async def test_unhealthy_container_suggests_restart(monkeypatch: pytest.MonkeyPatch):
    _override_run(
        monkeypatch,
        responses={
            "inspect": (
                0,
                "/hranix-wazuh-manager|running|unhealthy\n",
                "",
            ),
        },
    )

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "hranix-wazuh-manager") == {
        "id": "hranix-wazuh-manager",
        "status": "unreachable",
        "detail": "container_unhealthy",
        "action": "restart_container",
    }
    assert payload["aggregate"] == "down"


@pytest.mark.unit
async def test_starting_healthcheck_is_degraded_not_down(monkeypatch: pytest.MonkeyPatch):
    """start_period wazuh 90с: «поднимается» — degraded, не авария."""
    _override_run(
        monkeypatch,
        responses={
            "inspect": (0, "/hranix-wazuh-manager|running|starting\n", ""),
        },
    )

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "hranix-wazuh-manager") == {
        "id": "hranix-wazuh-manager",
        "status": "degraded",
        "detail": "healthcheck_starting",
        "action": None,
    }
    # Остальные компоненты фейковой среды здоровы — degraded у wazuh
    # означает агрегат «внимание», не аварию.
    assert payload["aggregate"] == "degraded"


@pytest.mark.unit
async def test_http_endpoint_refused_while_engine_ok_suggests_restart(
    monkeypatch: pytest.MonkeyPatch,
):
    import urllib.error

    async def refused(url: str, *, timeout: float = 3.0):
        raise urllib.error.URLError(ConnectionRefusedError(111))

    monkeypatch.setattr(health_system_module, "_probe_http", refused)

    payload = await health_system_module.collect_system_health(force=True)

    wazuh_api = _by_id(payload, "wazuh_api")
    assert wazuh_api["status"] == "unreachable"
    assert wazuh_api["detail"] == "connection_refused"
    assert wazuh_api["action"] == "restart_container"


@pytest.mark.unit
async def test_broken_database_reports_code_not_exception_text(
    monkeypatch: pytest.MonkeyPatch,
):
    """Публичная матрица не должна уносить текст исключения (sqlite-ошибка
    содержит путь) — только фиксированный код."""

    async def broken():
        return CheckResult(status=Status.DEGRADED, details={"error": "sqlite3: /secret/path/db"})

    monkeypatch.setattr(health_system_module, "check_database", broken)

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "database") == {
        "id": "database",
        "status": "degraded",
        "detail": "database_unavailable",
        "action": None,
    }


@pytest.mark.unit
async def test_low_disk_space_is_degraded(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        health_system_module, "_disk_free_bytes", lambda path: 2 * 1024**3
    )

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "disk") == {
        "id": "disk",
        "status": "degraded",
        "detail": "disk_low_free_space",
        "action": None,
    }
    assert payload["aggregate"] == "degraded"


@pytest.mark.unit
async def test_missing_tools_are_not_configured(monkeypatch: pytest.MonkeyPatch):
    import app.services.mcp.security_connectors._local_command as local_command_module

    async def not_found(*args: str, timeout: float = 5.0):
        if args[0] in ("restic", "osqueryi"):
            raise local_command_module.LocalCommandNotFound(f"{args[0]!r} missing")
        return (0, "29.0.0\n", "")

    monkeypatch.setattr(health_system_module, "run_local_command", not_found)

    payload = await health_system_module.collect_system_health(force=True)

    assert _by_id(payload, "restic")["status"] == "not_configured"
    assert _by_id(payload, "restic")["detail"] == "restic_not_found"
    assert _by_id(payload, "osqueryi")["status"] == "not_configured"


@pytest.mark.unit
async def test_public_payload_never_contains_secrets_or_paths(monkeypatch: pytest.MonkeyPatch):
    """Контракт публичного эндпоинта: только статусы/коды — ни значений
    config.env, ни путей файловой системы."""
    payload = await health_system_module.collect_system_health(force=True)

    text = json.dumps(payload)
    assert "fake-bouncer-key" not in text
    assert "fake-wazuh-pass" not in text
    assert "127.0.0.1" not in text


# ---------------------------------------------------------------------------
# Кэш 30с и in-flight guard (урок A-63-3)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_cache_reuses_payload_until_ttl_or_invalidation(
    monkeypatch: pytest.MonkeyPatch,
):
    calls: list[tuple[str, ...]] = []
    _override_run(monkeypatch, calls=calls)

    clock = {"value": 0.0}
    monkeypatch.setattr(health_system_module, "_now", lambda: clock["value"])
    health_system_module.invalidate_system_health_cache()

    first = await health_system_module.collect_system_health()
    second = await health_system_module.collect_system_health()
    assert first is second  # кэш отдаёт тот же payload без пересбора
    docker_info_calls = [c for c in calls if "info" in " ".join(c)]
    assert len(docker_info_calls) == 1

    clock["value"] = health_system_module.MATRIX_CACHE_TTL_SECONDS + 1
    await health_system_module.collect_system_health()
    assert len([c for c in calls if "info" in " ".join(c)]) == 2

    health_system_module.invalidate_system_health_cache()
    await health_system_module.collect_system_health()
    assert len([c for c in calls if "info" in " ".join(c)]) == 3


@pytest.mark.unit
async def test_in_flight_guard_coalesces_concurrent_collections(
    monkeypatch: pytest.MonkeyPatch,
):
    """Одновременные вызовы (пилюля + форма входа + «Проверить снова») —
    один сбор, остальные ждут его результат, а не дублируют subprocess-ы."""
    calls: list[tuple[str, ...]] = []
    release = asyncio.Event()

    async def slow_fake_run(*args: str, timeout: float = 5.0):
        calls.append(args)
        if "info" in " ".join(args):
            await release.wait()
            return (0, "29.0.0\n", "")
        if "inspect" in " ".join(args):
            return (
                0,
                "/hranix-crowdsec|running|none\n"
                "/hranix-clamav|running|none\n"
                "/hranix-wazuh-manager|running|healthy\n",
                "",
            )
        if "--version" in args:
            return (0, "fake 1.0\n", "")
        return (0, "", "")

    async def slow_probe(url: str, *, timeout: float = 3.0):
        await release.wait()
        return 401

    async def slow_clamd(host: str, port: int):
        await release.wait()
        return None

    monkeypatch.setattr(health_system_module, "run_local_command", slow_fake_run)
    monkeypatch.setattr(health_system_module, "_probe_http", slow_probe)
    monkeypatch.setattr(health_system_module, "_probe_clamd", slow_clamd)
    health_system_module.invalidate_system_health_cache()

    async def _release_later():
        await asyncio.sleep(0.05)
        release.set()

    results, _ = await asyncio.gather(
        asyncio.gather(*[health_system_module.collect_system_health() for _ in range(5)]),
        _release_later(),
    )

    # docker info мог бы вызваться 5 раз без guard — с guard ровно 1.
    assert len([c for c in calls if "info" in " ".join(c)]) == 1
    assert {payload["aggregate"] for payload in results} == {"ok"}
