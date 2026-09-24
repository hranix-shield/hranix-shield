from enum import Enum
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import require_role
from app.services.event_bus import EventBus, get_event_bus
from app.services.health import HealthRegistry, get_health_registry
from app.services.health.remediation import (
    compose_up_stack,
    ping_components,
    restart_container,
    start_docker_desktop,
)
from app.services.health.system import collect_system_health

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/health/detailed")
async def health_detailed(
    registry: HealthRegistry = Depends(get_health_registry),
    bus: EventBus = Depends(get_event_bus),
) -> dict[str, Any]:
    return await registry.run_all(event_bus=bus)


# A-65-1: публичная матрица всех компонентов машины (уровень 1 реанимации —
# полоса статуса на форме входа). Намеренно БЕЗ auth: только статусы, коды
# причин и коды действий — ни секретов, ни путей (см. system.py); кэш 30с
# внутри коллектора. Remediation-действия к этой матрице — отдельно и
# admin-only (POST /health/system/actions/{id}, A-65-3).
@router.get("/health/system")
async def health_system() -> dict[str, Any]:
    return await collect_system_health()


# ---------------------------------------------------------------------------
# A-65-3: remediation-действия над компонентами матрицы. Как POST
# /security/stack/bootstrap (A-60) — admin-only: поднятие/рестарт контейнеров
# и запуск Docker Desktop это write-операции уровня оператора. Ответы —
# машиночитаемые коды; HTTP-код отличает только «неправильный запрос»
# (400/404) от честного статуса действия (200 с {"status": "error", ...}) —
# «Docker не установлен» это статус, а не ошибка HTTP.
# ---------------------------------------------------------------------------


class RemediationActionId(str, Enum):
    restart_container = "restart_container"
    compose_up_stack = "compose_up_stack"
    start_docker_desktop = "start_docker_desktop"
    ping_components = "ping_components"


class RestartContainerBody(BaseModel):
    # name опционален на уровне модели: у маршрута ОДНО тело на все четыре
    # действия, и UI шлёт "{}" для не-restarter'ов — обязательное поле дало
    # бы 422 на них всех (найдено живым прогоном A-65). Требование имени
    # проверяется только в ветке restart_container ниже.
    name: str | None = None


@router.post("/health/system/actions/{action_id}")
async def health_system_action(
    action_id: RemediationActionId,
    body: RestartContainerBody | None = None,
    _user: Any = Depends(require_role("admin")),
) -> dict[str, Any]:
    if action_id is RemediationActionId.restart_container:
        if body is None or not (body.name or "").strip():
            raise HTTPException(
                status_code=400, detail={"error": "container_name_required"}
            )
        result = await restart_container(body.name.strip())
        if result["detail"] == "unknown_container":
            raise HTTPException(status_code=404, detail={"error": "unknown_container"})
        return result
    if action_id is RemediationActionId.compose_up_stack:
        return await compose_up_stack()
    if action_id is RemediationActionId.start_docker_desktop:
        return await start_docker_desktop()
    return await ping_components()
