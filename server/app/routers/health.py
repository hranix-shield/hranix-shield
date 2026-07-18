from typing import Any

from fastapi import APIRouter, Depends

from app.services.event_bus import EventBus, get_event_bus
from app.services.health import HealthRegistry, get_health_registry

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
