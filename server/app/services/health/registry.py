from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from fastapi import Request

from app.services.event_bus import EventBus, Topic

logger = logging.getLogger(__name__)


class Status(StrEnum):
    """Health status of one subsystem.

    Ordered worst-to-best as DOWN > DEGRADED > OK (see `_SEVERITY` below) —
    that ordering drives both the aggregate status (worst of all registered
    checks, mirrors the "связка состояний" rule from the A-10 UI spec: худшее
    из инструментов) and change detection (did this subsystem's status move
    to a different rung, in either direction).
    """

    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


_SEVERITY: dict[Status, int] = {Status.OK: 0, Status.DEGRADED: 1, Status.DOWN: 2}


@dataclass(frozen=True)
class CheckResult:
    """What one health check function returns.

    `details` is free-form and merged into that subsystem's entry in the
    `/health/detailed` response (e.g. `{"error": "..."}`) — a check must
    never put a secret/token in here, this registry does not run details
    through A-5's masking filter.
    """

    status: Status
    details: dict[str, Any] = field(default_factory=dict)


HealthCheck = Callable[[], Awaitable[CheckResult]]


def worst_status(statuses: Iterable[Status]) -> Status:
    """Aggregate rule: the overall status is the worst of all given
    statuses. No statuses at all (an empty registry) aggregates to OK —
    nothing registered means nothing known to be wrong."""
    worst = Status.OK
    for status in statuses:
        if _SEVERITY[status] > _SEVERITY[worst]:
            worst = status
    return worst


class HealthRegistry:
    """Extensible registry of subsystem health checks.

    A subsystem registers once, at app-startup time, via `register(name,
    check)` — `check` is a zero-argument async callable returning a
    `CheckResult`. This registry owns:
      - calling every registered check and isolating one that raises
        (turned into a DOWN result instead of propagating — mirrors
        `EventBus.publish`'s per-handler isolation in event_bus.py, so one
        buggy check can never turn `/health/detailed` into a 500),
      - computing the worst-of-all aggregate status,
      - publishing `Topic.HEALTH_CHANGED` when a subsystem's status differs
        from what it was on this registry's *previous* `run_all()` call.

    Future tasks (A-11: CrowdSec/Osquery/Wazuh/ClamAV connectors) register
    their own checker through this same `register()` call — this file does
    not need another edit for that, the same open-ended-registry shape as
    A-5's sensitive-field patterns (see logger_config.py's module docstring)
    or A-4's topic set.

    One instance is created per `create_app()` call (see app_factory), not a
    module-level singleton — so per-subsystem "previous status" state never
    leaks between app instances / tests, same reasoning as `EventBus`.
    """

    def __init__(self) -> None:
        self._checks: dict[str, HealthCheck] = {}
        self._last_status: dict[str, Status] = {}

    def register(self, name: str, check: HealthCheck) -> None:
        self._checks[name] = check

    async def _run_one(self, name: str, check: HealthCheck) -> CheckResult:
        try:
            return await check()
        except Exception as exc:
            logger.error("health: check %r raised an exception", name, exc_info=True)
            return CheckResult(status=Status.DOWN, details={"error": str(exc)})

    async def run_all(self, *, event_bus: EventBus | None = None) -> dict[str, Any]:
        """Runs every registered check once and returns the `/health/detailed`
        body: `{"status": <aggregate>, "components": {name: {"status": ..., **details}}}`.

        When `event_bus` is given, publishes `Topic.HEALTH_CHANGED` for each
        subsystem whose status differs from its status on this registry's
        previous `run_all()` call.

        A subsystem's very first observation (no previous status on record —
        typically right after process start) establishes the baseline
        silently rather than publishing: there is nothing it *changed from*
        yet, and publishing on every fresh app start would put a same-shape
        row in `events` on every single boot, for every subsystem, forever.
        This is a judgment call — see the task report.
        """
        components: dict[str, dict[str, Any]] = {}
        statuses: list[Status] = []

        for name, check in self._checks.items():
            result = await self._run_one(name, check)
            components[name] = {"status": result.status.value, **result.details}
            statuses.append(result.status)

            previous = self._last_status.get(name)
            self._last_status[name] = result.status
            if event_bus is not None and previous is not None and previous != result.status:
                await event_bus.publish(
                    Topic.HEALTH_CHANGED,
                    {
                        "component": name,
                        "previous_status": previous.value,
                        "status": result.status.value,
                    },
                )

        return {"status": worst_status(statuses).value, "components": components}


def get_health_registry(request: Request) -> HealthRegistry:
    """FastAPI dependency: the registry instance attached to this app (see
    app_factory.create_app -> app.state.health_registry), mirrors
    event_bus.get_event_bus."""
    return request.app.state.health_registry
