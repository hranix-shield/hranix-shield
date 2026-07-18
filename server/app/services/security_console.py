from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum

from fastapi import Request

from app.services.mcp.security_connectors.clamav import ClamAvScanJobRegistry


class ConsoleStatus(StrEnum):
    """Status of one security console.

    Sibling concept to `app/services/health/registry.py`'s `Status` — same
    OK < DEGRADED < DOWN severity ordering and worst-of-all aggregation idea,
    deliberately NOT the same class: `HealthRegistry` aggregates *application
    subsystems* (DB, event bus, ...), this aggregates *security tools/
    consoles* (CrowdSec, ClamAV, ...) — a different domain that happens to
    need the same shape (see A-10 spec: "не переиспользуй HealthRegistry
    буквально, просто ту же идею агрегации").
    """

    OK = "ok"
    DEGRADED = "degraded"
    DOWN = "down"


_SEVERITY: dict[ConsoleStatus, int] = {
    ConsoleStatus.OK: 0,
    ConsoleStatus.DEGRADED: 1,
    ConsoleStatus.DOWN: 2,
}


def worst_console_status(statuses: Iterable[ConsoleStatus]) -> ConsoleStatus:
    """Aggregate rule: the overall status is the worst of all given
    statuses. No statuses at all aggregates to OK — mirrors
    `health.registry.worst_status`."""
    worst = ConsoleStatus.OK
    for status in statuses:
        if _SEVERITY[status] > _SEVERITY[worst]:
            worst = status
    return worst


class ConsoleId(StrEnum):
    """The 6 security consoles, §6.2 of the analytical plan, display order."""

    PERIMETER = "perimeter"
    IDS = "ids"
    AV = "av"
    NETWORK = "network"
    BACKUP = "backup"
    LOGS = "logs"


CONSOLE_IDS: tuple[str, ...] = tuple(console_id.value for console_id in ConsoleId)


class SecurityConsoleRegistry:
    """Per-console enabled/disabled toggle state (A-10 requirement #4: "Тумблер
    вкл/выкл на консоль").

    Judgment call (Phase 0): kept in-process memory, not a DB table/model.
    A-11 (real CrowdSec/Osquery/Wazuh/ClamAV integration) does not exist yet
    for this toggle to actually arm/disarm anything, and the DoD only asks
    that the state survive "between requests in the life of the process" —
    a persisted settings model is more naturally scoped to A-11 (when a real
    per-console settings row can store toggle + thresholds + schedules
    together) or A-14. Restarting the server resets every console back to
    enabled; this is an accepted, documented limitation of this phase, not
    an oversight — flagged again in the task report as a candidate follow-up.

    A disabled console reports `ConsoleStatus.DEGRADED`, not `DOWN`:
    switching a protection tool off is a real posture gap the aggregate
    shield should reflect, but the tool itself has not failed/errored. This
    toggle doubles as the only way, in Phase 0 (no real integrations yet
    that could organically go degraded), to demonstrate the "связка
    состояний" (worst-of-all aggregation) end-to-end — see A-10 DoD.

    One instance per `create_app()` call (attached at
    `app.state.security_console_registry`), same non-singleton reasoning as
    `EventBus`/`HealthRegistry`: no state leaks between app instances/tests.
    """

    def __init__(self) -> None:
        self._enabled: dict[str, bool] = {console_id: True for console_id in CONSOLE_IDS}

    def is_enabled(self, console_id: str) -> bool:
        return self._enabled.get(console_id, True)

    def set_enabled(self, console_id: str, enabled: bool) -> None:
        self._enabled[console_id] = enabled

    def status_for(self, console_id: str) -> ConsoleStatus:
        return ConsoleStatus.OK if self.is_enabled(console_id) else ConsoleStatus.DEGRADED

    def snapshot(self) -> dict[str, dict[str, object]]:
        """`{console_id: {"status": ..., "enabled": ...}}` for every known console."""
        return {
            console_id: {
                "status": self.status_for(console_id).value,
                "enabled": self.is_enabled(console_id),
            }
            for console_id in CONSOLE_IDS
        }

    def aggregate_status(self) -> ConsoleStatus:
        return worst_console_status(
            ConsoleStatus(entry["status"]) for entry in self.snapshot().values()
        )


def get_security_console_registry(request: Request) -> SecurityConsoleRegistry:
    """FastAPI dependency: the registry instance attached to this app (see
    app_factory.create_app -> app.state.security_console_registry), mirrors
    health.registry.get_health_registry."""
    return request.app.state.security_console_registry


def get_clamav_scan_job_registry(request: Request) -> ClamAvScanJobRegistry:
    """FastAPI dependency: the A-17 scan-job registry instance attached to
    this app (see app_factory.create_app -> app.state.clamav_scan_job_registry),
    same mirror-of-get_health_registry shape as
    `get_security_console_registry` above."""
    return request.app.state.clamav_scan_job_registry
