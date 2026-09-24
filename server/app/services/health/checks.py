from __future__ import annotations

import logging

from sqlalchemy import text

from app.db.session import async_session_maker
from app.services.event_bus import EventBus
from app.services.health.registry import CheckResult, HealthCheck, HealthRegistry, Status

logger = logging.getLogger(__name__)


async def check_database() -> CheckResult:
    """A-2's DB is considered up iff a trivial `SELECT 1` completes over it.

    Reads `async_session_maker` from this module's own namespace at call
    time (imported here, referenced by bare name below — not read through
    `app.db.session` at call time) so a test can monkeypatch
    `app.services.health.checks.async_session_maker` to point at an isolated
    tmp DB, or at a deliberately-broken one (e.g. an engine created against a
    nonexistent directory) — same pattern already used for
    `app.services.event_bus.async_session_maker` (see conftest.py's `client`
    fixture and A-4's tests).

    A failure here (bad path, closed connection, locked file, timeout) is
    reported as DEGRADED and never raised — the DoD is explicit that a
    broken DB must show up as a degraded subsystem in `/health/detailed`,
    not a 500 (that safety net also exists one layer up, in
    `HealthRegistry._run_one`, for a check that fails in some *other* way).
    """
    try:
        async with async_session_maker() as session:
            await session.execute(text("SELECT 1"))
    except Exception as exc:
        logger.warning("health: database check failed: %s", exc)
        return CheckResult(status=Status.DEGRADED, details={"error": str(exc)})
    return CheckResult(status=Status.OK)


def _make_event_bus_check(event_bus: EventBus) -> HealthCheck:
    """The event bus subsystem check is intentionally trivial: by the time
    any request reaches `/health/detailed`, the process — and therefore the
    single `EventBus` instance living on `app.state` (see app_factory) — is
    already running. There is no separate process/connection for it to fail
    independently, unlike the DB; this only guards the wiring itself (the
    dependency actually resolved to an `EventBus` instance). Matches A-6
    spec's instruction to register it as "тривиально «жив, раз процесс жив»".
    """

    async def _check() -> CheckResult:
        if not isinstance(event_bus, EventBus):
            return CheckResult(status=Status.DOWN, details={"error": "event_bus_not_wired"})
        return CheckResult(status=Status.OK)

    return _check


def register_default_checks(registry: HealthRegistry, *, event_bus: EventBus) -> None:
    """Wires Phase 0's real subsystems onto `registry`.

    Called once per app instance from `app_factory.create_app()`, mirroring
    `event_bus.register_default_subscribers`. A-11 (CrowdSec/Osquery/Wazuh/
    ClamAV) registers its own checks the same way, elsewhere, without this
    function needing to grow a parameter for every future subsystem.
    """
    registry.register("database", check_database)
    registry.register("event_bus", _make_event_bus_check(event_bus))
    # A-65-2 («честное здоровье»): машина целиком — docker-движок, контейнеры
    # стека, wazuh_api/crowdsec_lapi/clamd, restic/osqueryi, диск — как один
    # чек. Агрегат /health/detailed (и пилюля) становится худшим ИЗ ВСЕХ
    # компонентов: инцидент 2026-09-23 («пилюля OK при лежащем Docker-стеке»)
    # больше невозможен. Опрос — тот же коллектор с кэшем 30с, что у
    # публичной /health/system, поэтому пилюля-поллинг каждые 20с не
    # устраивает шторм subprocess-ов. Отложенный импорт: system.py импортирует
    # check_database отсюда (цикл модулей, безопасный на вызове — к моменту
    # register_default_checks оба модуля уже загружены).
    from app.services.health.system import check_system_stack

    registry.register("system_stack", check_system_stack)
