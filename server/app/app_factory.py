from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.infra.logger_config import configure_logging
from app.routers import auth, diagnostics, health, notifications, security_console
from app.services.auth import ensure_bootstrap_admin
from app.services.backup import create_default_scheduler, run_startup_integrity_check
from app.services.event_bus import EventBus, register_default_subscribers
from app.services.health import HealthRegistry, register_default_checks
from app.services.mcp import MCPRegistry
from app.services.mcp.security_connectors import register_default_security_connectors
from app.services.notifications import (
    NotificationRegistry,
    NotificationService,
    TrustedContactRegistry,
    create_default_escalation_scheduler,
    register_default_notification_subscribers,
    register_default_topics,
)
from app.services.mcp.security_connectors.clamav import ClamAvScanJobRegistry
from app.services.security_console import SecurityConsoleRegistry

# Panel static assets (A-10): HTML/CSS/JS live under app/static/ — inside the
# `app` package, next to routers/services/db, so they ship with the app
# package itself (not a separate top-level server/static/ that a packaging
# step could forget to include).
#
# Mounted under /panel, deliberately NOT at "/": a Mount is a prefix match
# that swallows every path under it, and several existing tests (e.g.
# test_role_below_required_is_403 in test_auth_router.py) add throwaway
# routes to the app *after* create_app() returns via `app.add_api_route(...)`.
# Starlette matches routes in list order, and a route appended after the
# fact always lands after a Mount("/", ...) registered inside create_app() —
# so a root-mounted StaticFiles would silently 404 every such route instead
# of ever reaching it (found by running the full suite after wiring this in,
# see A-10 task report). A dedicated "/panel" prefix leaves "/" and every
# other path free for exactly this kind of dynamic route registration.
STATIC_DIR = Path(__file__).resolve().parent / "static"


class _NoCacheStaticFiles(StaticFiles):
    """Found live 2026-07-16: Starlette's default `StaticFiles` lets browsers
    cache `app.js`/`index.html` aggressively with no explicit `Cache-Control`
    header, relying only on ETag for revalidation — which several real
    browsers/back-forward-cache paths skip for a long time after a page has
    already been loaded once. Result: after redeploying a real bugfix
    (A-15..A-18's `connectors`-field rendering fix), a tab left open from
    before the redeploy kept showing the OLD `app.js`'s behaviour for hours,
    reading as "the fix didn't work" when the server was actually already
    serving the fixed file the whole time — confirmed by fetching the same
    URL fresh (curl, and a brand-new Playwright browser context) and getting
    the correct, fixed behaviour immediately.

    `no-cache` (not `no-store`): the browser must revalidate with the server
    before reusing a cached copy, not "never cache" — an unchanged file still
    gets a fast `304 Not Modified` off the existing ETag, only a *changed*
    file (new deploy) is guaranteed to be re-fetched instead of silently
    reused. Applies to the whole `/panel` static mount — this is a local,
    single-user panel, not a CDN-fronted site serving many users, so the
    extra revalidation round-trip costs nothing worth optimizing away here.
    """

    def file_response(self, *args, **kwargs):  # type: ignore[override]
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # A-12: backup integrity-check/auto-restore runs BEFORE ensure_bootstrap_admin
    # — found the hard way, live: ensure_bootstrap_admin's very first
    # action is `SELECT count(*) FROM users`, which raises immediately
    # (OperationalError: no such table) against a missing or corrupted DB
    # file, crashing the whole lifespan before this task's own restore
    # logic ever got a chance to run. A restic restore brings back the
    # FULL previously-migrated file (schema and all — restic doesn't know
    # or care about SQL, it restores exact bytes), so running it first
    # means ensure_bootstrap_admin sees a normal, already-populated `users`
    # table afterward, exactly as if nothing had ever gone wrong. Both the
    # integrity-check/auto-restore and the daily scheduler are gated behind
    # one flag, `backup_enabled` (default False, same "safe default,
    # explicit opt-in" reasoning as A-7's ai_enabled) — see
    # Settings.backup_enabled's docstring: with it unset, this whole block
    # is a complete no-op, so every existing lifespan test (e.g.
    # test_auth_startup.py, written before A-12 existed) keeps behaving
    # exactly as before, untouched.
    settings = get_settings()
    scheduler = None
    if settings.backup_enabled:
        await run_startup_integrity_check(event_bus=app.state.event_bus, settings=settings)
        scheduler = create_default_scheduler(event_bus=app.state.event_bus, settings=settings)
        if scheduler is not None:
            scheduler.start()
    app.state.backup_scheduler = scheduler

    # A-13: the escalation sweep (services/notifications/escalation.py) is
    # NOT gated behind a settings flag the way backup_enabled/ai_enabled
    # are: unlike those, it has no externally-visible side effect until a
    # critical notification actually goes unacknowledged past the
    # configured window, and even then the only "action" Phase 0 takes is a
    # clearly-logged channel-6 no-op (see escalate_to_channel_6) — nothing
    # it does can surprise an operator who never configured SMTP/contacts.
    # Always sleeps before its first tick (see EscalationScheduler's
    # docstring), so short-lived lifespans in tests that don't monkeypatch
    # app.services.notifications.escalation.async_session_maker (most of
    # them — only tests that exercise this scheduler directly need to)
    # never reach a DB query before being cancelled at shutdown.
    escalation_scheduler = create_default_escalation_scheduler(
        trusted_contacts=app.state.trusted_contact_registry, settings=settings
    )
    escalation_scheduler.start()
    app.state.notification_escalation_scheduler = escalation_scheduler

    await ensure_bootstrap_admin()

    yield

    if scheduler is not None:
        await scheduler.stop()
    await escalation_scheduler.stop()


def create_app() -> FastAPI:
    settings = get_settings()

    # First thing, before anything else can log: every logger obtained via
    # `logging.getLogger(__name__)` anywhere under app/ (routers, services,
    # including A-4's event_bus.py) propagates to the root logger, so this
    # single call is what makes every log line in the process go through
    # A-5's masking + JSON formatting.
    configure_logging(settings)

    app = FastAPI(title="Hranix Shield", lifespan=_lifespan)

    # A fresh bus per app instance (not a module-level singleton) so tests
    # creating multiple `create_app()` instances never leak subscriptions
    # between each other.
    app.state.event_bus = EventBus()
    register_default_subscribers(app.state.event_bus)

    # Same per-instance-not-singleton reasoning as the event bus above: a
    # fresh HealthRegistry per create_app() call, so no subsystem's
    # "previous status" (used for HEALTH_CHANGED change detection) leaks
    # between app instances / tests.
    app.state.health_registry = HealthRegistry()
    register_default_checks(app.state.health_registry, event_bus=app.state.event_bus)

    # Same reasoning again: a fresh SecurityConsoleRegistry per create_app()
    # call, so one test's console toggles never leak into the next test's
    # (or the next app instance's) state (see services/security_console.py).
    app.state.security_console_registry = SecurityConsoleRegistry()

    # A-17: same non-singleton reasoning again — a fresh scan-job registry
    # per create_app() call, so one test's/one process's quick/full-scan
    # history never leaks into another's (see
    # services/mcp/security_connectors/clamav.py's ClamAvScanJobRegistry).
    app.state.clamav_scan_job_registry = ClamAvScanJobRegistry()

    # A-11: a fresh MCPRegistry per create_app() call, same non-singleton
    # reasoning as every registry above. Unlike A-9's original "laid down,
    # zero connectors" abstraction (see registry.py's docstring), this now
    # gets one real entry at startup: CrowdSec (Osquery/Wazuh/ClamAV are out
    # of scope for A-11, see task brief).
    app.state.mcp_registry = MCPRegistry()
    register_default_security_connectors(app.state.mcp_registry, settings=settings)

    # A-13: same non-singleton reasoning — a fresh NotificationRegistry
    # (topic x channel matrix) and TrustedContactRegistry per create_app()
    # call. The matrix is wired with Phase 0's 3 known topics immediately
    # (not only inside _lifespan) so it is ready before the first request,
    # same as health_registry/security_console_registry above.
    app.state.notification_registry = NotificationRegistry()
    register_default_topics(app.state.notification_registry)

    app.state.trusted_contact_registry = TrustedContactRegistry(
        seed_emails=settings.trusted_contact_emails_list
    )

    # The NotificationService instance itself lives only as an event-bus
    # subscriber (register_default_notification_subscribers below) — unlike
    # the registries above, no router needs to reach this object directly,
    # so it is not stored on app.state.
    notification_service = NotificationService(
        registry=app.state.notification_registry,
        trusted_contacts=app.state.trusted_contact_registry,
    )
    register_default_notification_subscribers(app.state.event_bus, notification_service)

    # A-12: set eagerly (not only inside _lifespan) so `app.state.backup_scheduler`
    # is always a valid attribute — None until/unless the lifespan actually
    # starts one — for any test or introspection that inspects it without
    # running the lifespan (mirrors the other app.state.* attributes above,
    # all set here rather than only in _lifespan).
    app.state.backup_scheduler = None
    # A-13: same reasoning as backup_scheduler above — always a valid
    # attribute, None until the lifespan actually starts the escalation
    # sweep (see _lifespan).
    app.state.notification_escalation_scheduler = None

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(security_console.router)
    app.include_router(notifications.router)
    app.include_router(diagnostics.router)

    if STATIC_DIR.is_dir():
        app.mount("/panel", _NoCacheStaticFiles(directory=STATIC_DIR, html=True), name="panel")

        @app.get("/", include_in_schema=False)
        async def _panel_redirect() -> RedirectResponse:
            return RedirectResponse(url="/panel/")

    return app
