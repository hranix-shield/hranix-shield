import asyncio
import os
from collections.abc import AsyncGenerator, Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Must run before the first `app.*` import below: app.db.session builds its
# module-level engine at import time via get_settings(), and get_settings()
# is process-wide cached (lru_cache) for the rest of the test session. Pinning
# JWT_SECRET here keeps the whole suite on the "explicit secret configured"
# path — matching a correctly configured deployment — and off the
# auto-generate-and-persist-to-disk fallback, so tests never write to the
# real data/.jwt_secret. That fallback path is tested in isolation, with an
# explicit tmp secret_file, in tests/unit/test_auth_service.py.
os.environ.setdefault("JWT_SECRET", "test-suite-fixed-secret-do-not-use-outside-tests")

# Found live 2026-07-16: Settings.model_config points env_file at the real
# REPO_ROOT/.env (see app/config.py) — pydantic-settings only falls back to
# that file for a var with no real process env var already set, same
# precedence JWT_SECRET above already relies on. A real deployment's .env
# legitimately ends up with real CROWDSEC_API_KEY/CLAMAV_ENABLED/
# WAZUH_API_PASSWORD values once an operator wires up those companion
# services (see infra/security/*/docker-compose.yml) — and once it does,
# every "unconfigured by default" test for those three connectors
# (test_security_console_ids_crowdsec.py, test_security_console_perimeter.py,
# test_a11_crowdsec_regression.py, and the ClamAV/Wazuh equivalents) starts
# failing, not because of a code regression but because the test process
# picked up the real repo's real .env. Confirmed to actually happen: adding
# a real bouncer key to this repo's own .env for live Docker verification
# broke exactly those three tests on the next `pytest` run. Same "shared
# mutable state leaking into tests" bug family as A-4's alembic loggers/
# A-12's restic password file/A-13's notifications DB — pinned here the
# same way, once, rather than re-discovered per connector.
os.environ.setdefault("CROWDSEC_API_KEY", "")
os.environ.setdefault("CLAMAV_ENABLED", "False")
os.environ.setdefault("WAZUH_API_PASSWORD", "")
# A-60: the same reasoning, one generation later — the stack bootstrap
# (services/stack/bootstrap.py) legitimately writes CROWDSEC_MACHINE_ID/
# CROWDSEC_MACHINE_PASSWORD/WAZUH_API_URL into the real deployment .env once
# the operator runs it, and every "not_configured by default" CrowdSec test
# (ban/unban, ids console, A-11 regression) would then see a configured
# machine credential and fail — the same shared-mutable-.env leak the three
# pins above already document. Pinned the same way, once.
os.environ.setdefault("CROWDSEC_MACHINE_ID", "")
os.environ.setdefault("CROWDSEC_MACHINE_PASSWORD", "")
os.environ.setdefault("WAZUH_API_URL", "")

import app.services.backup.service as backup_service_module  # noqa: E402
import app.services.event_bus as event_bus_module  # noqa: E402
import app.services.health.checks as health_checks_module  # noqa: E402
import app.services.mcp.security_connectors.clamav as clamav_module  # noqa: E402
import app.services.notifications.service as notifications_service_module  # noqa: E402
from app.app_factory import create_app  # noqa: E402
from app.db.session import get_session  # noqa: E402

SERVER_DIR = Path(__file__).resolve().parents[1]
ALEMBIC_INI = SERVER_DIR / "alembic.ini"


@pytest.fixture(autouse=True)
def _isolate_restic_password_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Blanket safety net for every test in the suite (A-12), same spirit
    as pinning JWT_SECRET above: `services.backup.service.resolve_backup_password_file`
    always writes a password FILE to disk — even when `Settings.restic_password`
    is already set explicitly — because restic needs a real `--password-file`,
    unlike `resolve_jwt_secret` which can just return the secret string
    in-process. Without this, ANY test that reaches
    `services/backup/wiring.py.resolve_backup_paths()` — even one that
    never sets `restic_password` itself, e.g. a test only checking the
    "no SQLite database configured" branch — writes into this repo's real
    `data/.restic_password`. Confirmed to actually happen while developing
    this task's own test suite (caught via `git status`/`ls data/` before
    the live DoD run, see the A-12 task report) before this fixture
    existed. Autouse, so no individual test file has to remember to opt in.
    """
    monkeypatch.setattr(
        backup_service_module, "RESTIC_PASSWORD_FILE", tmp_path / ".restic_password_autouse"
    )


def _alembic_config_for(db_path: Path) -> Config:
    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return alembic_cfg


@pytest.fixture
def migrated_session_maker(tmp_path: Path) -> Iterator[async_sessionmaker[AsyncSession]]:
    """A fresh, migrated SQLite DB per test — isolated from the real data/assistant.db."""
    db_path = tmp_path / "test_auth.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    maker = async_sessionmaker(engine, expire_on_commit=False)
    try:
        yield maker
    finally:
        asyncio.run(engine.dispose())


@pytest.fixture
def client(
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[TestClient]:
    """App wired to the isolated test DB via dependency override.

    Deliberately NOT used as a `with` context manager: that would run the
    app's lifespan (`ensure_bootstrap_admin`) against the *real* global
    session maker/settings, not this test DB. See test_auth_startup.py for a
    dedicated, explicitly-isolated test of the lifespan wiring itself.

    `app.services.event_bus.async_session_maker` is also redirected here
    (A-4): `create_app()` always wires the default events-table subscriber
    onto `app.state.event_bus` regardless of lifespan (see app_factory), so
    any route that publishes to the bus — e.g. /auth/login's brute-force
    lock -> `security.alert` — would otherwise write into the *real*
    data/assistant.db during tests instead of this isolated one.

    `app.services.health.checks.async_session_maker` is redirected the same
    way (A-6): the "database" health check reads that module-level name at
    call time (see checks.py), independent of the `get_session` FastAPI
    dependency override above, so without this it would probe the *real*
    data/assistant.db instead of this isolated one whenever a test hits
    `/health/detailed`.

    `app.services.notifications.service.async_session_maker` is redirected
    the same way (A-13): `create_app()` always wires `NotificationService`
    as a subscriber on every topic (see
    services.notifications.register_default_notification_subscribers), so
    any event publish reachable through this client — not just
    /auth/login's brute-force lock, ANY of the 3 known topics — would
    otherwise have this subscriber try to write into the *real*
    data/assistant.db. Confirmed to actually happen while developing this
    task's own test suite (EventBus.publish's per-handler isolation, see
    event_bus.py, caught the resulting "no such table: notifications"
    error and logged it rather than failing the request — so tests kept
    passing while quietly attempting real writes; caught via
    logs/assistant.log before the live DoD run, same class of bug as A-12's
    restic-password-file leak this file already documents above).

    `app.services.mcp.security_connectors.clamav.async_session_maker` is
    redirected the same way (A-33): `start_full_scan`'s background job
    (`_run_full_scan_job`) opens its own session via that module-level name
    to record a `scan_history` row on completion, independent of the
    `get_session` FastAPI dependency override above — without this, a test
    that let a real full scan job actually complete would write into the
    real data/assistant.db instead of this isolated one.
    """
    monkeypatch.setattr(event_bus_module, "async_session_maker", migrated_session_maker)
    monkeypatch.setattr(health_checks_module, "async_session_maker", migrated_session_maker)
    monkeypatch.setattr(notifications_service_module, "async_session_maker", migrated_session_maker)
    monkeypatch.setattr(clamav_module, "async_session_maker", migrated_session_maker)

    app = create_app()

    async def _override_get_session() -> AsyncGenerator[AsyncSession, None]:
        async with migrated_session_maker() as session:
            yield session

    app.dependency_overrides[get_session] = _override_get_session

    yield TestClient(app)
