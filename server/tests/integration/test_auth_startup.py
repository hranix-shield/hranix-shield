import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.auth as auth_service
from app.app_factory import create_app
from app.config import Settings
from app.db.models import User
from tests.common.factories import create_user


@pytest.mark.integration
async def test_lifespan_bootstraps_admin_when_users_table_empty(
    monkeypatch: pytest.MonkeyPatch,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """Exercises the real app_factory lifespan wiring (create_app -> startup ->
    ensure_bootstrap_admin), not just the service function in isolation.

    Both `async_session_maker` and `get_settings` used *inside*
    app.services.auth are monkeypatched to point at this test's isolated,
    migrated tmp DB — never the real data/assistant.db — so this is safe to
    run regardless of the developer's real environment variables.
    """
    settings = Settings(
        _env_file=None,
        bootstrap_admin_username="test-admin",
        bootstrap_admin_password="test-admin-password",
    )
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "async_session_maker", migrated_session_maker)

    app = create_app()
    with TestClient(app):
        pass

    async with migrated_session_maker() as session:
        user = await session.scalar(select(User).where(User.username == "test-admin"))

    assert user is not None
    assert user.role == "admin"


@pytest.mark.integration
async def test_lifespan_skips_bootstrap_when_credentials_unset(
    monkeypatch: pytest.MonkeyPatch,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    settings = Settings(_env_file=None, bootstrap_admin_username=None, bootstrap_admin_password=None)
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "async_session_maker", migrated_session_maker)

    app = create_app()
    with TestClient(app):
        pass

    async with migrated_session_maker() as session:
        any_user = await session.scalar(select(User))

    assert any_user is None


@pytest.mark.integration
async def test_bootstrap_skipped_when_a_user_already_exists(
    monkeypatch: pytest.MonkeyPatch,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    await create_user(migrated_session_maker, username="existing", password="pw", role="viewer")

    settings = Settings(
        _env_file=None,
        bootstrap_admin_username="test-admin",
        bootstrap_admin_password="test-admin-password",
    )
    monkeypatch.setattr(auth_service, "get_settings", lambda: settings)
    monkeypatch.setattr(auth_service, "async_session_maker", migrated_session_maker)

    app = create_app()
    with TestClient(app):
        pass

    async with migrated_session_maker() as session:
        bootstrap_admin = await session.scalar(
            select(User).where(User.username == "test-admin")
        )

    assert bootstrap_admin is None
