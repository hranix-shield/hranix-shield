import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import User
from app.dependencies import require_role
from app.services.auth import MAX_FAILED_LOGIN_ATTEMPTS
from tests.common.factories import create_user


@pytest.mark.integration
def test_me_without_token_is_401(client: TestClient):
    response = client.get("/auth/me")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
def test_me_with_garbage_token_is_401_invalid_token(client: TestClient):
    response = client.get("/auth/me", headers={"Authorization": "Bearer not-a-real-jwt"})

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "invalid_token"}


@pytest.mark.integration
async def test_me_with_valid_token_for_deactivated_user_is_401_invalid_token(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A token issued before the account was deactivated must stop working.

    Reuses the merged "invalid_token" code (see server/app/dependencies.py)
    rather than a separate "account_inactive" code — see A-3 error-code
    revision notes for the reasoning.
    """
    await create_user(migrated_session_maker, username="frank", password="pw", role="viewer")
    token = client.post(
        "/auth/login", json={"username": "frank", "password": "pw"}
    ).json()["access_token"]

    async with migrated_session_maker() as session:
        await session.execute(
            update(User).where(User.username == "frank").values(is_active=False)
        )
        await session.commit()

    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "invalid_token"}


@pytest.mark.integration
async def test_login_with_correct_credentials_returns_jwt_and_me_works(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(
        migrated_session_maker, username="admin", password="correct-horse", role="admin"
    )

    login_response = client.post(
        "/auth/login", json={"username": "admin", "password": "correct-horse"}
    )
    assert login_response.status_code == 200
    token = login_response.json()["access_token"]
    assert token

    me_response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_response.status_code == 200
    body = me_response.json()
    assert body["username"] == "admin"
    assert body["role"] == "admin"
    assert "hashed_password" not in body


@pytest.mark.integration
async def test_login_with_wrong_password_is_401(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="bob", password="right-pass")

    response = client.post("/auth/login", json={"username": "bob", "password": "wrong-pass"})

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "invalid_credentials"}


@pytest.mark.integration
def test_login_with_unknown_username_is_401_same_code_as_wrong_password(client: TestClient):
    """Must return the exact same "invalid_credentials" code as a wrong
    password (test_login_with_wrong_password_is_401 above) — an attacker
    must not be able to tell "no such user" apart from "wrong password".
    """
    response = client.post(
        "/auth/login", json={"username": "no-such-user", "password": "whatever"}
    )

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "invalid_credentials"}


@pytest.mark.integration
async def test_brute_force_lock_rejects_correct_password_once_locked(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="carol", password="right-pass")

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        response = client.post(
            "/auth/login", json={"username": "carol", "password": "wrong-pass"}
        )
        assert response.status_code == 401
        assert response.json()["detail"] == {"error": "invalid_credentials"}

    # N+1th attempt, this time with the CORRECT password — must still be rejected,
    # and now with the distinct "account_locked" code (not "invalid_credentials"),
    # since the account-lock check runs before password verification.
    locked_response = client.post(
        "/auth/login", json={"username": "carol", "password": "right-pass"}
    )

    assert locked_response.status_code == 401
    assert locked_response.json()["detail"] == {"error": "account_locked"}


@pytest.mark.integration
async def test_refresh_reissues_token(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(migrated_session_maker, username="dave", password="right-pass")

    login_response = client.post(
        "/auth/login", json={"username": "dave", "password": "right-pass"}
    )
    token = login_response.json()["access_token"]

    refresh_response = client.post(
        "/auth/refresh", headers={"Authorization": f"Bearer {token}"}
    )

    assert refresh_response.status_code == 200
    assert refresh_response.json()["access_token"]


@pytest.mark.integration
async def test_refresh_without_token_is_401(client: TestClient):
    response = client.post("/auth/refresh")

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_role_below_required_is_403(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """Wires require_role("admin") onto a throwaway route on the *real* app
    under test, so the full get_current_user -> require_role chain is
    exercised through actual HTTP request handling — not just a bare
    function call (see tests/unit/test_dependencies.py for that).
    """
    async def admin_only(user: User = Depends(require_role("admin"))) -> dict[str, bool]:
        return {"ok": True}

    client.app.add_api_route("/test/admin-only", admin_only, methods=["GET"])

    await create_user(migrated_session_maker, username="eve_admin", password="pw", role="admin")
    await create_user(
        migrated_session_maker, username="eve_viewer", password="pw", role="viewer"
    )

    admin_token = client.post(
        "/auth/login", json={"username": "eve_admin", "password": "pw"}
    ).json()["access_token"]
    viewer_token = client.post(
        "/auth/login", json={"username": "eve_viewer", "password": "pw"}
    ).json()["access_token"]

    admin_response = client.get(
        "/test/admin-only", headers={"Authorization": f"Bearer {admin_token}"}
    )
    viewer_response = client.get(
        "/test/admin-only", headers={"Authorization": f"Bearer {viewer_token}"}
    )

    assert admin_response.status_code == 200
    assert viewer_response.status_code == 403
    assert viewer_response.json()["detail"] == {"error": "insufficient_role"}
