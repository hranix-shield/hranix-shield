"""A-3 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task from A-2 on adds
at least one regression test that must stay green through the rest of Phase 0
(and beyond). This pins the auth contract other tasks (A-4+) must not break:
`/health` stays public, protected routes stay JWT-gated, and the full
login -> token -> /auth/me path keeps working end to end.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user


@pytest.mark.integration
def test_health_stays_public_without_auth(client: TestClient):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.integration
async def test_full_login_to_me_path_stays_green(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    await create_user(
        migrated_session_maker, username="regress-admin", password="pw", role="admin"
    )

    unauthenticated = client.get("/auth/me")
    assert unauthenticated.status_code == 401

    login = client.post("/auth/login", json={"username": "regress-admin", "password": "pw"})
    assert login.status_code == 200
    token = login.json()["access_token"]

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "regress-admin"
