"""A-65-1: GET /health/system против реальной HTTP-прослойки (client-фикстура).

Ключевое отличие от /health/detailed: эндпоинт ПУБЛИЧНЫЙ (без Authorization —
уровень 1 реанимации, полоса статуса на форме входа), payload — только
статусы/коды. Детерминированная «здоровая машина» ставится autouse-фикстурой
`_fake_system_health_environment` (tests/conftest.py); сценарные тесты
переопределяют её куски поверх.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.health.remediation as remediation_module
import app.services.health.system as health_system_module
from tests.common.factories import create_user


async def _token_for(
    client: TestClient,
    maker: async_sessionmaker[AsyncSession],
    *,
    username: str,
    role: str,
) -> str:
    await create_user(maker, username=username, password="pw", role=role)
    response = client.post("/auth/login", json={"username": username, "password": "pw"})
    return response.json()["access_token"]


@pytest.mark.integration
def test_health_system_is_public_and_returns_full_matrix(client: TestClient):
    response = client.get("/health/system")

    assert response.status_code == 200  # без Authorization — публичный
    body = response.json()
    assert set(body.keys()) == {"aggregate", "components"}
    assert body["aggregate"] == "ok"
    ids = [component["id"] for component in body["components"]]
    assert ids == [
        "server",
        "database",
        "event_bus",
        "docker_engine",
        "hranix-crowdsec",
        "hranix-clamav",
        "hranix-wazuh-manager",
        "wazuh_api",
        "crowdsec_lapi",
        "clamd",
        "restic",
        "osqueryi",
        "disk",
    ]
    for component in body["components"]:
        assert set(component.keys()) == {"id", "status", "detail", "action"}


@pytest.mark.integration
def test_health_system_reflects_docker_outage_as_down(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    async def engine_down(*args: str, timeout: float = 5.0):
        if "info" in " ".join(args):
            return (1, "", "Cannot connect to the Docker daemon")
        return (0, "", "")

    monkeypatch.setattr(health_system_module, "run_local_command", engine_down)

    response = client.get("/health/system")

    assert response.status_code == 200
    body = response.json()
    assert body["aggregate"] == "down"
    engine = next(c for c in body["components"] if c["id"] == "docker_engine")
    assert engine["status"] == "unreachable"
    assert engine["action"] == "start_docker_desktop"


@pytest.mark.integration
def test_health_system_payload_stays_secret_free_even_on_outage(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
):
    """Даже при аварии в ответе нет ни значений config.env, ни URL/путей."""

    async def engine_down(*args: str, timeout: float = 5.0):
        return (1, "", "Cannot connect to the Docker daemon")

    monkeypatch.setattr(health_system_module, "run_local_command", engine_down)

    text = client.get("/health/system").text

    assert "fake-bouncer-key" not in text
    assert "fake-wazuh-pass" not in text
    assert "127.0.0.1" not in text


# ---------------------------------------------------------------------------
# A-65-3: remediation-действия — admin-only HTTP-слой.
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_actions_require_authentication(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    assert client.post("/health/system/actions/ping_components").status_code == 401


@pytest.mark.integration
async def test_actions_are_admin_only(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    viewer_token = await _token_for(
        client, migrated_session_maker, username="health-viewer", role="viewer"
    )

    response = client.post(
        "/health/system/actions/ping_components",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "insufficient_role"


@pytest.mark.integration
async def test_admin_restart_container_without_body_is_400(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin", role="admin"
    )

    response = client.post(
        "/health/system/actions/restart_container",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "container_name_required"


@pytest.mark.integration
async def test_admin_restart_of_unknown_container_is_404(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-404", role="admin"
    )

    response = client.post(
        "/health/system/actions/restart_container",
        json={"name": "not-our-container"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "unknown_container"


@pytest.mark.integration
async def test_admin_restart_container_happy_path(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-restart", role="admin"
    )
    calls: list[tuple[str, ...]] = []

    async def fake_run(*args: str, timeout: float = 5.0):
        calls.append(args)
        return (0, "hranix-crowdsec\n", "")

    monkeypatch.setattr(remediation_module, "run_local_command", fake_run)

    response = client.post(
        "/health/system/actions/restart_container",
        json={"name": "hranix-crowdsec"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "detail": "restarted"}
    assert ("docker", "restart", "hranix-crowdsec") in calls


@pytest.mark.integration
async def test_admin_compose_up_stack_returns_bootstrap_steps(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-up", role="admin"
    )

    async def fake_bootstrap():
        return {
            "status": "ok",
            "steps": [{"step": "compose_up", "status": "ok", "detail": None}],
            "restart_required": True,
        }

    monkeypatch.setattr(remediation_module, "run_stack_bootstrap", fake_bootstrap)

    response = client.post(
        "/health/system/actions/compose_up_stack",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["steps"][0]["step"] == "compose_up"
    assert body["restart_required"] is True


@pytest.mark.integration
async def test_admin_start_docker_desktop_happy_path(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-dd", role="admin"
    )
    exe = tmp_path / "Docker Desktop.exe"
    exe.write_bytes(b"fake-pe")
    spawned: list = []

    async def fake_spawn(path):
        spawned.append(path)

    monkeypatch.setattr(remediation_module, "_docker_desktop_installation", lambda: exe)
    monkeypatch.setattr(remediation_module, "_spawn_detached_windows", fake_spawn)

    response = client.post(
        "/health/system/actions/start_docker_desktop",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "detail": "docker_desktop_starting"}
    assert spawned == [exe]


@pytest.mark.integration
async def test_admin_ping_components_returns_fresh_matrix(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-ping", role="admin"
    )

    response = client.post(
        "/health/system/actions/ping_components",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"aggregate", "components"}
    assert [c["id"] for c in body["components"]][0] == "server"


@pytest.mark.integration
async def test_actions_accept_empty_json_body_without_422(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Живая находка A-65: UI шлёт "{}" телом для не-restart действий —
    обязательное поле name в общей модели тела давало 422 на них всех.
    Пустой JSON-объект обязаны принимать все четыре действия."""
    admin_token = await _token_for(
        client, migrated_session_maker, username="health-admin-empty", role="admin"
    )
    spawned: list = []

    async def fake_spawn(path):
        spawned.append(path)

    exe = migrated_session_maker  # любой объект-маркер, валидация не важна
    monkeypatch.setattr(remediation_module, "_docker_desktop_installation", lambda: exe)
    monkeypatch.setattr(remediation_module, "_spawn_detached_windows", fake_spawn)

    for action in ("ping_components", "compose_up_stack", "start_docker_desktop"):
        monkeypatch.setattr(remediation_module, "run_stack_bootstrap", fake_bootstrap_ok)
        response = client.post(
            f"/health/system/actions/{action}",
            json={},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert response.status_code == 200, (action, response.status_code, response.text)
    assert spawned  # start_docker_desktop реально исполнился


async def fake_bootstrap_ok():
    return {"status": "ok", "steps": [], "restart_required": False}
