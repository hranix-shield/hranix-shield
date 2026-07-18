import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.app_factory import create_app
from app.config import Settings
from app.services.event_bus import EventBus
from app.services.mcp import MCPRegistry


@pytest.mark.unit
def test_create_app_returns_fastapi_instance():
    app = create_app()

    assert isinstance(app, FastAPI)


@pytest.mark.unit
def test_create_app_wires_a_fresh_event_bus_with_default_subscriber_per_instance():
    """Each create_app() call gets its own EventBus (not a shared module-level
    singleton), so subscriptions never leak across app instances/tests, and
    the default events-table logger is already wired without needing the
    lifespan to run (see app_factory.create_app — done outside `_lifespan`).
    """
    app_one = create_app()
    app_two = create_app()

    assert isinstance(app_one.state.event_bus, EventBus)
    assert app_one.state.event_bus is not app_two.state.event_bus


@pytest.mark.unit
def test_create_app_wires_a_fresh_mcp_registry_per_instance_with_crowdsec_registered():
    """A-11: unlike A-9's original zero-connectors abstraction (see
    services/mcp/registry.py's docstring), `app.state.mcp_registry` is now a
    real per-instance registry with CrowdSec already registered at startup
    (Osquery/Wazuh/ClamAV are out of scope for A-11, see task brief)."""
    app_one = create_app()
    app_two = create_app()

    assert isinstance(app_one.state.mcp_registry, MCPRegistry)
    assert app_one.state.mcp_registry is not app_two.state.mcp_registry
    assert app_one.state.mcp_registry.get("crowdsec").name == "crowdsec"


@pytest.mark.unit
def test_create_app_registers_health_route():
    app = create_app()

    paths = {route.path for route in app.routes}

    assert "/health" in paths


@pytest.mark.unit
def test_health_endpoint_returns_ok():
    app = create_app()
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.unit
def test_settings_default_host_is_localhost(monkeypatch):
    monkeypatch.delenv("SERVER_HOST", raising=False)

    # _env_file=None: ignore any real .env on disk, isolate the default value
    # this test guards — panel must bind localhost unless the user opts in
    settings = Settings(_env_file=None)

    assert settings.server_host == "127.0.0.1"
