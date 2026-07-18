import pytest

from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPConnectorNotFoundError, MCPRegistry


def _stub_connector(name: str = "security-stack") -> MCPConnector:
    return MCPConnector(
        name=name,
        description="Stub connector for tests — no real transport behind it.",
        transport="stdio",
    )


@pytest.mark.unit
def test_get_returns_the_registered_connector():
    registry = MCPRegistry()
    connector = _stub_connector()
    registry.register(connector)

    assert registry.get("security-stack") is connector


@pytest.mark.unit
def test_get_raises_mcp_connector_not_found_error_for_an_unregistered_name():
    registry = MCPRegistry()

    with pytest.raises(MCPConnectorNotFoundError) as excinfo:
        registry.get("does_not_exist")

    assert "does_not_exist" in str(excinfo.value)
    assert excinfo.value.name == "does_not_exist"


@pytest.mark.unit
def test_not_found_error_lists_known_connector_names():
    registry = MCPRegistry()
    registry.register(_stub_connector("crowdsec"))

    with pytest.raises(MCPConnectorNotFoundError) as excinfo:
        registry.get("missing")

    assert "crowdsec" in str(excinfo.value)


@pytest.mark.unit
def test_registering_a_second_connector_under_the_same_name_replaces_the_first():
    registry = MCPRegistry()
    registry.register(_stub_connector("crowdsec"))
    replacement = MCPConnector(
        name="crowdsec",
        description="Updated description.",
        transport="http",
        endpoint="http://localhost:8080",
    )

    registry.register(replacement)

    assert registry.get("crowdsec") is replacement


@pytest.mark.unit
def test_list_connectors_on_an_empty_registry_is_empty():
    registry = MCPRegistry()

    assert registry.list_connectors() == []


@pytest.mark.unit
def test_list_connectors_returns_every_registered_connector_in_registration_order():
    registry = MCPRegistry()
    first = _stub_connector("crowdsec")
    second = _stub_connector("osquery")

    registry.register(first)
    registry.register(second)

    assert registry.list_connectors() == [first, second]


@pytest.mark.unit
def test_endpoint_defaults_to_empty_string_when_not_given():
    connector = MCPConnector(name="wazuh", description="Not wired up yet.", transport="http")

    assert connector.endpoint == ""


@pytest.mark.unit
def test_connector_is_a_frozen_value_object():
    connector = _stub_connector()

    with pytest.raises(Exception):
        connector.name = "renamed"  # type: ignore[misc]
