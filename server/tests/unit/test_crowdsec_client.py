"""A-11: CrowdSecClient + Settings-driven wiring, fully offline (httpx's own
`MockTransport` test seam — same technique already used for OllamaBackend,
see test_ollama_backend.py's module docstring) — no Docker/real CrowdSec
required for this file. The live-container scenarios (real LAPI, real
decisions) are covered separately in
tests/integration/test_crowdsec_live.py, marked `crowdsec_live` and self-
skipping when no real CrowdSec is reachable.
"""

import httpx
import pytest

from app.config import Settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecClient,
    CrowdSecError,
    create_crowdsec_client,
    is_crowdsec_configured,
    register_crowdsec_connector,
)


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://crowdsec.test")


@pytest.mark.unit
async def test_get_decisions_returns_parsed_list_and_sends_the_api_key_header():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["api_key"] = request.headers.get("X-Api-Key")
        return httpx.Response(
            200,
            json=[
                {"id": 1, "value": "198.51.100.23", "scenario": "crowdsecurity/ssh-bf", "type": "ban"},
            ],
        )

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test", api_key="secret-key", client=_client_with_handler(handler)
    )

    decisions = await client.get_decisions()

    assert captured["path"] == "/v1/decisions"
    assert captured["api_key"] == "secret-key"
    assert decisions == [
        {"id": 1, "value": "198.51.100.23", "scenario": "crowdsecurity/ssh-bf", "type": "ban"}
    ]


@pytest.mark.unit
async def test_get_decisions_translates_a_null_body_into_an_empty_list():
    """CrowdSec's own API answers JSON `null`, not `[]`, when there are no
    active decisions — confirmed empirically against a live container while
    building this task (see task report)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test", api_key="k", client=_client_with_handler(handler)
    )

    assert await client.get_decisions() == []


@pytest.mark.unit
@pytest.mark.parametrize("status_code", [401, 403])
async def test_get_decisions_raises_unauthorized_on_401_or_403(status_code: int):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"message": "access forbidden"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test", api_key="wrong-key", client=_client_with_handler(handler)
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_decisions()

    assert excinfo.value.reason == "unauthorized"


@pytest.mark.unit
async def test_get_decisions_raises_unreachable_on_a_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test", api_key="k", client=_client_with_handler(handler)
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_decisions()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_get_decisions_raises_unreachable_on_an_unexpected_non_200():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "internal error"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test", api_key="k", client=_client_with_handler(handler)
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_decisions()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_aclose_closes_a_client_it_created_itself():
    client = CrowdSecClient(lapi_url="http://crowdsec.test", api_key="k")

    await client.aclose()

    assert client._client.is_closed


@pytest.mark.unit
async def test_aclose_does_not_close_a_caller_supplied_client():
    external = _client_with_handler(lambda request: httpx.Response(200, json=[]))
    client = CrowdSecClient(lapi_url="http://crowdsec.test", api_key="k", client=external)

    await client.aclose()

    assert external.is_closed is False
    await external.aclose()


@pytest.mark.unit
def test_is_crowdsec_configured_requires_both_url_and_key():
    assert is_crowdsec_configured(Settings(crowdsec_lapi_url=None, crowdsec_api_key=None)) is False
    assert (
        is_crowdsec_configured(Settings(crowdsec_lapi_url="http://x", crowdsec_api_key=None))
        is False
    )
    assert (
        is_crowdsec_configured(Settings(crowdsec_lapi_url=None, crowdsec_api_key="k")) is False
    )
    assert (
        is_crowdsec_configured(Settings(crowdsec_lapi_url="http://x", crowdsec_api_key="k"))
        is True
    )


@pytest.mark.unit
def test_create_crowdsec_client_returns_none_when_not_configured():
    settings = Settings(crowdsec_lapi_url=None, crowdsec_api_key=None)

    assert create_crowdsec_client(settings) is None


@pytest.mark.unit
async def test_create_crowdsec_client_builds_a_real_client_when_configured():
    settings = Settings(crowdsec_lapi_url="http://crowdsec.test:8080", crowdsec_api_key="k")

    client = create_crowdsec_client(settings)

    assert client is not None
    assert isinstance(client, CrowdSecClient)
    await client.aclose()


@pytest.mark.unit
def test_register_crowdsec_connector_registers_the_expected_metadata():
    registry = MCPRegistry()
    settings = Settings(crowdsec_lapi_url="http://crowdsec.test:8080", crowdsec_api_key="k")

    register_crowdsec_connector(registry, settings=settings)

    connector = registry.get("crowdsec")
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "http"
    assert connector.endpoint == "http://crowdsec.test:8080"


@pytest.mark.unit
def test_register_crowdsec_connector_endpoint_is_empty_string_when_unconfigured():
    registry = MCPRegistry()
    settings = Settings(crowdsec_lapi_url=None, crowdsec_api_key=None)

    register_crowdsec_connector(registry, settings=settings)

    assert registry.get("crowdsec").endpoint == ""
