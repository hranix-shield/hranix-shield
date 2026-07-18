"""A-16: WazuhClient + Settings-driven wiring, fully offline (httpx's own
`MockTransport` test seam — same technique already used for
CrowdSecClient/OllamaBackend, see test_crowdsec_client.py's module
docstring) — no Docker/real Wazuh required for this file. The live-container
scenarios (real Manager API, real FIM findings) are covered separately in
tests/integration/test_wazuh_live.py, marked `wazuh_live` and self-skipping
when no real Wazuh is reachable.
"""

import httpx
import pytest

from app.config import Settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.wazuh import (
    WazuhClient,
    WazuhError,
    create_wazuh_client,
    is_wazuh_configured,
    register_wazuh_connector,
)


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://wazuh.test")


def _wazuh_client(handler, **kwargs) -> WazuhClient:
    return WazuhClient(
        api_url="http://wazuh.test",
        username="wazuh-wui",
        password="secret-pass",
        client=_client_with_handler(handler),
        **kwargs,
    )


@pytest.mark.unit
async def test_get_agent_status_authenticates_then_sends_the_bearer_token():
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/security/user/authenticate":
            assert request.headers["Authorization"].startswith("Basic ")
            return httpx.Response(200, text="fake-jwt-token")
        assert request.headers.get("Authorization") == "Bearer fake-jwt-token"
        assert request.url.params.get("agents_list") == "000"
        return httpx.Response(
            200,
            json={"data": {"affected_items": [{"id": "000", "status": "active"}]}},
        )

    client = _wazuh_client(handler)

    status = await client.get_agent_status()

    assert status == "active"
    assert calls == ["/security/user/authenticate", "/agents"]


@pytest.mark.unit
async def test_authentication_is_cached_across_multiple_calls_on_one_client():
    """One `WazuhClient` instance = one login for its whole lifetime — see
    the class docstring for why re-authenticating per call would be both
    unnecessary and wasteful."""
    auth_calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal auth_calls
        if request.url.path == "/security/user/authenticate":
            auth_calls += 1
            return httpx.Response(200, text="fake-jwt-token")
        if request.url.path == "/agents":
            return httpx.Response(200, json={"data": {"affected_items": [{"status": "active"}]}})
        return httpx.Response(200, json={"data": {"affected_items": []}})

    client = _wazuh_client(handler)

    await client.get_agent_status()
    await client.get_syscheck_findings()

    assert auth_calls == 1


@pytest.mark.unit
async def test_get_syscheck_findings_returns_the_parsed_affected_items():
    finding = {
        "file": "/monitored/data/seed.txt",
        "date": "2026-07-16T14:19:56+00:00",
        "changes": 1,
        "md5": "deadbeef",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="tok")
        assert request.url.path == "/syscheck/000"
        assert request.url.params.get("sort") == "-date"
        return httpx.Response(200, json={"data": {"affected_items": [finding]}})

    client = _wazuh_client(handler)

    findings = await client.get_syscheck_findings()

    assert findings == [finding]


@pytest.mark.unit
async def test_authenticate_raises_unauthorized_on_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Invalid credentials"})

    client = _wazuh_client(handler)

    with pytest.raises(WazuhError) as excinfo:
        await client.get_agent_status()

    assert excinfo.value.reason == "unauthorized"


@pytest.mark.unit
async def test_a_later_401_after_successful_auth_is_also_unauthorized():
    """A token that was valid at login time but gets rejected by a later
    call (e.g. revoked mid-session) must surface the same `"unauthorized"`
    reason, not `"unreachable"`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="tok")
        return httpx.Response(403, json={"message": "forbidden"})

    client = _wazuh_client(handler)

    with pytest.raises(WazuhError) as excinfo:
        await client.get_agent_status()

    assert excinfo.value.reason == "unauthorized"


@pytest.mark.unit
async def test_connect_error_during_authentication_raises_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = _wazuh_client(handler)

    with pytest.raises(WazuhError) as excinfo:
        await client.get_agent_status()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_unexpected_status_code_raises_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="tok")
        return httpx.Response(500, json={"message": "internal error"})

    client = _wazuh_client(handler)

    with pytest.raises(WazuhError) as excinfo:
        await client.get_agent_status()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_get_agent_status_returns_none_when_agent_is_unknown():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/security/user/authenticate":
            return httpx.Response(200, text="tok")
        return httpx.Response(200, json={"data": {"affected_items": []}})

    client = _wazuh_client(handler)

    assert await client.get_agent_status() is None


@pytest.mark.unit
async def test_aclose_closes_a_client_it_created_itself():
    client = WazuhClient(api_url="http://wazuh.test", username="u", password="p")

    await client.aclose()

    assert client._client.is_closed


@pytest.mark.unit
async def test_aclose_does_not_close_a_caller_supplied_client():
    external = _client_with_handler(lambda request: httpx.Response(200, text="tok"))
    client = WazuhClient(api_url="http://wazuh.test", username="u", password="p", client=external)

    await client.aclose()

    assert external.is_closed is False
    await external.aclose()


@pytest.mark.unit
def test_is_wazuh_configured_requires_all_three_settings():
    assert is_wazuh_configured(Settings(wazuh_api_url=None)) is False
    assert (
        is_wazuh_configured(Settings(wazuh_api_url="http://x", wazuh_api_username="u"))
        is False
    )
    assert (
        is_wazuh_configured(
            Settings(wazuh_api_url="http://x", wazuh_api_username="u", wazuh_api_password="p")
        )
        is True
    )


@pytest.mark.unit
def test_create_wazuh_client_returns_none_when_not_configured():
    settings = Settings(wazuh_api_url=None, wazuh_api_username=None, wazuh_api_password=None)

    assert create_wazuh_client(settings) is None


@pytest.mark.unit
async def test_create_wazuh_client_builds_a_real_client_when_configured():
    settings = Settings(
        wazuh_api_url="http://wazuh.test:55000", wazuh_api_username="u", wazuh_api_password="p"
    )

    client = create_wazuh_client(settings)

    assert client is not None
    assert isinstance(client, WazuhClient)
    await client.aclose()


@pytest.mark.unit
def test_register_wazuh_connector_registers_the_expected_metadata():
    registry = MCPRegistry()
    settings = Settings(
        wazuh_api_url="http://wazuh.test:55000", wazuh_api_username="u", wazuh_api_password="p"
    )

    register_wazuh_connector(registry, settings=settings)

    connector = registry.get("wazuh")
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "http"
    assert connector.endpoint == "http://wazuh.test:55000"


@pytest.mark.unit
def test_register_wazuh_connector_endpoint_is_empty_string_when_unconfigured():
    registry = MCPRegistry()
    settings = Settings(wazuh_api_url=None, wazuh_api_username=None, wazuh_api_password=None)

    register_wazuh_connector(registry, settings=settings)

    assert registry.get("wazuh").endpoint == ""
