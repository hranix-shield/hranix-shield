"""A-29: the write-capable half of `CrowdSecClient` — machine-level LAPI
auth (`POST /v1/watchers/login`) plus `create_ban`/`delete_decision`
(`POST /v1/alerts` / `DELETE /v1/decisions/{id}`) — fully offline (httpx's
own `MockTransport` test seam, same technique as test_crowdsec_client.py).
Every request/response shape asserted here was captured against a real
`hranix-crowdsec` container while building this task (see crowdsec.py's "A-29
addendum" docstring section for the exact commands run) — this file is not
guessing at CrowdSec's API from documentation. Live-container coverage
(the real DoD click-and-verify loop) lives in
tests/integration/test_crowdsec_write_live.py, marked `crowdsec_write_live`.
"""

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app.config import Settings
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecClient,
    CrowdSecError,
    CrowdSecNotConfiguredError,
    ban_ip,
    create_crowdsec_write_client,
    is_crowdsec_write_configured,
    unban_decision,
)


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://crowdsec.test")


def _login_response(token: str = "jwt-token", expire: str = "2026-07-18T21:24:46Z") -> httpx.Response:
    return httpx.Response(200, json={"code": 200, "expire": expire, "token": token})


# ---------------------------------------------------------------------------
# _login_machine (POST /v1/watchers/login)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_login_machine_sends_machine_id_and_password_as_json_body():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        captured["path"] = request.url.path
        captured["json"] = json.loads(request.content)
        return _login_response()

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="hranix-shield-machine",
        machine_password="s3cr3t",
        client=_client_with_handler(handler),
    )

    token = await client._login_machine()

    assert captured["path"] == "/v1/watchers/login"
    assert captured["json"] == {"machine_id": "hranix-shield-machine", "password": "s3cr3t"}
    assert token == "jwt-token"


@pytest.mark.unit
async def test_login_machine_caches_the_token_across_calls():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        # Far-future expiry so the cache never looks stale within this test.
        return _login_response(expire="2099-01-01T00:00:00Z")

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    first = await client._login_machine()
    second = await client._login_machine()

    assert first == second == "jwt-token"
    assert call_count == 1  # second call reused the cached token, no re-login


@pytest.mark.unit
async def test_login_machine_relogs_in_once_the_cached_token_is_near_expiry():
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        return _login_response(token=f"jwt-{call_count}", expire="2099-01-01T00:00:00Z")

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    await client._login_machine()
    # Force the cached token to look like it is about to expire.
    client._write_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=1)
    token = await client._login_machine()

    assert call_count == 2
    assert token == "jwt-2"


@pytest.mark.unit
async def test_login_machine_raises_unauthorized_on_401():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"code": 401, "message": "incorrect Username or Password"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="wrong",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client._login_machine()

    assert excinfo.value.reason == "unauthorized"


@pytest.mark.unit
async def test_login_machine_raises_unreachable_on_a_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client._login_machine()

    assert excinfo.value.reason == "unreachable"


# ---------------------------------------------------------------------------
# create_ban (POST /v1/alerts)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_create_ban_sends_the_alert_shape_captured_from_a_real_cscli_run():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        assert request.url.path == "/v1/alerts"
        captured["auth"] = request.headers.get("Authorization")
        import json

        captured["body"] = json.loads(request.content)
        return httpx.Response(201, json=["24"])

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    alert_ids = await client.create_ban("192.0.2.1", duration="5m", reason="test-ban")

    assert alert_ids == ["24"]
    assert captured["auth"] == "Bearer jwt-token"
    [alert] = captured["body"]
    assert alert["decisions"] == [
        {
            "duration": "5m",
            "origin": "hranix-shield",
            "scenario": "test-ban",
            "scope": "Ip",
            "type": "ban",
            "value": "192.0.2.1",
        }
    ]
    assert alert["source"] == {"ip": "192.0.2.1", "scope": "Ip", "value": "192.0.2.1"}
    assert alert["simulated"] is False


@pytest.mark.unit
async def test_create_ban_rejects_an_invalid_ip_without_any_network_call():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("must not reach LAPI for a locally-invalid IP")

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.create_ban("not-an-ip")

    assert excinfo.value.reason == "invalid_ip"


@pytest.mark.unit
async def test_create_ban_raises_rejected_when_lapi_answers_201_with_no_decisions():
    """Confirmed live: CrowdSec's alert-schema validation can accept a
    request (HTTP 201) while its own IP parsing silently creates zero
    decisions — an empty array, not an error. See crowdsec.py's "A-29
    addendum" docstring section."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(201, json=[])

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.create_ban("192.0.2.1")

    assert excinfo.value.reason == "rejected"


@pytest.mark.unit
async def test_create_ban_raises_unauthorized_on_401_from_alerts():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(401, json={"code": 401, "message": "cookie token is empty"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.create_ban("192.0.2.1")

    assert excinfo.value.reason == "unauthorized"


# ---------------------------------------------------------------------------
# delete_decision (DELETE /v1/decisions/{id})
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_delete_decision_returns_the_parsed_deleted_count():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        assert request.url.path == "/v1/decisions/88500"
        assert request.headers.get("Authorization") == "Bearer jwt-token"
        # Confirmed live: CrowdSec answers nbDeleted as a STRING, not an int.
        return httpx.Response(200, json={"nbDeleted": "1"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    assert await client.delete_decision(88500) == 1


@pytest.mark.unit
async def test_delete_decision_raises_not_found_on_the_doesnt_exist_500():
    """Confirmed live: deleting an id LAPI has never heard of answers HTTP
    500 (not 404) with this exact message shape — see crowdsec.py's "A-29
    addendum" docstring section."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(
            500, json={"message": "decision with id '999999999' doesn't exist: unable to delete"}
        )

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.delete_decision(999999999)

    assert excinfo.value.reason == "not_found"


@pytest.mark.unit
async def test_delete_decision_raises_unreachable_on_a_generic_500():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(500, json={"message": "internal server error"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.delete_decision(1)

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_delete_decision_raises_unauthorized_on_401():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(401, json={"code": 401, "message": "cookie token is empty"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.delete_decision(1)

    assert excinfo.value.reason == "unauthorized"


# ---------------------------------------------------------------------------
# Settings-driven wiring: is_crowdsec_write_configured / create_crowdsec_write_client
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_crowdsec_write_configured_requires_all_three_fields():
    assert (
        is_crowdsec_write_configured(
            Settings(crowdsec_lapi_url=None, crowdsec_machine_id=None, crowdsec_machine_password=None)
        )
        is False
    )
    assert (
        is_crowdsec_write_configured(
            Settings(
                crowdsec_lapi_url="http://x",
                crowdsec_machine_id="m",
                crowdsec_machine_password=None,
            )
        )
        is False
    )
    assert (
        is_crowdsec_write_configured(
            Settings(
                crowdsec_lapi_url="http://x",
                crowdsec_machine_id="m",
                crowdsec_machine_password="p",
            )
        )
        is True
    )


@pytest.mark.unit
def test_is_crowdsec_write_configured_is_independent_of_the_bouncer_key():
    """A deployment can have a working read-only bouncer key with NO
    machine credential at all (the Phase-0-until-now default) — writes stay
    unconfigured regardless of the bouncer key's own state."""
    settings = Settings(
        crowdsec_lapi_url="http://x",
        crowdsec_api_key="bouncer-key",
        crowdsec_machine_id=None,
        crowdsec_machine_password=None,
    )

    assert is_crowdsec_write_configured(settings) is False


@pytest.mark.unit
def test_create_crowdsec_write_client_returns_none_when_not_configured():
    settings = Settings(crowdsec_lapi_url=None, crowdsec_machine_id=None, crowdsec_machine_password=None)

    assert create_crowdsec_write_client(settings) is None


@pytest.mark.unit
async def test_create_crowdsec_write_client_builds_a_real_client_when_configured():
    settings = Settings(
        crowdsec_lapi_url="http://crowdsec.test:8080",
        crowdsec_machine_id="m",
        crowdsec_machine_password="p",
    )

    client = create_crowdsec_write_client(settings)

    assert client is not None
    assert isinstance(client, CrowdSecClient)
    await client.aclose()


# ---------------------------------------------------------------------------
# ban_ip / unban_decision (module-level wrappers used by the router)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_ban_ip_raises_not_configured_error_when_write_creds_are_missing():
    settings = Settings(crowdsec_lapi_url=None, crowdsec_machine_id=None, crowdsec_machine_password=None)

    with pytest.raises(CrowdSecNotConfiguredError):
        await ban_ip("192.0.2.1", settings=settings)


@pytest.mark.unit
async def test_unban_decision_raises_not_configured_error_when_write_creds_are_missing():
    settings = Settings(crowdsec_lapi_url=None, crowdsec_machine_id=None, crowdsec_machine_password=None)

    with pytest.raises(CrowdSecNotConfiguredError):
        await unban_decision(1, settings=settings)


@pytest.mark.unit
async def test_ban_ip_delegates_to_the_client_create_crowdsec_write_client_returns(
    monkeypatch: pytest.MonkeyPatch,
):
    """`ban_ip` is a thin wrapper (build a write client via
    `create_crowdsec_write_client`, call `create_ban`, always `aclose()`) —
    this confirms it actually uses whatever that factory returns rather than
    building its own client some other way."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response(expire="2099-01-01T00:00:00Z")
        return httpx.Response(201, json=["42"])

    import app.services.mcp.security_connectors.crowdsec as crowdsec_module

    settings = Settings(
        crowdsec_lapi_url="http://crowdsec.test",
        crowdsec_machine_id="m",
        crowdsec_machine_password="p",
    )
    real_client = CrowdSecClient(
        lapi_url=settings.crowdsec_lapi_url,
        machine_id=settings.crowdsec_machine_id,
        machine_password=settings.crowdsec_machine_password,
        client=_client_with_handler(handler),
    )
    monkeypatch.setattr(
        crowdsec_module, "create_crowdsec_write_client", lambda settings=None: real_client
    )

    alert_ids = await ban_ip("192.0.2.1", settings=settings)

    assert alert_ids == ["42"]
