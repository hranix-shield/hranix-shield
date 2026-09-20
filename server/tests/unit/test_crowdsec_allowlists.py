"""A-42: `CrowdSecClient.get_allowlists`/module-level `fetch_allowlists` —
the `ids` console's real «Белый список» data source, replacing A-11's
hardcoded `settings.whitelist_count: 0`. Fully offline (httpx's own
`MockTransport` test seam, same technique as test_crowdsec_write_client.py).
Every request/response shape asserted here matches CrowdSec's own published
`localapi_swagger.yaml` (`GetAllowlistResponse`/`AllowlistItem`) and the live
401/405/404 checks recorded in crowdsec.py's "A-42 addendum" docstring
section — this file is not guessing at CrowdSec's API. Live-container
coverage (the real DoD click-and-verify loop, opt-in/self-skipping) lives in
tests/integration/test_crowdsec_allowlists_live.py, marked
`crowdsec_write_live` (the same marker test_crowdsec_write_live.py uses,
since this needs the identical machine-level credential).
"""

from __future__ import annotations

import httpx
import pytest

from app.config import Settings
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecClient,
    CrowdSecError,
    fetch_allowlists,
)


def _client_with_handler(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://crowdsec.test")


def _login_response(token: str = "jwt-token", expire: str = "2099-01-01T00:00:00Z") -> httpx.Response:
    return httpx.Response(200, json={"code": 200, "expire": expire, "token": token})


# ---------------------------------------------------------------------------
# CrowdSecClient.get_allowlists (GET /v1/allowlists?with_content=true)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_get_allowlists_uses_the_machine_jwt_not_a_bouncer_key():
    """Confirmed live (crowdsec.py's "A-42 addendum"): a bouncer key gets
    HTTP 401 here — this endpoint needs the SAME machine-level
    `Authorization: Bearer` token `create_ban`/`delete_decision` use."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        captured["path"] = request.url.path
        captured["params"] = dict(request.url.params)
        captured["auth"] = request.headers.get("Authorization")
        captured["api_key"] = request.headers.get("X-Api-Key")
        return httpx.Response(200, json=[])

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    await client.get_allowlists()

    assert captured["path"] == "/v1/allowlists"
    assert captured["params"] == {"with_content": "true"}
    assert captured["auth"] == "Bearer jwt-token"
    assert captured["api_key"] is None


@pytest.mark.unit
async def test_get_allowlists_returns_the_real_shape_confirmed_against_swagger():
    """Response shape matches CrowdSec's own `localapi_swagger.yaml`
    (`GetAllowlistResponse`/`AllowlistItem`) — see crowdsec.py's "A-42
    addendum" docstring section."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(
            200,
            json=[
                {
                    "name": "test_al",
                    "allowlist_id": "abc123",
                    "description": "A-42 live verification test allowlist",
                    "console_managed": False,
                    "created_at": "2026-07-23T12:00:00Z",
                    "updated_at": "2026-07-23T12:00:00Z",
                    "items": [
                        {
                            "value": "203.0.113.5",
                            "description": "RFC 5737 test address",
                            "created_at": "2026-07-23T12:00:00Z",
                            "expiration": None,
                        }
                    ],
                }
            ],
        )

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    allowlists = await client.get_allowlists()

    assert len(allowlists) == 1
    assert allowlists[0]["name"] == "test_al"
    assert allowlists[0]["items"][0]["value"] == "203.0.113.5"


@pytest.mark.unit
async def test_get_allowlists_translates_a_null_body_to_an_empty_list():
    """Same `null` -> `[]` translation as `get_decisions` (see that
    method's own docstring) — CrowdSec answers a JSON `null`, not `[]`,
    when there is genuinely nothing to return."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(200, content=b"null", headers={"content-type": "application/json"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    assert await client.get_allowlists() == []


@pytest.mark.unit
async def test_get_allowlists_raises_unauthorized_on_401():
    """Confirmed live: a rejected/bouncer-only credential gets the same
    "cookie token is empty" 401 shape the write endpoints already document
    (crowdsec.py's "A-29 addendum")."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(401, json={"code": 401, "message": "cookie token is empty"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_allowlists()

    assert excinfo.value.reason == "unauthorized"


@pytest.mark.unit
async def test_get_allowlists_raises_unreachable_on_a_connection_error():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        raise httpx.ConnectError("connection refused", request=request)

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_allowlists()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_get_allowlists_raises_unreachable_on_an_unexpected_status():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(500, json={"message": "internal error"})

    client = CrowdSecClient(
        lapi_url="http://crowdsec.test",
        machine_id="m",
        machine_password="p",
        client=_client_with_handler(handler),
    )

    with pytest.raises(CrowdSecError) as excinfo:
        await client.get_allowlists()

    assert excinfo.value.reason == "unreachable"


# ---------------------------------------------------------------------------
# fetch_allowlists (module-level wrapper the router calls)
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fetch_allowlists_reports_not_configured_when_machine_creds_are_missing():
    """Deliberately the SAME `is_crowdsec_write_configured` gate `ban_ip`/
    `unban_decision` already use (A-29) — a bouncer-only deployment (the
    A-11 default) must report this as `not_configured`, not attempt a call
    that would 401."""
    settings = Settings(
        crowdsec_lapi_url="http://crowdsec.test",
        crowdsec_api_key="bouncer-key-only",
        crowdsec_machine_id=None,
        crowdsec_machine_password=None,
    )

    result = await fetch_allowlists(settings)

    assert result == {"connector": {"status": "not_configured"}, "allowlists": []}


@pytest.mark.unit
async def test_fetch_allowlists_flattens_items_across_named_allowlists(monkeypatch: pytest.MonkeyPatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(
            200,
            json=[
                {
                    "name": "test_al",
                    "items": [
                        {
                            "value": "203.0.113.5",
                            "description": "RFC 5737 test address",
                            "expiration": None,
                            "created_at": "2026-07-23T12:00:00Z",
                        }
                    ],
                },
                {"name": "other_al", "items": []},
            ],
        )

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

    result = await fetch_allowlists(settings)

    assert result["connector"] == {"status": "ok"}
    assert result["allowlists"] == [
        {
            "allowlist_name": "test_al",
            "value": "203.0.113.5",
            "comment": "RFC 5737 test address",
            "expiration": None,
            "created_at": "2026-07-23T12:00:00Z",
        }
    ]


@pytest.mark.unit
async def test_fetch_allowlists_normalises_go_zero_time_expiration_to_none(
    monkeypatch: pytest.MonkeyPatch,
):
    """Confirmed live: `cscli allowlists add` with no `-e` flag (a genuinely
    permanent entry — the common case) makes LAPI answer a literal
    `"0001-01-01T00:00:00.000Z"` `expiration`, Go's zero `time.Time` value
    serialised — not `null`. Left as-is, `app.js`'s `formatTimestamp` would
    render this as a real-looking date ("01.01, 02:30") instead of "never
    expires" — a fabricated-looking value from a technically-real-but-empty
    field. `_flatten_allowlist_items` must normalise it to a real `None`."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(
            200,
            json=[
                {
                    "name": "test_al",
                    "items": [
                        {
                            "value": "203.0.113.9",
                            "description": "permanent trust entry",
                            "expiration": "0001-01-01T00:00:00.000Z",
                            "created_at": "2026-07-23T12:00:00Z",
                        }
                    ],
                },
            ],
        )

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

    result = await fetch_allowlists(settings)

    assert result["allowlists"][0]["expiration"] is None


@pytest.mark.unit
async def test_fetch_allowlists_reports_the_honest_reason_on_a_crowdsec_error(
    monkeypatch: pytest.MonkeyPatch,
):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return httpx.Response(401, json={"code": 401, "message": "incorrect Username or Password"})
        raise AssertionError("must not reach /v1/allowlists without a token")

    import app.services.mcp.security_connectors.crowdsec as crowdsec_module

    settings = Settings(
        crowdsec_lapi_url="http://crowdsec.test",
        crowdsec_machine_id="m",
        crowdsec_machine_password="wrong",
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

    result = await fetch_allowlists(settings)

    assert result == {"connector": {"status": "unauthorized"}, "allowlists": []}


@pytest.mark.unit
async def test_fetch_allowlists_empty_items_stay_an_honest_empty_list(monkeypatch: pytest.MonkeyPatch):
    """A real, reachable CrowdSec with zero allowlist entries must come back
    as a real empty list, not conflated with the not_configured/error
    cases — DoD's "Белый список пуст" (never «ошибка»)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/watchers/login":
            return _login_response()
        return httpx.Response(200, json=[])

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

    result = await fetch_allowlists(settings)

    assert result == {"connector": {"status": "ok"}, "allowlists": []}
