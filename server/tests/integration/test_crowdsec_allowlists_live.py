"""A-42 DoD: a live check of `CrowdSecClient.get_allowlists`/`fetch_allowlists`
against a REAL running CrowdSec container (see
infra/security/crowdsec/docker-compose.yml/README.md), using the SAME
machine-level write credential test_crowdsec_write_live.py already uses (this
call is a read, but — confirmed live, see crowdsec.py's "A-42 addendum"
docstring section — `GET /v1/allowlists` itself needs the machine JWT, the
bouncer key alone gets HTTP 401 here).

Deliberately opt-in and self-skipping, marked `crowdsec_write_live`
(registered in pytest.ini, reused here rather than a new marker — same
credential class): reads CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/
CROWDSEC_MACHINE_PASSWORD straight from the environment, same reasoning as
test_crowdsec_write_live.py. A plain `server/venv/bin/python -m pytest -q`
run therefore needs no Docker.

This file never creates/deletes CrowdSec state itself (there is no HTTP
write path to do so at all — see crowdsec.py's "A-42 addendum" for why every
write method on this path answers HTTP 405): it only asserts the READ works
against whatever allowlists genuinely exist on the target container right
now. The full "create a test allowlist, see it appear in the panel, delete
it again" DoD round trip needs `cscli allowlists create/add/delete` run
directly against the container (see infra/security/crowdsec/README.md) —
that is a one-off manual verification step, not something this test suite
can automate, because there is no HTTP write path this project's own
docker-exec policy allows it to drive.

Run explicitly with:
    CROWDSEC_LAPI_URL=http://127.0.0.1:8089 \\
        CROWDSEC_MACHINE_ID=<machine id from `cscli machines add`> \\
        CROWDSEC_MACHINE_PASSWORD=<its password> \\
        server/venv/bin/python -m pytest -q -m crowdsec_write_live
"""

import os

import pytest

from app.services.mcp.security_connectors.crowdsec import CrowdSecClient, CrowdSecError


def _live_write_client() -> CrowdSecClient | None:
    lapi_url = os.environ.get("CROWDSEC_LAPI_URL")
    machine_id = os.environ.get("CROWDSEC_MACHINE_ID")
    machine_password = os.environ.get("CROWDSEC_MACHINE_PASSWORD")
    if not lapi_url or not machine_id or not machine_password:
        return None
    return CrowdSecClient(
        lapi_url=lapi_url,
        machine_id=machine_id,
        machine_password=machine_password,
        timeout=5.0,
    )


@pytest.mark.crowdsec_write_live
async def test_live_get_allowlists_succeeds_with_the_machine_credential():
    """DoD smoke check: the read genuinely works against a live container
    with a real machine-level login — whatever allowlists/items exist right
    now come back as a well-formed list, never an error."""
    client = _live_write_client()
    if client is None:
        pytest.skip(
            "CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD not set — "
            "no live CrowdSec machine credential configured"
        )

    try:
        allowlists = await client.get_allowlists()
    except CrowdSecError as exc:
        pytest.skip(f"CrowdSec machine credential not reachable/authorized: {exc}")
    finally:
        await client.aclose()

    assert isinstance(allowlists, list)
    for allowlist in allowlists:
        assert "name" in allowlist
        assert "items" in allowlist


@pytest.mark.crowdsec_write_live
async def test_live_get_allowlists_rejects_a_wrong_machine_password_with_unauthorized():
    """DoD failure scenario, live: a wrong machine password must fail at
    LAPI's own login step (`reason="unauthorized"`), never silently return
    an empty allowlist that would read as "really is empty"."""
    lapi_url = os.environ.get("CROWDSEC_LAPI_URL")
    machine_id = os.environ.get("CROWDSEC_MACHINE_ID")
    if not lapi_url or not machine_id:
        pytest.skip("CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID not set — no live machine id to test with")

    client = CrowdSecClient(
        lapi_url=lapi_url, machine_id=machine_id, machine_password="deliberately-wrong", timeout=5.0
    )
    try:
        with pytest.raises(CrowdSecError) as excinfo:
            await client.get_allowlists()
        assert excinfo.value.reason == "unauthorized"
    finally:
        await client.aclose()
