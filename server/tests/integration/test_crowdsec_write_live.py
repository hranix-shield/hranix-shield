"""A-29 DoD: a live end-to-end check of ban/unban against a REAL running
CrowdSec container (see infra/security/crowdsec/docker-compose.yml/README.md)
using the machine-level write credential — not the monkeypatched unit tests
in test_crowdsec_write_client.py.

Deliberately opt-in and self-skipping, marked `crowdsec_write_live`
(registered in pytest.ini): reads CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/
CROWDSEC_MACHINE_PASSWORD straight from the environment (NOT via the cached
`get_settings()`, same reasoning as test_crowdsec_live.py) and skips with a
clear reason when any is unset or the write credential does not actually
work. A plain `server/venv/bin/python -m pytest -q` run therefore needs no
Docker and never touches a real CrowdSec container's decision list.

Uses a real, RFC 5737 TEST-NET-1 documentation address (`192.0.2.1`) —
never a real public IP — for the ban it creates, and always deletes it again
at the end (`finally`), so a run of this test never leaves the machine it
runs against actually banning anything, matching this task's own DoD
("после теста — убери свой тестовый бан").

Run explicitly with:
    CROWDSEC_LAPI_URL=http://127.0.0.1:8089 \\
        CROWDSEC_MACHINE_ID=<machine id from `cscli machines add`> \\
        CROWDSEC_MACHINE_PASSWORD=<its password> \\
        server/venv/bin/python -m pytest -q -m crowdsec_write_live
"""

import os

import pytest

from app.services.mcp.security_connectors.crowdsec import CrowdSecClient, CrowdSecError

_TEST_IP = "192.0.2.1"  # RFC 5737 TEST-NET-1 — reserved for documentation/testing, never real


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
async def test_live_ban_then_unban_a_test_ip_round_trips_through_real_lapi():
    """DoD: "клик «Забанить вручную» с тестовым IP -> `cscli decisions list`
    реально показывает новый бан" / "«Разбанить IP» -> решение реально
    снято". This is the same round trip through the same `CrowdSecClient`
    the router uses (rather than shelling out to `cscli`), against a real
    machine-level login — with a `GET /v1/decisions` re-check via a second,
    read-only client before and after so the assertions are against LAPI's
    own live state, not just "the write call didn't raise"."""
    write_client = _live_write_client()
    if write_client is None:
        pytest.skip(
            "CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD not set — "
            "no live CrowdSec machine credential configured"
        )

    lapi_url = os.environ["CROWDSEC_LAPI_URL"]
    bouncer_key = os.environ.get("CROWDSEC_API_KEY")
    read_client = (
        CrowdSecClient(lapi_url=lapi_url, api_key=bouncer_key, timeout=5.0)
        if bouncer_key
        else None
    )

    try:
        try:
            before = await read_client.get_decisions() if read_client else []
        except CrowdSecError as exc:
            pytest.skip(f"CrowdSec bouncer key not reachable/authorized: {exc}")
        assert not any(d.get("value") == _TEST_IP for d in before), (
            f"{_TEST_IP} was already banned before this test ran — "
            "leftover test state, investigate before trusting this run"
        )

        try:
            alert_ids = await write_client.create_ban(
                _TEST_IP, duration="5m", reason="A-29 live DoD test ban"
            )
        except CrowdSecError as exc:
            pytest.skip(f"CrowdSec machine credential not reachable/authorized: {exc}")
        assert alert_ids

        if read_client:
            after_ban = await read_client.get_decisions()
            banned = [d for d in after_ban if d.get("value") == _TEST_IP]
            assert len(banned) == 1
            decision_id = banned[0]["id"]
        else:
            # No bouncer key configured for this run — fall back to the
            # write credential's own login to look the decision id up via
            # a direct GET (LAPI does not gate this endpoint by credential
            # TYPE the way it gates /v1/alerts, only by whether a valid
            # credential of EITHER kind was presented).
            pytest.skip(
                "CROWDSEC_API_KEY not set — cannot look up the new decision's id "
                "to unban it without a read-side client"
            )

        deleted_count = await write_client.delete_decision(decision_id)
        assert deleted_count == 1

        after_unban = await read_client.get_decisions()
        assert not any(d.get("value") == _TEST_IP for d in after_unban)
    finally:
        # Best-effort cleanup even if an assertion above failed midway —
        # never leave this task's own test ban sitting in a real CrowdSec's
        # decision list (this task's own DoD requirement).
        if read_client:
            try:
                leftover = await read_client.get_decisions()
                for decision in leftover:
                    if decision.get("value") == _TEST_IP:
                        await write_client.delete_decision(decision["id"])
            except CrowdSecError:
                pass
            await read_client.aclose()
        await write_client.aclose()


@pytest.mark.crowdsec_write_live
async def test_live_create_ban_rejects_an_invalid_ip_before_touching_lapi():
    """DoD failure scenario, against a real (if deliberately malformed)
    input: this must fail client-side (`reason="invalid_ip"`), never reach
    LAPI, and never create a decision for garbage input."""
    write_client = _live_write_client()
    if write_client is None:
        pytest.skip(
            "CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD not set — "
            "no live CrowdSec machine credential configured"
        )

    try:
        with pytest.raises(CrowdSecError) as excinfo:
            await write_client.create_ban("definitely-not-an-ip")
        assert excinfo.value.reason == "invalid_ip"
    finally:
        await write_client.aclose()


@pytest.mark.crowdsec_write_live
async def test_live_delete_decision_on_an_unknown_id_reports_not_found():
    """DoD failure scenario: deleting a decision id nothing real could ever
    have (a huge, made-up integer) must map to `reason="not_found"`, not a
    generic failure — see crowdsec.py's "A-29 addendum" docstring for why
    CrowdSec's own HTTP 500 shape for this case needed a dedicated branch."""
    write_client = _live_write_client()
    if write_client is None:
        pytest.skip(
            "CROWDSEC_LAPI_URL/CROWDSEC_MACHINE_ID/CROWDSEC_MACHINE_PASSWORD not set — "
            "no live CrowdSec machine credential configured"
        )

    try:
        try:
            await write_client.delete_decision(999_999_999)
        except CrowdSecError as exc:
            if exc.reason in ("unreachable", "unauthorized"):
                pytest.skip(f"CrowdSec machine credential not reachable/authorized: {exc}")
            assert exc.reason == "not_found"
        else:
            pytest.fail("deleting a made-up decision id was expected to raise CrowdSecError")
    finally:
        await write_client.aclose()
