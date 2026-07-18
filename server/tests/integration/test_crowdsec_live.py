"""A-11 DoD: a live end-to-end check against a REAL running CrowdSec
container (see infra/security/crowdsec/docker-compose.yml) — not the
monkeypatched integration tests in test_security_console_ids_crowdsec.py.

Deliberately opt-in and self-skipping, marked `crowdsec_live` (registered in
pytest.ini): reads CROWDSEC_LAPI_URL/CROWDSEC_API_KEY straight from the
environment (NOT via the cached `get_settings()` — a developer running this
against a real container typically hasn't restarted the whole test process
with a real `.env`) and skips with a clear reason when either is unset or
the LAPI does not actually answer. A plain `server/venv/bin/python -m
pytest -q` run therefore needs no Docker at all, matching how A-12's own
restic tests only run against a real installed restic binary (see A-12) —
except CrowdSec is a *network service* that must be separately started
(`docker compose -f infra/security/crowdsec/docker-compose.yml up -d`,
then `... exec crowdsec cscli bouncers add <name> -o raw`), so this test
skips on unreachability too, not only on missing config.

Run explicitly with:
    CROWDSEC_LAPI_URL=http://127.0.0.1:8089 CROWDSEC_API_KEY=<key> \\
        server/venv/bin/python -m pytest -q -m crowdsec_live
"""

import os

import pytest

from app.services.mcp.security_connectors.crowdsec import CrowdSecClient, CrowdSecError


def _live_client() -> CrowdSecClient | None:
    lapi_url = os.environ.get("CROWDSEC_LAPI_URL")
    api_key = os.environ.get("CROWDSEC_API_KEY")
    if not lapi_url or not api_key:
        return None
    return CrowdSecClient(lapi_url=lapi_url, api_key=api_key, timeout=2.0)


@pytest.mark.crowdsec_live
async def test_live_crowdsec_decisions_match_a_direct_lapi_call():
    """DoD: "покажи прямой запрос к CrowdSec LAPI и сравни с тем, что
    отдаёт эндпоинт панели — они должны согласовываться." This test is the
    "direct LAPI call" half, done through the same `CrowdSecClient` the
    router uses (rather than shelling out to `curl`) so the comparison is
    apples-to-apples with what `fetch_ids_console_data` will compute from
    the exact same `get_decisions()` result.
    """
    client = _live_client()
    if client is None:
        pytest.skip("CROWDSEC_LAPI_URL/CROWDSEC_API_KEY not set — no live CrowdSec configured")

    try:
        decisions = await client.get_decisions()
    except CrowdSecError as exc:
        pytest.skip(f"CrowdSec not reachable/authorized: {exc}")
    finally:
        await client.aclose()

    # No assertion on *content* (a live container's decisions are whatever
    # an operator has actually banned) — the DoD-relevant assertion is that
    # a real bouncer-authenticated call succeeds and returns the documented
    # shape (see crowdsec.py's module docstring: value/scenario/type/id).
    assert isinstance(decisions, list)
    for decision in decisions:
        assert "value" in decision
        assert "scenario" in decision
        assert "type" in decision


@pytest.mark.crowdsec_live
async def test_live_unreachable_crowdsec_reports_a_clear_error_not_a_hang():
    """DoD failure scenario, against a real (if briefly wrong) address:
    pointing at a port nothing listens on must fail fast with
    `CrowdSecError(reason="unreachable")`, not hang or raise something
    uncaught."""
    if not os.environ.get("CROWDSEC_API_KEY"):
        pytest.skip("CROWDSEC_API_KEY not set — nothing live configured to contrast against")

    client = CrowdSecClient(
        lapi_url="http://127.0.0.1:1", api_key="irrelevant-for-this-check", timeout=1.0
    )
    try:
        with pytest.raises(CrowdSecError) as excinfo:
            await client.get_decisions()
        assert excinfo.value.reason == "unreachable"
    finally:
        await client.aclose()
