"""A-40: `crowdsec.py`'s network-reputation cross-reference —
`fetch_active_decision_values` (reuses `get_decisions()`/
`create_crowdsec_client`, no new CrowdSec integration, see that
function's own docstring) and `ip_matches_any_decision` (pure IP-vs-
(IP-or-CIDR) comparison, no I/O at all). Same fake-client seam
`test_crowdsec_ids_console_data.py` already established for
`fetch_ids_console_data` — no Docker/network access required for this
file; the live-container scenario is covered by
tests/integration/test_crowdsec_live.py.
"""

import pytest

import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.config import Settings
from app.services.mcp.security_connectors.crowdsec import (
    CrowdSecError,
    fetch_active_decision_values,
    ip_matches_any_decision,
)

_CONFIGURED_SETTINGS = Settings(crowdsec_lapi_url="http://crowdsec.test:8080", crowdsec_api_key="k")
_UNCONFIGURED_SETTINGS = Settings(crowdsec_lapi_url=None, crowdsec_api_key=None)


class _FakeCrowdSecClient:
    def __init__(self, decisions=None, error: CrowdSecError | None = None):
        self._decisions = decisions or []
        self._error = error
        self.closed = False

    async def get_decisions(self):
        if self._error is not None:
            raise self._error
        return self._decisions

    async def aclose(self):
        self.closed = True


# ---------------------------------------------------------------------------
# fetch_active_decision_values
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_not_configured_reports_honest_placeholder():
    result = await fetch_active_decision_values(_UNCONFIGURED_SETTINGS)

    assert result == {"connector": {"status": "not_configured"}, "values": []}


@pytest.mark.unit
async def test_unreachable_reports_that_status_and_closes_the_client(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeCrowdSecClient(error=CrowdSecError("down", reason="unreachable"))
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_active_decision_values(_CONFIGURED_SETTINGS)

    assert result == {"connector": {"status": "unreachable"}, "values": []}
    assert fake.closed is True


@pytest.mark.unit
async def test_unauthorized_reports_that_status(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeCrowdSecClient(error=CrowdSecError("bad key", reason="unauthorized"))
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_active_decision_values(_CONFIGURED_SETTINGS)

    assert result == {"connector": {"status": "unauthorized"}, "values": []}


@pytest.mark.unit
async def test_ok_returns_every_decisions_raw_value_including_community_ones(
    monkeypatch: pytest.MonkeyPatch,
):
    """Deliberately does NOT split local-vs-CAPI the way `fetch_ids_console_data`
    does — a community-blocklisted IP connecting to THIS machine is still a
    real reason to flag a row, see this function's own docstring."""
    fake = _FakeCrowdSecClient(
        decisions=[
            {"id": 1, "value": "198.51.100.23", "origin": "cscli"},
            {"id": 2, "value": "203.0.113.0/24", "origin": "CAPI"},
            {"id": 3, "value": None, "origin": "cscli"},  # defensively skipped
        ]
    )
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_active_decision_values(_CONFIGURED_SETTINGS)

    assert result == {
        "connector": {"status": "ok"},
        "values": ["198.51.100.23", "203.0.113.0/24"],
    }
    assert fake.closed is True


# ---------------------------------------------------------------------------
# ip_matches_any_decision
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_exact_ip_match():
    assert ip_matches_any_decision("198.51.100.23", ["198.51.100.23"]) is True


@pytest.mark.unit
def test_no_match_among_several_values():
    assert ip_matches_any_decision("198.51.100.99", ["198.51.100.23", "203.0.113.5"]) is False


@pytest.mark.unit
def test_cidr_range_containment_matches():
    # A-29's own RFC 5737 TEST-NET-1 range, the same block used for this
    # project's own live CrowdSec ban tests.
    assert ip_matches_any_decision("192.0.2.42", ["192.0.2.0/24"]) is True


@pytest.mark.unit
def test_cidr_range_containment_does_not_match_outside_the_range():
    assert ip_matches_any_decision("192.0.3.1", ["192.0.2.0/24"]) is False


@pytest.mark.unit
def test_falsy_or_unparsable_ip_never_matches_and_never_raises():
    assert ip_matches_any_decision(None, ["198.51.100.23"]) is False
    assert ip_matches_any_decision("", ["198.51.100.23"]) is False
    assert ip_matches_any_decision("not-an-ip", ["198.51.100.23"]) is False


@pytest.mark.unit
def test_unparsable_decision_values_are_skipped_not_fatal():
    """A malformed `value` from CrowdSec (should not happen with real data,
    but never trusted unconditionally — see this function's own docstring)
    is just one non-match among the list, not a crash."""
    assert (
        ip_matches_any_decision("198.51.100.23", ["not-a-real-value", "198.51.100.23"])
        is True
    )
    assert ip_matches_any_decision("198.51.100.23", ["not-a-real-value"]) is False


@pytest.mark.unit
def test_empty_decision_values_list_never_matches():
    assert ip_matches_any_decision("198.51.100.23", []) is False
