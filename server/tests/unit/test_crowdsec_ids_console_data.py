"""A-11: `fetch_ids_console_data` — the assembler behind
GET /security/consoles/ids's real (non-stub) fields. Exercised here against
a fake `CrowdSecClient` (monkeypatched in via `create_crowdsec_client`, same
technique conftest.py already uses for `health.checks.async_session_maker`)
so these unit tests need neither Docker nor a network call. Live-container
coverage lives in tests/integration/test_crowdsec_live.py.
"""

import pytest

import app.services.mcp.security_connectors.crowdsec as crowdsec_module
from app.config import Settings
from app.services.mcp.security_connectors.crowdsec import CrowdSecError, fetch_ids_console_data

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


@pytest.mark.unit
async def test_not_configured_reports_honest_placeholder_not_fabricated_zeros(
    monkeypatch: pytest.MonkeyPatch,
):
    result = await fetch_ids_console_data(_UNCONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "not_configured"}
    assert result["metrics"] == {
        "active_bans": None,
        # A-23: the two fields the old single `active_bans` was split into
        # (community blocklist vs local decisions) stay honestly `None` too
        # when nothing could be queried at all — same "not a fabricated 0"
        # rule as every other field here.
        "active_bans_local": None,
        "active_bans_community": None,
        "banned_24h": None,
        "scenarios": None,
        "last_event_at": None,
    }
    assert result["recent_attempts"] == []
    # A-26: this connector no longer returns a `chart` key at all — real
    # chart history now comes from services/metrics/chart.chart_values_7d()
    # in routers/security_console.py, not from this pure external-tool
    # client (see this function's own docstring).
    assert "chart" not in result


@pytest.mark.unit
async def test_unreachable_connector_reports_that_status_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    fake = _FakeCrowdSecClient(error=CrowdSecError("down", reason="unreachable"))
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_ids_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "unreachable"}
    assert result["metrics"]["active_bans"] is None
    assert result["metrics"]["active_bans_local"] is None
    assert result["metrics"]["active_bans_community"] is None
    assert fake.closed is True


@pytest.mark.unit
async def test_unauthorized_connector_reports_that_status(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeCrowdSecClient(error=CrowdSecError("bad key", reason="unauthorized"))
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_ids_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "unauthorized"}


@pytest.mark.unit
async def test_reachable_connector_computes_real_metrics_from_live_decisions(
    monkeypatch: pytest.MonkeyPatch,
):
    """All three decisions here are locally-originated (`origin` is either
    `"cscli"` — a manually-added decision, confirmed live to use exactly
    this origin string, see crowdsec.py's "A-23 addendum" — or missing
    entirely, which must also count as local, not community: only an
    explicit `origin == "CAPI"` is community)."""
    decisions = [
        {
            "id": 1,
            "value": "198.51.100.10",
            "scenario": "crowdsecurity/ssh-bf",
            "type": "ban",
            "origin": "cscli",
        },
        {
            "id": 2,
            "value": "198.51.100.11",
            "scenario": "crowdsecurity/http-probing",
            "type": "ban",
            # No `origin` key at all — must still count as local, not
            # silently treated as community just because it is absent.
        },
        {
            "id": 3,
            "value": "198.51.100.10",
            "scenario": "crowdsecurity/ssh-bf",
            "type": "captcha",
            "origin": "cscli",
        },
    ]
    fake = _FakeCrowdSecClient(decisions=decisions)
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_ids_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["active_bans"] == 3
    assert result["metrics"]["active_bans_local"] == 3
    assert result["metrics"]["active_bans_community"] == 0
    assert result["metrics"]["scenarios"] == 2  # distinct scenarios: ssh-bf, http-probing
    # Honestly unavailable via bouncer LAPI regardless of success — see
    # crowdsec.py's module docstring for why these two stay None even when
    # everything else is real.
    assert result["metrics"]["banned_24h"] is None
    assert result["metrics"]["last_event_at"] is None
    # Most-recently-added decision (highest id) first.
    assert [attempt["ip"] for attempt in result["recent_attempts"]] == [
        "198.51.100.10",
        "198.51.100.11",
        "198.51.100.10",
    ]
    assert result["recent_attempts"][0] == {
        # A-29: the decision's own `id` is now carried through — the same
        # value `DELETE /v1/decisions/{id}` (CrowdSecClient.delete_decision)
        # expects, so the console's per-row "Разбанить" button has
        # something real to call. See crowdsec.py's `fetch_ids_console_data`
        # "A-29" docstring note.
        "id": 3,
        "ip": "198.51.100.10",
        "vector": "crowdsecurity/ssh-bf",
        "status": "captcha",
    }
    assert fake.closed is True


@pytest.mark.unit
async def test_reachable_connector_splits_community_blocklist_from_local_decisions(
    monkeypatch: pytest.MonkeyPatch,
):
    """A-23's actual bug fix: a mix of CAPI (community-blocklist) and local
    decisions must be counted separately, and `recent_attempts` must contain
    ONLY the local ones — confirmed live against a real CrowdSec container
    that `origin == "CAPI"` is exactly (and only) how community-blocklist
    decisions are marked, see crowdsec.py's "A-23 addendum" docstring."""
    decisions = [
        {"id": 10, "value": "203.0.113.1", "scenario": "ssh:exploit", "type": "ban", "origin": "CAPI"},
        {"id": 11, "value": "203.0.113.2", "scenario": "ssh:exploit", "type": "ban", "origin": "CAPI"},
        {"id": 12, "value": "203.0.113.3", "scenario": "generic:scan", "type": "ban", "origin": "CAPI"},
        {
            "id": 13,
            "value": "198.51.100.42",
            "scenario": "A-23 manual test decision",
            "type": "ban",
            "origin": "cscli",
        },
    ]
    fake = _FakeCrowdSecClient(decisions=decisions)
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_ids_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["active_bans"] == 4
    assert result["metrics"]["active_bans_local"] == 1
    assert result["metrics"]["active_bans_community"] == 3
    # Only the one locally-originated decision shows up as a "recent
    # attempt" — the three CAPI/community-blocklist entries must not leak
    # into a list a user reads as "recent attempts against this machine".
    assert result["recent_attempts"] == [
        {"id": 13, "ip": "198.51.100.42", "vector": "A-23 manual test decision", "status": "ban"}
    ]


@pytest.mark.unit
async def test_reachable_connector_with_zero_active_decisions_is_a_real_zero_not_none(
    monkeypatch: pytest.MonkeyPatch,
):
    """Distinguishes "genuinely queried and found nothing" (real `0`) from
    "could not ask at all" (`None`, the not_configured/unreachable/
    unauthorized cases above) — both are honest, but they mean different
    things and must not collapse into the same value."""
    fake = _FakeCrowdSecClient(decisions=[])
    monkeypatch.setattr(crowdsec_module, "create_crowdsec_client", lambda settings: fake)

    result = await fetch_ids_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["active_bans"] == 0
    assert result["metrics"]["active_bans_local"] == 0
    assert result["metrics"]["active_bans_community"] == 0
    assert result["metrics"]["scenarios"] == 0
    assert result["recent_attempts"] == []
