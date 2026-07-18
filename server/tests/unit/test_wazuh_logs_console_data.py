"""A-16: `fetch_logs_console_data` — the assembler behind
GET /security/consoles/logs's real (non-stub) fields. Exercised here against
a fake `WazuhClient` (monkeypatched in via `create_wazuh_client`, same
technique test_crowdsec_ids_console_data.py already uses for
`create_crowdsec_client`) so these unit tests need neither Docker nor a
network call. Live-container coverage lives in
tests/integration/test_wazuh_live.py, marked `wazuh_live`.
"""

from datetime import datetime, timedelta, timezone

import pytest

import app.services.mcp.security_connectors.wazuh as wazuh_module
from app.config import Settings
from app.services.mcp.security_connectors.wazuh import WazuhError, fetch_logs_console_data

_CONFIGURED_SETTINGS = Settings(
    wazuh_api_url="http://wazuh.test:55000", wazuh_api_username="u", wazuh_api_password="p"
)
_UNCONFIGURED_SETTINGS = Settings(wazuh_api_url=None, wazuh_api_username=None, wazuh_api_password=None)


class _FakeWazuhClient:
    def __init__(self, findings=None, error: WazuhError | None = None):
        self._findings = findings or []
        self._error = error
        self.closed = False

    async def get_syscheck_findings(self, *, limit=500):
        if self._error is not None:
            raise self._error
        return self._findings

    async def aclose(self):
        self.closed = True


def _iso(dt: datetime) -> str:
    return dt.isoformat()


@pytest.mark.unit
async def test_not_configured_reports_honest_placeholder_not_fabricated_zeros():
    """A-16 also fixes this console's own pre-existing placeholder bug: the
    stub used to hardcode `0` for every metric even when nothing was
    connected — a false "all clear". `None` is the honest answer, matching
    every other connector-backed console in this stack (CrowdSec/ClamAV)."""
    result = await fetch_logs_console_data(_UNCONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "not_configured"}
    assert result["metrics"] == {
        "events_24h": None,
        "warnings_24h": None,
        "security_errors_24h": None,
        "sources": None,
    }
    assert result["entries"] == []
    assert result["chart"]["values"] == []


@pytest.mark.unit
async def test_unreachable_connector_reports_that_status_and_never_raises(
    monkeypatch: pytest.MonkeyPatch,
):
    fake = _FakeWazuhClient(error=WazuhError("down", reason="unreachable"))
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    result = await fetch_logs_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "unreachable"}
    assert result["metrics"]["events_24h"] is None
    assert fake.closed is True


@pytest.mark.unit
async def test_unauthorized_connector_reports_that_status(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeWazuhClient(error=WazuhError("bad creds", reason="unauthorized"))
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    result = await fetch_logs_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "unauthorized"}


@pytest.mark.unit
async def test_reachable_connector_computes_events_24h_from_recent_fim_findings(
    monkeypatch: pytest.MonkeyPatch,
):
    now = datetime.now(timezone.utc)
    findings = [
        {"file": "/monitored/data/recent.txt", "date": _iso(now - timedelta(hours=1))},
        {"file": "/monitored/logs/assistant.log", "date": _iso(now - timedelta(hours=23))},
        # Outside the 24h window -- must NOT be counted in events_24h, but
        # still present in `entries` (entries shows the most recent N
        # regardless of the 24h cutoff, same "raw recent list" shape
        # crowdsec's recent_attempts uses).
        {"file": "/monitored/data/old.txt", "date": _iso(now - timedelta(days=3))},
    ]
    fake = _FakeWazuhClient(findings=findings)
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    result = await fetch_logs_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["events_24h"] == 2
    assert result["metrics"]["sources"] == 1
    # Honestly not derivable from a manager-only deployment's REST API --
    # see wazuh.py's module docstring for why these stay None even on a
    # fully successful fetch.
    assert result["metrics"]["warnings_24h"] is None
    assert result["metrics"]["security_errors_24h"] is None
    assert len(result["entries"]) == 3
    assert result["entries"][0]["file"] == "/monitored/data/recent.txt"
    assert result["entries"][0]["source"] == "wazuh_fim"
    assert fake.closed is True


@pytest.mark.unit
async def test_reachable_connector_with_zero_findings_is_a_real_zero_not_none(
    monkeypatch: pytest.MonkeyPatch,
):
    """Distinguishes "genuinely queried and found nothing" (real `0`) from
    "could not ask at all" (`None`) — same discipline
    test_crowdsec_ids_console_data.py's equivalent test already applies."""
    fake = _FakeWazuhClient(findings=[])
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    result = await fetch_logs_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["events_24h"] == 0
    assert result["entries"] == []


@pytest.mark.unit
async def test_findings_with_a_missing_or_malformed_date_are_never_counted_or_crash(
    monkeypatch: pytest.MonkeyPatch,
):
    findings = [
        {"file": "/monitored/data/no_date.txt"},  # missing "date" entirely
        {"file": "/monitored/data/bad_date.txt", "date": "not-a-timestamp"},
    ]
    fake = _FakeWazuhClient(findings=findings)
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    result = await fetch_logs_console_data(_CONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "ok"}
    assert result["metrics"]["events_24h"] == 0
    assert len(result["entries"]) == 2  # still listed, just not counted as "recent"
