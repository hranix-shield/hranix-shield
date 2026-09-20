"""A-30: `trigger_syscheck_scan` — the assembler behind
`POST /security/consoles/logs/wazuh/syscheck`'s real (non-stub) on-demand FIM
rescan action. Exercised here against a fake `WazuhClient` (monkeypatched in
via `create_wazuh_client`, same technique test_wazuh_logs_console_data.py
already uses for the read path) so these unit tests need neither Docker nor
a network call. Live-container coverage lives in
tests/integration/test_wazuh_live.py, marked `wazuh_live`.
"""

import pytest

import app.services.mcp.security_connectors.wazuh as wazuh_module
from app.config import Settings
from app.services.mcp.security_connectors.wazuh import (
    WazuhError,
    WazuhNotConfiguredError,
    trigger_syscheck_scan,
)

_CONFIGURED_SETTINGS = Settings(
    wazuh_api_url="http://wazuh.test:55000", wazuh_api_username="u", wazuh_api_password="p"
)
_UNCONFIGURED_SETTINGS = Settings(wazuh_api_url=None, wazuh_api_username=None, wazuh_api_password=None)


class _FakeWazuhClient:
    def __init__(self, affected=None, error: WazuhError | None = None):
        self._affected = affected if affected is not None else []
        self._error = error
        self.closed = False

    async def trigger_syscheck(self):
        if self._error is not None:
            raise self._error
        return self._affected

    async def aclose(self):
        self.closed = True


@pytest.mark.unit
async def test_raises_not_configured_when_wazuh_is_not_set_up():
    with pytest.raises(WazuhNotConfiguredError):
        await trigger_syscheck_scan(_UNCONFIGURED_SETTINGS)


@pytest.mark.unit
async def test_returns_affected_agent_ids_on_success(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeWazuhClient(affected=["003"])
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    affected = await trigger_syscheck_scan(_CONFIGURED_SETTINGS)

    assert affected == ["003"]
    assert fake.closed is True


@pytest.mark.unit
async def test_propagates_wazuh_error_and_still_closes_the_client(monkeypatch: pytest.MonkeyPatch):
    fake = _FakeWazuhClient(error=WazuhError("down", reason="unreachable"))
    monkeypatch.setattr(wazuh_module, "create_wazuh_client", lambda settings: fake)

    with pytest.raises(WazuhError) as excinfo:
        await trigger_syscheck_scan(_CONFIGURED_SETTINGS)

    assert excinfo.value.reason == "unreachable"
    assert fake.closed is True
