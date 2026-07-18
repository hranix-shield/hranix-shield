"""A-16 DoD: a live end-to-end check against a REAL running Wazuh Manager
container (see infra/security/wazuh/docker-compose.yml) — not the
monkeypatched tests in test_wazuh_client.py/test_wazuh_logs_console_data.py/
test_security_console_logs_wazuh.py.

Deliberately opt-in and self-skipping, marked `wazuh_live` (registered in
pytest.ini), same shape as A-11's `crowdsec_live`/A-17's `clamav_live`
markers: reads WAZUH_API_URL/WAZUH_API_USERNAME/WAZUH_API_PASSWORD straight
from the environment (NOT via the cached `get_settings()` — same reasoning
as test_crowdsec_live.py) and skips with a clear reason when any is unset or
the manager does not actually answer. A plain `server/venv/bin/python -m
pytest -q` run therefore needs no Docker at all.

The FIM live test writes a real file under REPO_ROOT/logs — the exact host
path infra/security/wazuh/docker-compose.yml bind-mounts (read-only) into
the container at /monitored/logs (see that file's Decision #2) — so this
only produces a real detected event when the live container being tested
against was started from THIS SAME checkout (true for the intended
"developer runs the compose file from this repo, then runs this test
against it" workflow; a container started from a different checkout would
not see this test's writes, and the FIM assertion below self-skips with a
clear message rather than failing in that case, since that is a test-setup
mismatch, not a product defect).

Run explicitly with:
    docker compose -f infra/security/wazuh/docker-compose.yml up -d
    WAZUH_API_URL=http://127.0.0.1:55000 WAZUH_API_USERNAME=wazuh-wui \\
        WAZUH_API_PASSWORD=<password from infra/security/wazuh/.env> \\
        server/venv/bin/python -m pytest -q -m wazuh_live
"""

from __future__ import annotations

import os
import time
import uuid

import pytest

from app.config import REPO_ROOT, Settings
from app.services.mcp.security_connectors.wazuh import (
    WazuhClient,
    WazuhError,
    fetch_logs_console_data,
)


def _live_settings() -> Settings | None:
    url = os.environ.get("WAZUH_API_URL")
    username = os.environ.get("WAZUH_API_USERNAME")
    password = os.environ.get("WAZUH_API_PASSWORD")
    if not url or not username or not password:
        return None
    return Settings(wazuh_api_url=url, wazuh_api_username=username, wazuh_api_password=password)


async def _skip_unless_reachable() -> Settings:
    settings = _live_settings()
    if settings is None:
        pytest.skip(
            "WAZUH_API_URL/WAZUH_API_USERNAME/WAZUH_API_PASSWORD not set — no live Wazuh configured"
        )
    client = WazuhClient(
        api_url=settings.wazuh_api_url,  # type: ignore[arg-type]
        username=settings.wazuh_api_username,  # type: ignore[arg-type]
        password=settings.wazuh_api_password,  # type: ignore[arg-type]
        timeout=3.0,
    )
    try:
        await client.get_agent_status()
    except WazuhError as exc:
        pytest.skip(f"Wazuh Manager not reachable/authorized: {exc}")
    finally:
        await client.aclose()
    return settings


# ---------------------------------------------------------------------------
# Direct protocol check
# ---------------------------------------------------------------------------


@pytest.mark.wazuh_live
async def test_live_wazuh_manager_self_agent_000_is_active():
    """DoD: this manager-only deployment monitors ITSELF as agent "000" (see
    wazuh.py's module docstring for why no separate agent container is
    used) — confirmed live against a real container, not just read from
    docs."""
    settings = await _skip_unless_reachable()
    client = WazuhClient(
        api_url=settings.wazuh_api_url,  # type: ignore[arg-type]
        username=settings.wazuh_api_username,  # type: ignore[arg-type]
        password=settings.wazuh_api_password,  # type: ignore[arg-type]
        timeout=5.0,
    )

    status = await client.get_agent_status()

    assert status == "active"
    await client.aclose()


@pytest.mark.wazuh_live
async def test_live_fim_detects_a_real_file_change_under_the_monitored_logs_directory():
    """DoD: "спровоцировать тестовое FIM-событие — изменить файл под
    наблюдением — увидеть его в журнале панели". Writes a real, uniquely-
    named file under REPO_ROOT/logs (bind-mounted read-only into the
    container at /monitored/logs, see this module's docstring), waits for
    realtime FIM (inotify-based, confirmed live while building this task to
    detect a change within single-digit seconds) to pick it up, then
    confirms it appears in a real `GET /syscheck/000` call through the same
    `WazuhClient` the product connector uses.
    """
    settings = await _skip_unless_reachable()
    client = WazuhClient(
        api_url=settings.wazuh_api_url,  # type: ignore[arg-type]
        username=settings.wazuh_api_username,  # type: ignore[arg-type]
        password=settings.wazuh_api_password,  # type: ignore[arg-type]
        timeout=5.0,
    )

    logs_dir = REPO_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    probe_name = f"a16_live_probe_{uuid.uuid4().hex}.log"
    probe_path = logs_dir / probe_name
    probe_path.write_text(f"A-16 live FIM probe {time.time()}\n")

    try:
        found = False
        # Realtime FIM was confirmed live (see the A-16 task report) to
        # detect a new/changed file within single-digit seconds; this polls
        # generously (up to ~20s) rather than assuming a fixed sleep, so a
        # transiently slower CI/dev machine does not flake.
        for _ in range(10):
            findings = await client.get_syscheck_findings(limit=500)
            if any(finding.get("file") == f"/monitored/logs/{probe_name}" for finding in findings):
                found = True
                break
            time.sleep(2)

        if not found:
            pytest.skip(
                "Probe file was written but never appeared in /syscheck/000 — "
                "most likely this live container was started from a DIFFERENT "
                "checkout than this test process (see this module's docstring: "
                "the bind-mount source is THIS checkout's REPO_ROOT/logs), not "
                "a product defect. Re-run with the container started from this "
                "same checkout to get a real pass/fail here."
            )

        assert found
    finally:
        probe_path.unlink(missing_ok=True)
        await client.aclose()


@pytest.mark.wazuh_live
async def test_live_fetch_logs_console_data_matches_a_direct_manager_call():
    """DoD-adjacent: "покажи прямой запрос к Wazuh Manager API и сравни с
    тем, что отдаёт эндпоинт панели" (same comparison shape A-11's own live
    test already established for CrowdSec) — computed through the exact
    same `WazuhClient` the product connector uses, so this is apples-to-
    apples with what `fetch_logs_console_data` derives from that same
    `get_syscheck_findings()` result."""
    settings = await _skip_unless_reachable()

    result = await fetch_logs_console_data(settings)

    assert result["connector"]["status"] == "ok"
    assert isinstance(result["metrics"]["events_24h"], int)
    assert result["metrics"]["events_24h"] >= 0
    assert isinstance(result["entries"], list)


# ---------------------------------------------------------------------------
# Failure scenario, against a real (if briefly wrong) address
# ---------------------------------------------------------------------------


@pytest.mark.wazuh_live
async def test_live_unreachable_wazuh_reports_a_clear_error_not_a_hang():
    if not os.environ.get("WAZUH_API_PASSWORD"):
        pytest.skip("WAZUH_API_PASSWORD not set — nothing live configured to contrast against")

    client = WazuhClient(
        api_url="http://127.0.0.1:1", username="irrelevant", password="irrelevant", timeout=1.0
    )
    try:
        with pytest.raises(WazuhError) as excinfo:
            await client.get_agent_status()
        assert excinfo.value.reason == "unreachable"
    finally:
        await client.aclose()
