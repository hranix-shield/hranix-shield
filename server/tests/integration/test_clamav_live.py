"""A-17 DoD: a live end-to-end check against a REAL running `clamd`
container (see infra/security/clamav/docker-compose.yml) — not the
monkeypatched tests in test_clamav_client.py/test_clamav_scan.py/
test_security_console_av_clamav.py.

Deliberately opt-in and self-skipping, marked `clamav_live` (registered in
pytest.ini), same shape as A-11's `crowdsec_live`/A-15's `osquery_live`
markers: reads CLAMAV_HOST/CLAMAV_PORT straight from the environment (NOT
via the cached `get_settings()` — same reasoning as `test_crowdsec_live.py`)
and skips with a clear reason when either is unset or `clamd` does not
actually answer PING. A plain `server/venv/bin/python -m pytest -q` run
therefore needs no Docker at all.

Run explicitly with:
    docker compose -f infra/security/clamav/docker-compose.yml up -d
    CLAMAV_HOST=127.0.0.1 CLAMAV_PORT=3310 \\
        server/venv/bin/python -m pytest -q -m clamav_live
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.services.mcp.security_connectors.clamav as clamav_module
from app.config import Settings
from app.services.mcp.security_connectors.clamav import ClamdClient, ClamdError, run_quick_scan
from tests.common.factories import create_user

_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _live_settings() -> Settings | None:
    host = os.environ.get("CLAMAV_HOST")
    port = os.environ.get("CLAMAV_PORT")
    if not host or not port:
        return None
    return Settings(clamav_enabled=True, clamav_host=host, clamav_port=int(port))


async def _skip_unless_reachable() -> Settings:
    settings = _live_settings()
    if settings is None:
        pytest.skip("CLAMAV_HOST/CLAMAV_PORT not set — no live clamd configured")
    client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port, timeout=3.0)
    try:
        await client.ping()
    except ClamdError as exc:
        pytest.skip(f"clamd not reachable: {exc}")
    return settings


# ---------------------------------------------------------------------------
# Direct protocol check
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_clamd_ping_and_version_answer():
    settings = await _skip_unless_reachable()
    client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port, timeout=3.0)

    await client.ping()  # must not raise
    version = await client.version()

    assert version.startswith("ClamAV")


@pytest.mark.clamav_live
async def test_live_clamd_detects_the_eicar_test_string_via_instream():
    """DoD: "проверки быстрая/полная... реально сканирует и детектит...
    EICAR-файл". This is the lowest-level half of that check: the raw
    `INSTREAM` protocol call against a real `clamd`, independent of this
    connector's own directory-walking/API layer (covered separately below)."""
    settings = await _skip_unless_reachable()
    client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port, timeout=5.0)

    result = await client.scan_bytes(_EICAR)

    assert result.status == "infected"
    assert result.signature == "Eicar-Test-Signature"

    clean_result = await client.scan_bytes(b"this is definitely not a virus\n")
    assert clean_result.status == "clean"


# ---------------------------------------------------------------------------
# run_quick_scan against a real tmp directory containing an EICAR file
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_quick_scan_detects_an_eicar_file_on_disk(tmp_path):
    """The connector-level engine (`run_quick_scan`, the exact function
    `POST /security/consoles/av/clamav/scan/quick` calls) against a real
    `clamd`: writes a real EICAR file to `tmp_path`, points the scan at that
    directory, and asserts it comes back `infected`."""
    settings = await _skip_unless_reachable()
    (tmp_path / "clean.txt").write_bytes(b"nothing to see here")
    eicar_path = tmp_path / "eicar.txt"
    eicar_path.write_bytes(_EICAR)

    result = await run_quick_scan(settings=settings, target_dirs=[tmp_path])

    assert result["scanned_count"] == 2
    assert len(result["infected"]) == 1
    assert result["infected"][0]["signature"] == "Eicar-Test-Signature"
    assert Path(result["infected"][0]["path"]) == eicar_path


# ---------------------------------------------------------------------------
# The actual HTTP API: POST /security/consoles/av/clamav/scan/quick
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_quick_scan_via_the_real_http_api_detects_eicar(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """DoD, taken literally: "ручной запуск быстрой проверки через API
    реально сканирует и детектит... EICAR-файл" — this test drives the real
    HTTP endpoint (not the Python function directly, see the test above),
    against a real `clamd`, exercising the real default-target-resolution
    code path (`_default_quick_scan_targets`), not an explicit override.

    `Path.home()` is monkeypatched to a throwaway `tmp_path`-based directory
    (NOT the real OS temp dir or this machine's real ~/Downloads) so the
    EICAR file this test plants is the ONLY thing quick scan finds —
    deterministic and isolated from whatever else happens to be on this
    machine. An earlier version of this test wrote directly into the real
    `tempfile.gettempdir()` and turned out flaky live: on this dev machine
    that directory holds ~1,000 top-level files from unrelated processes,
    which could starve the 50-file-per-directory cap before ever reaching
    the freshly written EICAR file — the actual bug this finding led to
    fixing is `_iter_scan_candidates`'s cap now being per-directory, not
    shared (see that function's docstring); this test's own isolation is a
    separate, additional fix so the test itself no longer depends on the
    real machine's clutter either way.
    """
    settings = await _skip_unless_reachable()
    # `run_quick_scan()` (called with no explicit `settings`, exactly like
    # the router does) resolves via `get_settings()` — monkeypatched here to
    # the live settings for the duration of this one test, same technique
    # test_crowdsec_live.py avoids needing by testing the client directly;
    # an HTTP-level DoD check needs the app's own call path to see them.
    monkeypatch.setattr(clamav_module, "get_settings", lambda: settings)

    fake_home = tmp_path / "fake-home"
    downloads_dir = fake_home / "Downloads"
    downloads_dir.mkdir(parents=True)
    eicar_path = downloads_dir / "eicar.txt"
    eicar_path.write_bytes(_EICAR)
    (downloads_dir / "clean.txt").write_bytes(b"nothing to see here")
    monkeypatch.setattr(clamav_module.Path, "home", classmethod(lambda cls: fake_home))

    await create_user(migrated_session_maker, username="clamav_live_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "clamav_live_admin", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    # >= 2, not == 2: the OS temp dir is quick scan's *other* default
    # target (see clamav.py._default_quick_scan_targets) and is NOT
    # isolated by this test's Path.home() patch — whatever loose top-level
    # files this real dev machine's real temp dir happens to have get
    # scanned too. The DoD-relevant assertion is that OUR EICAR file
    # specifically got flagged, checked below, not an exact total count.
    assert body["scanned_count"] >= 2
    matching = [entry for entry in body["infected"] if entry["path"] == str(eicar_path)]
    assert matching, (
        f"expected {eicar_path} to be reported infected, got: {body['infected']}"
    )
    assert matching[0]["signature"] == "Eicar-Test-Signature"

    # GET /security/consoles/av now reflects this real scan too.
    av_response = client.get("/security/consoles/av", headers=headers)
    assert av_response.status_code == 200
    av_body = av_response.json()
    assert av_body["connectors"]["clamav"]["status"] == "ok"
    assert av_body["metrics"]["clean"] is False
    assert av_body["metrics"]["last_scan_at"] is not None
