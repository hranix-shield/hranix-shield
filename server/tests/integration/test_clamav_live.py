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
async def test_live_clamd_reload_answers_reloading():
    """A-27 DoD: "клик «Перечитать базы» → подтверди реальный RELOAD-ответ
    от clamd" — the lowest-level half of that check, direct protocol call
    against the real `hranix-clamav` container (the HTTP-level equivalent
    is covered below, same split `test_live_clamd_ping_and_version_answer`
    /`test_live_quick_scan_via_the_real_http_api_detects_eicar` already
    establish for PING/quick-scan)."""
    settings = await _skip_unless_reachable()
    client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port, timeout=3.0)

    await client.reload()  # must not raise — clamd answered "RELOADING"


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


# ---------------------------------------------------------------------------
# A-33: POST /security/consoles/av/clamav/scan/custom against the real
# container + GET /security/consoles/av/clamav/scan/history
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_custom_scan_via_the_real_http_api_detects_eicar_and_persists_history(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """DoD: "ввод пути внутри разрешённого корня → реальный скан именно
    этой папки" against a REAL `clamd` (not the in-process fake — see
    tests/integration/test_security_console_av_clamav.py's own real-wiring
    test for why that one is scoped to path-validation only). Also
    confirms the `scan_history` row this task's own brief requires is
    really written — the DoD's "таблица истории показывает реальные
    записи" check, at the HTTP level.
    """
    settings = await _skip_unless_reachable()
    monkeypatch.setattr(clamav_module, "get_settings", lambda: settings)

    fake_home = tmp_path / "fake-home"
    project_dir = fake_home / "project"
    project_dir.mkdir(parents=True)
    eicar_path = project_dir / "eicar.txt"
    eicar_path.write_bytes(_EICAR)
    (project_dir / "clean.txt").write_bytes(b"nothing to see here")
    # A-33's own `_known_scan_roots()` includes `_default_full_scan_targets()`
    # (`Path.home()`) — patched the same way
    # test_live_quick_scan_via_the_real_http_api_detects_eicar already
    # patches it for quick scan's Downloads target, so `project_dir` (under
    # this fake home) is a real, allowed custom-scan target.
    monkeypatch.setattr(clamav_module.Path, "home", classmethod(lambda cls: fake_home))

    await create_user(
        migrated_session_maker, username="clamav_live_custom_admin", password="pw", role="admin"
    )
    token = client.post(
        "/auth/login", json={"username": "clamav_live_custom_admin", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Traversal attempt, still honestly rejected against the real container
    # too (the scope check runs before clamd is ever contacted). Climbs a
    # generous 20 levels of `..` (clamped at the real filesystem root by
    # `.resolve()`, however deep `tmp_path` itself happens to live) before
    # descending into `/etc/passwd` — a real absolute path that is safely
    # outside `fake_home` AND outside the real OS temp dir (this file's
    # OTHER active default root, see `test_live_quick_scan_via_the_real_http_api_detects_eicar`'s
    # own comment on why that one is never patched away here). A plain
    # `fake_home / ".." / "something"` is NOT safe for this: `tmp_path`
    # itself already lives under the real OS temp dir on this dev machine,
    # so climbing just one level would still land inside an allowed root.
    traversal_path = project_dir.joinpath(*([".."] * 20), "etc", "passwd")
    traversal_response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": str(traversal_path)},
        headers=headers,
    )
    assert traversal_response.status_code == 403
    assert traversal_response.json()["detail"] == {"error": "path_outside_scan_roots"}

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": str(project_dir)},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "completed"
    assert body["kind"] == "custom"
    assert body["scanned_count"] == 2
    matching = [entry for entry in body["infected"] if entry["path"] == str(eicar_path)]
    assert matching, f"expected {eicar_path} to be reported infected, got: {body['infected']}"
    assert matching[0]["signature"] == "Eicar-Test-Signature"

    # The DoD's own restart-survival contract, at the persistence layer:
    # this row lives in the DB, not in ClamAvScanJobRegistry's process
    # memory — confirmed here by reading it back through the real endpoint.
    history_response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)
    assert history_response.status_code == 200
    items = history_response.json()["items"]
    matching_history = [item for item in items if item.get("path") == str(project_dir.resolve())]
    assert matching_history, f"expected a scan_history row for {project_dir}, got: {items}"
    assert matching_history[0]["scan_type"] == "custom"
    assert matching_history[0]["scanned_count"] == 2
    assert matching_history[0]["infected_count"] == 1


# ---------------------------------------------------------------------------
# A-27: POST /security/consoles/av/clamav/reload against the real container
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_reload_via_the_real_http_api_answers_reloaded(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """DoD: "клик «Перечитать базы» → подтверди реальный RELOAD-ответ от
    clamd" — this test drives the real HTTP endpoint against the real
    `hranix-clamav` container, not just the raw protocol call (that one is
    `test_live_clamd_reload_answers_reloading` above)."""
    settings = await _skip_unless_reachable()
    monkeypatch.setattr(clamav_module, "get_settings", lambda: settings)

    await create_user(migrated_session_maker, username="clamav_live_reload_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "clamav_live_reload_admin", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post("/security/consoles/av/clamav/reload", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"reloaded": True}


# ---------------------------------------------------------------------------
# A-27: quarantine -> list -> restore round trip against the real container
# ---------------------------------------------------------------------------


@pytest.mark.clamav_live
async def test_live_quarantine_then_restore_round_trip_via_the_real_http_api(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
):
    """DoD: "файл реально вернулся на исходный путь на диске" — quarantines
    a real file via the real HTTP endpoint, confirms it shows up in the
    real `GET .../quarantine` list, restores it via the real HTTP endpoint,
    and checks the filesystem directly (not just the response body) for
    the restored file. `clamd` reachability is not actually exercised by
    quarantine/restore themselves (pure filesystem operations), but this
    lives here (not in test_security_console_av_clamav.py) to match this
    task's own "перечитать/карантин" live-container DoD grouping.
    """
    settings = await _skip_unless_reachable()
    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    quarantine_settings = clamav_module.Settings(
        clamav_enabled=settings.clamav_enabled,
        clamav_host=settings.clamav_host,
        clamav_port=settings.clamav_port,
        clamav_quarantine_dir=str(tmp_path / "quarantine"),
    )
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])
    monkeypatch.setattr(clamav_module, "get_settings", lambda: quarantine_settings)

    source = allowed_root / "eicar.txt"
    source.write_bytes(_EICAR)

    await create_user(migrated_session_maker, username="clamav_live_quarantine_admin", password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": "clamav_live_quarantine_admin", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    quarantine_response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(source), "reason": "Eicar-Test-Signature"},
        headers=headers,
    )
    assert quarantine_response.status_code == 200
    assert not source.exists()  # really moved into quarantine

    list_response = client.get("/security/consoles/av/clamav/quarantine", headers=headers)
    assert list_response.status_code == 200
    items = list_response.json()["items"]
    assert len(items) == 1
    assert items[0]["original_path"] == str(source.resolve())
    item_id = items[0]["id"]

    restore_response = client.post(
        f"/security/consoles/av/clamav/quarantine/{item_id}/restore", headers=headers
    )
    assert restore_response.status_code == 200
    assert restore_response.json()["restored_path"] == str(source.resolve())
    # The DoD-relevant assertion: real filesystem check, not just the HTTP
    # response body.
    assert source.exists()
    assert source.read_bytes() == _EICAR
