"""A-17: `GET /security/consoles/av`'s `connectors["clamav"]` +
`/security/consoles/av/clamav/{scan/quick,scan/full,scan/full/{job_id},
quarantine}` against the real app wiring (client fixture — real migrated tmp
SQLite DB, real HTTP layer via TestClient, real in-process
`ClamAvScanJobRegistry` on `app.state`), same monkeypatch-the-bare-name
technique test_security_console_network_av.py already uses for osquery.

Most scan/quarantine functions are monkeypatched here (rather than
exercised for real): `run_quick_scan`/`start_full_scan`'s *default* target
directories are the real Downloads/temp/home directories (see clamav.py's
docstrings) — an integration test hitting those for real would depend on
this machine's actual filesystem contents and could write into the real
repo's `data/quarantine/`. That real, non-mocked, filesystem-touching
behavior is exercised deliberately in tests/unit/test_clamav_scan.py (with
explicit `tmp_path` target dirs), tests/integration/test_clamav_live.py
(the DoD's own live EICAR-via-API run against a real Docker `clamd`), and
`test_quarantine_real_wiring_rejects_outside_and_accepts_inside_scan_roots`
below (the one exception: exercises the real `quarantine_file`, including
its real path-scope check, with only `_default_quick_scan_targets`
monkeypatched to a controlled tmp_path root — an architect-review security
finding, 2026-07-16, real enough to be worth a real-wiring test, not just a
status-code mapping check). The rest of this file verifies the router's own
wiring: request/response shape, status-code mapping, and that `GET
/security/consoles/av` surfaces `clamav`'s connector status alongside
osquery's.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.clamav import (
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvQuarantineNotFoundError,
    ClamAvRestoreConflictError,
    ClamdError,
    QuarantineEntry,
    ScanJob,
)
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# GET /security/consoles/av -> connectors["clamav"]
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_av_console_surfaces_clamav_source_when_ok(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_clamav_data(job_registry=None):
        return {
            "connector": {"status": "ok"},
            "engine_version": "1.5.3",
            "database_version": "28059",
            "databases_updated_at": "2026-07-13T06:25:07+00:00",
            "quarantine_count": 2,
            "last_scan_at": "2026-07-16T10:00:00+00:00",
            "clean": True,
        }

    monkeypatch.setattr(security_console_module, "fetch_av_clamav_data", _fake_clamav_data)
    headers = await _admin_headers(client, migrated_session_maker, "clamav_admin")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connectors"]["clamav"] == {"status": "ok"}
    assert body["metrics"]["databases_updated_at"] == "2026-07-13T06:25:07+00:00"
    assert body["metrics"]["quarantine_count"] == 2
    assert body["metrics"]["last_scan_at"] == "2026-07-16T10:00:00+00:00"
    assert body["metrics"]["clean"] is True


# ---------------------------------------------------------------------------
# POST /security/consoles/av/clamav/scan/quick
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_quick_scan_returns_a_completed_job_on_success(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_run_quick_scan(**kwargs):
        return {
            "scanned_count": 3,
            "infected": [{"path": "/tmp/eicar.txt", "signature": "Eicar-Test-Signature"}],
            "target_dirs": ["/tmp"],
        }

    monkeypatch.setattr(security_console_module, "run_quick_scan", _fake_run_quick_scan)
    headers = await _admin_headers(client, migrated_session_maker, "quick_scan_admin")

    response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "quick"
    assert body["status"] == "completed"
    assert body["scanned_count"] == 3
    assert body["infected"] == [{"path": "/tmp/eicar.txt", "signature": "Eicar-Test-Signature"}]


@pytest.mark.integration
async def test_quick_scan_returns_503_when_not_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_configured(**kwargs):
        raise ClamAvNotConfiguredError("clamav_enabled is off")

    monkeypatch.setattr(security_console_module, "run_quick_scan", _raise_not_configured)
    headers = await _admin_headers(client, migrated_session_maker, "quick_scan_admin_nc")

    response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_quick_scan_returns_503_when_clamd_unreachable(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_unreachable(**kwargs):
        raise ClamdError("connection refused", reason="unreachable")

    monkeypatch.setattr(security_console_module, "run_quick_scan", _raise_unreachable)
    headers = await _admin_headers(client, migrated_session_maker, "quick_scan_admin_unreach")

    response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_unreachable"}


# ---------------------------------------------------------------------------
# A-33: POST /security/consoles/av/clamav/scan/custom
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_custom_scan_returns_a_completed_job_with_the_scanned_path(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_run_custom_scan(path, **kwargs):
        return {"scanned_count": 4, "infected": [], "path": str(path)}

    monkeypatch.setattr(security_console_module, "run_custom_scan", _fake_run_custom_scan)
    headers = await _admin_headers(client, migrated_session_maker, "custom_scan_admin")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": "/home/user/Downloads/project"},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["kind"] == "custom"
    assert body["status"] == "completed"
    assert body["scanned_count"] == 4
    assert body["infected"] == []
    assert body["path"] == "/home/user/Downloads/project"


@pytest.mark.integration
@pytest.mark.integration
async def test_custom_scan_returns_404_for_a_missing_path(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_found(path, **kwargs):
        raise FileNotFoundError(str(path))

    monkeypatch.setattr(security_console_module, "run_custom_scan", _raise_not_found)
    headers = await _admin_headers(client, migrated_session_maker, "custom_scan_admin_404")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": "/home/user/Downloads/does-not-exist"},
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "scan_path_not_found"}


@pytest.mark.integration
async def test_custom_scan_returns_503_when_not_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_configured(path, **kwargs):
        raise ClamAvNotConfiguredError("clamav_enabled is off")

    monkeypatch.setattr(security_console_module, "run_custom_scan", _raise_not_configured)
    headers = await _admin_headers(client, migrated_session_maker, "custom_scan_admin_nc")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": "/home/user/Downloads/project"},
        headers=headers,
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_custom_scan_returns_503_when_clamd_unreachable(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_unreachable(path, **kwargs):
        raise ClamdError("connection refused", reason="unreachable")

    monkeypatch.setattr(security_console_module, "run_custom_scan", _raise_unreachable)
    headers = await _admin_headers(client, migrated_session_maker, "custom_scan_admin_unreach")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": "/home/user/Downloads/project"},
        headers=headers,
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_unreachable"}


@pytest.mark.integration
async def test_custom_scan_real_wiring_has_no_root_restriction(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
):
    """Post-merge user finding (2026-08-02): drives the REAL
    `run_custom_scan` (not monkeypatched) through the real HTTP endpoint —
    a path FAR outside the old `_known_scan_roots()` allowlist (this
    tmp_path is nowhere near the real Downloads/home/OS temp dir) must NOT
    be rejected with 403 `path_outside_scan_roots` anymore (that whole
    check is gone for this endpoint, see `run_custom_scan`'s own
    docstring) — it must reach the next real, honest stage instead: clamd
    not configured in this test environment (`CLAMAV_ENABLED=False`, see
    conftest.py) — 503 `clamav_not_configured`, never 403.

    Deliberately does NOT stand up `tests/common/fake_clamd.py` here — see
    the equivalent quarantine real-wiring test's own docstring for why a
    `TestClient.post()`-driven request starves that in-process fake
    server's event loop (confirmed empirically); the full success path
    (real detection + persisted history) is covered separately by
    tests/integration/test_clamav_live.py against this dev machine's real
    container.
    """
    outside_dir = tmp_path / "definitely-not-in-any-allowlist"
    outside_dir.mkdir()
    headers = await _admin_headers(client, migrated_session_maker, "custom_scan_admin_real")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": str(outside_dir)},
        headers=headers,
    )

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


# ---------------------------------------------------------------------------
# A-33: GET /security/consoles/av/clamav/scan/history
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_scan_history_is_honestly_empty_when_nothing_has_scanned_yet(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "scan_history_admin_empty")

    response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"items": []}


@pytest.mark.integration
async def test_scan_history_reflects_a_real_quick_scan(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Confirms `POST .../scan/quick` and `GET .../scan/history` are wired
    to the SAME persistent table — not just that each endpoint responds
    honestly on its own."""

    async def _fake_run_quick_scan(**kwargs):
        return {
            "scanned_count": 7,
            "infected": [{"path": "/tmp/eicar.txt", "signature": "Eicar-Test-Signature"}],
            "target_dirs": ["/tmp"],
        }

    monkeypatch.setattr(security_console_module, "run_quick_scan", _fake_run_quick_scan)
    headers = await _admin_headers(client, migrated_session_maker, "scan_history_admin_quick")

    scan_response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)
    assert scan_response.status_code == 200

    history_response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)

    assert history_response.status_code == 200
    items = history_response.json()["items"]
    assert len(items) == 1
    assert items[0]["scan_type"] == "quick"
    assert items[0]["path"] is None
    assert items[0]["scanned_count"] == 7
    assert items[0]["infected_count"] == 1


@pytest.mark.integration
async def test_scan_history_survives_a_fresh_dependency_override(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """A-33's own DoD: scan history must be REAL persistence (a DB row),
    not process-memory state like `ClamAvScanJobRegistry` — this test
    writes a row directly via the app's own migrated DB (bypassing the HTTP
    layer entirely) and confirms `GET .../scan/history` reads it back,
    the same round trip a server restart would also have to survive (the
    live DoD check restarts the real process; this is the fast, in-process
    equivalent: a completely fresh `AsyncSession` from the very same
    session maker, proving the row lives in the DB file, not in any
    Python object)."""
    from datetime import datetime

    from app.services.mcp.security_connectors.clamav import record_scan_history

    async with migrated_session_maker() as session:
        await record_scan_history(
            session,
            scan_type="full",
            path=None,
            scanned_count=42,
            infected_count=0,
            started_at=datetime(2026, 7, 19, 8, 0, 0),
            finished_at=datetime(2026, 7, 19, 8, 5, 0),
        )

    headers = await _admin_headers(client, migrated_session_maker, "scan_history_admin_persist")
    response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["scan_type"] == "full"
    assert items[0]["scanned_count"] == 42


# ---------------------------------------------------------------------------
# POST /security/consoles/av/clamav/scan/full + polling
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_full_scan_start_returns_a_running_job_immediately(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_start_full_scan(registry, **kwargs):
        return ScanJob(id="fixed-job-id", kind="full", status="running")

    monkeypatch.setattr(security_console_module, "start_full_scan", _fake_start_full_scan)
    headers = await _admin_headers(client, migrated_session_maker, "full_scan_admin")

    response = client.post("/security/consoles/av/clamav/scan/full", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "fixed-job-id"
    assert body["kind"] == "full"
    assert body["status"] == "running"


@pytest.mark.integration
async def test_full_scan_start_returns_503_when_not_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_configured(registry, **kwargs):
        raise ClamAvNotConfiguredError("clamav_enabled is off")

    monkeypatch.setattr(security_console_module, "start_full_scan", _raise_not_configured)
    headers = await _admin_headers(client, migrated_session_maker, "full_scan_admin_nc")

    response = client.post("/security/consoles/av/clamav/scan/full", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_full_scan_status_returns_404_for_an_unknown_job_id(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    headers = await _admin_headers(client, migrated_session_maker, "full_scan_poll_admin")

    response = client.get(
        "/security/consoles/av/clamav/scan/full/does-not-exist", headers=headers
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "scan_job_not_found"}


@pytest.mark.integration
async def test_full_scan_status_reflects_a_real_job_from_the_apps_own_registry(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """Unlike the tests above (which monkeypatch `start_full_scan` itself),
    this one drives the app's real `app.state.clamav_scan_job_registry`
    directly — confirming the poll endpoint reads from the *same* registry
    instance the app actually wires up (see app_factory.py), not a
    per-request throwaway."""
    headers = await _admin_headers(client, migrated_session_maker, "full_scan_poll_admin_real")

    registry = client.app.state.clamav_scan_job_registry
    job = registry.create("full")
    registry.mark_completed(job, scanned_count=7, infected=[])

    response = client.get(f"/security/consoles/av/clamav/scan/full/{job.id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == job.id
    assert body["status"] == "completed"
    assert body["scanned_count"] == 7


# ---------------------------------------------------------------------------
# POST /security/consoles/av/clamav/quarantine
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_quarantine_returns_the_new_path_on_success(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_quarantine_file(path, **kwargs):
        return path.parent / "quarantine" / f"quarantined_{path.name}"

    monkeypatch.setattr(security_console_module, "quarantine_file", _fake_quarantine_file)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_admin")

    response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": "/tmp/suspicious.exe"},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["quarantined_path"].endswith("quarantined_suspicious.exe")


@pytest.mark.integration
async def test_quarantine_returns_404_for_a_missing_file(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_found(path, **kwargs):
        raise FileNotFoundError(str(path))

    monkeypatch.setattr(security_console_module, "quarantine_file", _raise_not_found)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_admin_404")

    response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": "/tmp/does-not-exist.exe"},
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "file_not_found"}


@pytest.mark.integration
async def test_quarantine_returns_403_for_a_path_outside_scan_roots(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Security finding (architect review, 2026-07-16): the router must map
    `ClamAvPathNotAllowedError` to an honest 403, not let an arbitrary path
    (e.g. `/etc/passwd`) reach `shutil.move`."""

    async def _raise_not_allowed(path, **kwargs):
        raise ClamAvPathNotAllowedError(str(path))

    monkeypatch.setattr(security_console_module, "quarantine_file", _raise_not_allowed)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_admin_403")

    response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": "/etc/passwd"},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "path_outside_scan_roots"}


@pytest.mark.integration
async def test_quarantine_real_wiring_rejects_outside_and_accepts_inside_scan_roots(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """Unlike every other test in this file (which monkeypatches
    `quarantine_file` itself), this one drives the REAL `quarantine_file` —
    including its real path-scope check — through the real HTTP endpoint.
    Only `_default_quick_scan_targets` is monkeypatched (to a controlled
    tmp_path root instead of the real Downloads/OS temp dir), so this is a
    true regression test for the fix, not just a router-level status-code
    mapping check.
    """
    import app.services.mcp.security_connectors.clamav as clamav_module

    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])
    monkeypatch.setattr(
        clamav_module,
        "get_settings",
        lambda: clamav_module.Settings(clamav_quarantine_dir=str(tmp_path / "quarantine")),
    )

    outside_file = tmp_path / "outside.exe"
    outside_file.write_bytes(b"do not move me")
    inside_file = allowed_root / "eicar.txt"
    inside_file.write_bytes(b"move me")

    headers = await _admin_headers(client, migrated_session_maker, "quarantine_admin_real")

    outside_response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(outside_file)},
        headers=headers,
    )
    assert outside_response.status_code == 403
    assert outside_response.json()["detail"] == {"error": "path_outside_scan_roots"}
    assert outside_file.exists()  # never moved

    inside_response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(inside_file)},
        headers=headers,
    )
    assert inside_response.status_code == 200
    assert not inside_file.exists()  # actually moved this time
    quarantined_path = inside_response.json()["quarantined_path"]
    assert quarantined_path.endswith("_eicar.txt")


# ---------------------------------------------------------------------------
# A-27: GET /security/consoles/av/clamav/quarantine (list)
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_quarantine_list_returns_items_from_the_real_connector_shape(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    def _fake_list_quarantine_entries(settings=None):
        return [
            QuarantineEntry(
                id="abc123",
                quarantined_path="/data/quarantine/abc123_eicar.txt",
                original_path="/home/user/Downloads/eicar.txt",
                reason="Eicar-Test-Signature",
                quarantined_at="2026-07-19T10:00:00+00:00",
            )
        ]

    monkeypatch.setattr(
        security_console_module, "list_quarantine_entries", _fake_list_quarantine_entries
    )
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_list_admin")

    response = client.get("/security/consoles/av/clamav/quarantine", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["items"] == [
        {
            "id": "abc123",
            "quarantined_path": "/data/quarantine/abc123_eicar.txt",
            "original_path": "/home/user/Downloads/eicar.txt",
            "reason": "Eicar-Test-Signature",
            "quarantined_at": "2026-07-19T10:00:00+00:00",
        }
    ]


@pytest.mark.integration
async def test_quarantine_list_is_honestly_empty_when_nothing_is_quarantined(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(security_console_module, "list_quarantine_entries", lambda settings=None: [])
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_list_admin_empty")

    response = client.get("/security/consoles/av/clamav/quarantine", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"items": []}


@pytest.mark.integration
async def test_quarantine_list_real_wiring_reflects_a_real_quarantined_file(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """Unlike the two tests above (monkeypatched), this one drives the real
    `quarantine_file` -> real `list_quarantine_entries` round trip through
    the real HTTP endpoints, confirming the list genuinely reflects what
    `quarantine_file` wrote to disk, not just the router's own status-code
    mapping."""
    import app.services.mcp.security_connectors.clamav as clamav_module

    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    settings = clamav_module.Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])
    monkeypatch.setattr(clamav_module, "get_settings", lambda: settings)

    source = allowed_root / "eicar.txt"
    source.write_bytes(b"move me")
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_list_admin_real")

    quarantine_response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(source), "reason": "Eicar-Test-Signature"},
        headers=headers,
    )
    assert quarantine_response.status_code == 200

    list_response = client.get("/security/consoles/av/clamav/quarantine", headers=headers)

    assert list_response.status_code == 200
    items = list_response.json()["items"]
    assert len(items) == 1
    assert items[0]["original_path"] == str(source.resolve())
    assert items[0]["reason"] == "Eicar-Test-Signature"


# ---------------------------------------------------------------------------
# A-27: POST /security/consoles/av/clamav/quarantine/{item_id}/restore
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_quarantine_restore_returns_the_restored_path_on_success(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _fake_restore(item_id, **kwargs):
        assert item_id == "abc123"
        return Path("/home/user/Downloads/eicar.txt")

    monkeypatch.setattr(security_console_module, "restore_quarantine_file", _fake_restore)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_restore_admin")

    response = client.post(
        "/security/consoles/av/clamav/quarantine/abc123/restore", headers=headers
    )

    assert response.status_code == 200
    assert response.json()["restored_path"] == "/home/user/Downloads/eicar.txt"


@pytest.mark.integration
async def test_quarantine_restore_returns_404_for_an_unknown_item(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_not_found(item_id, **kwargs):
        raise ClamAvQuarantineNotFoundError(item_id)

    monkeypatch.setattr(security_console_module, "restore_quarantine_file", _raise_not_found)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_restore_admin_404")

    response = client.post(
        "/security/consoles/av/clamav/quarantine/does-not-exist/restore", headers=headers
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "quarantine_item_not_found"}


@pytest.mark.integration
async def test_quarantine_restore_returns_409_on_a_restore_path_conflict(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raise_conflict(item_id, **kwargs):
        raise ClamAvRestoreConflictError("/home/user/Downloads/eicar.txt")

    monkeypatch.setattr(security_console_module, "restore_quarantine_file", _raise_conflict)
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_restore_admin_409")

    response = client.post(
        "/security/consoles/av/clamav/quarantine/abc123/restore", headers=headers
    )

    assert response.status_code == 409
    assert response.json()["detail"] == {"error": "restore_path_conflict"}


@pytest.mark.integration
async def test_quarantine_restore_real_wiring_moves_the_file_back_to_disk(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """Real `quarantine_file` -> real `restore_quarantine_file` round trip
    through the real HTTP endpoints — the DoD's own "восстановлен... файл
    реально вернулся на исходный путь на диске" check, at the router level
    (the connector-level equivalent already lives in
    tests/unit/test_clamav_scan.py)."""
    import app.services.mcp.security_connectors.clamav as clamav_module

    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    settings = clamav_module.Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])
    monkeypatch.setattr(clamav_module, "get_settings", lambda: settings)

    source = allowed_root / "eicar.txt"
    source.write_bytes(b"move me")
    headers = await _admin_headers(client, migrated_session_maker, "quarantine_restore_admin_real")

    quarantine_response = client.post(
        "/security/consoles/av/clamav/quarantine", json={"path": str(source)}, headers=headers
    )
    assert quarantine_response.status_code == 200
    assert not source.exists()  # really moved into quarantine

    item_id = client.get(
        "/security/consoles/av/clamav/quarantine", headers=headers
    ).json()["items"][0]["id"]

    restore_response = client.post(
        f"/security/consoles/av/clamav/quarantine/{item_id}/restore", headers=headers
    )

    assert restore_response.status_code == 200
    assert restore_response.json()["restored_path"] == str(source.resolve())
    # The DoD-relevant assertion: a real filesystem check, not just the
    # HTTP response body.
    assert source.exists()
    assert source.read_bytes() == b"move me"


# ---------------------------------------------------------------------------
# A-27: POST /security/consoles/av/clamav/reload
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_reload_returns_503_when_not_configured(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(security_console_module, "create_clamav_client", lambda: None)
    headers = await _admin_headers(client, migrated_session_maker, "reload_admin_nc")

    response = client.post("/security/consoles/av/clamav/reload", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_reload_returns_503_when_clamd_unreachable(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    class _FailingClient:
        async def reload(self):
            raise ClamdError("connection refused", reason="unreachable")

    monkeypatch.setattr(security_console_module, "create_clamav_client", lambda: _FailingClient())
    headers = await _admin_headers(client, migrated_session_maker, "reload_admin_unreach")

    response = client.post("/security/consoles/av/clamav/reload", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_unreachable"}


@pytest.mark.integration
async def test_reload_returns_reloaded_true_on_success(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    class _OkClient:
        async def reload(self):
            return None

    monkeypatch.setattr(security_console_module, "create_clamav_client", lambda: _OkClient())
    headers = await _admin_headers(client, migrated_session_maker, "reload_admin_ok")

    response = client.post("/security/consoles/av/clamav/reload", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"reloaded": True}
