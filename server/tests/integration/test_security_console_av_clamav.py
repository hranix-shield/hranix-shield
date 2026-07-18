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

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.services.mcp.security_connectors.clamav import (
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamdError,
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
