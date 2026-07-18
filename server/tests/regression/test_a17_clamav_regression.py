"""A-17 regression anchor.

Per docs/инструкция-разработка-фаза-0-стек-безопасности-2026-07-16.md, this
task adds at least one regression test that must stay green through the rest
of Phase 0 (and beyond, alongside the A-10/A-11/A-15/A-18 anchors). Pins the
core A-17 contract a later A-16 (Wazuh, `av`'s third source) must not break:
  - `av`'s response always carries a `connectors` dict with (at least) the
    `osquery` AND `clamav` source ids, each with a `status` field;
  - `av`'s `metrics.databases_updated_at`/`quarantine_count`/`last_scan_at`/
    `clean` are always-present keys, honestly `None` when ClamAV is not
    configured/reachable — never a fabricated "0 threats found";
  - the four `/security/consoles/av/clamav/*` endpoints (quick scan, full
    scan start, full scan status, quarantine) all require a bearer token and
    never 500, even when `clamav_enabled` is off (the Phase 0 default);
  - neither `av` nor any clamav endpoint ever raises/500s when the ClamAV
    connector is failing — the "честный пустой экран" contract A-11/A-15/
    A-18 established extends here too.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user

_KNOWN_CONNECTOR_STATUSES = {"ok", "not_configured", "permission_denied", "unreachable", "unauthorized"}


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
@pytest.mark.parametrize(
    "method,route",
    [
        ("POST", "/security/consoles/av/clamav/scan/quick"),
        ("POST", "/security/consoles/av/clamav/scan/full"),
        ("GET", "/security/consoles/av/clamav/scan/full/some-job-id"),
        ("POST", "/security/consoles/av/clamav/quarantine"),
    ],
)
async def test_clamav_endpoints_still_require_a_token(client: TestClient, method: str, route: str):
    response = client.request(method, route, json={"path": "/tmp/x"} if method == "POST" else None)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_av_endpoint_always_reports_both_osquery_and_clamav_sources_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: runs the real connectors, whatever this machine's
    actual state is — the point of this anchor is the *shape* of the
    contract (both sources present, each with an honest status, never a
    crash), not any one machine's specific values."""
    headers = await _admin_headers(client, migrated_session_maker, "a17_av_regress")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert "osquery" in body["connectors"]
    assert "clamav" in body["connectors"]
    assert body["connectors"]["clamav"]["status"] in _KNOWN_CONNECTOR_STATUSES
    for key in ("clean", "last_scan_at", "quarantine_count", "databases_updated_at"):
        assert key in body["metrics"]


@pytest.mark.integration
async def test_av_endpoint_survives_clamav_failing(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    async def _raising_clamav(job_registry=None):
        return {
            "connector": {"status": "unreachable"},
            "engine_version": None,
            "database_version": None,
            "databases_updated_at": None,
            "quarantine_count": None,
            "last_scan_at": None,
            "clean": None,
        }

    monkeypatch.setattr(security_console_module, "fetch_av_clamav_data", _raising_clamav)
    headers = await _admin_headers(client, migrated_session_maker, "a17_av_regress_fail")

    response = client.get("/security/consoles/av", headers=headers)

    assert response.status_code == 200
    assert response.json()["connectors"]["clamav"]["status"] == "unreachable"


@pytest.mark.integration
async def test_quick_scan_never_500s_when_clamav_is_off_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """No monkeypatching: `clamav_enabled` defaults to False (Phase 0
    default, no `.env` in the test environment) — the real `run_quick_scan`
    genuinely raises `ClamAvNotConfiguredError`, and the router must
    translate that into an honest 503, never a 500."""
    headers = await _admin_headers(client, migrated_session_maker, "a17_quick_scan_regress")

    response = client.post("/security/consoles/av/clamav/scan/quick", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_full_scan_start_never_500s_when_clamav_is_off_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "a17_full_scan_regress")

    response = client.post("/security/consoles/av/clamav/scan/full", headers=headers)

    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_full_scan_status_404s_cleanly_for_an_unknown_job(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "a17_full_scan_status_regress")

    response = client.get("/security/consoles/av/clamav/scan/full/no-such-job", headers=headers)

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "scan_job_not_found"}


@pytest.mark.integration
async def test_quarantine_404s_cleanly_for_a_missing_file(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], tmp_path
):
    headers = await _admin_headers(client, migrated_session_maker, "a17_quarantine_regress")

    response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(tmp_path / "definitely-does-not-exist.exe")},
        headers=headers,
    )

    assert response.status_code == 404
    assert response.json()["detail"] == {"error": "file_not_found"}


@pytest.mark.integration
async def test_quarantine_403s_cleanly_for_a_path_outside_scan_roots(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
):
    """Regression anchor for the architect-review security finding
    (2026-07-16): quarantine is never an arbitrary-file-move primitive —
    an authenticated caller cannot quarantine a path outside the known
    scan roots (e.g. `/etc/passwd`), only something the scanner itself
    could have found. `_default_quick_scan_targets` is monkeypatched to a
    controlled root (not the real Downloads/OS temp dir) so this stays
    deterministic across machines, same technique
    test_security_console_av_clamav.py's dedicated real-wiring test uses.
    """
    import app.services.mcp.security_connectors.clamav as clamav_module

    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])

    outside_file = tmp_path / "outside.exe"
    outside_file.write_bytes(b"do not move me")
    headers = await _admin_headers(client, migrated_session_maker, "a17_quarantine_scope_regress")

    response = client.post(
        "/security/consoles/av/clamav/quarantine",
        json={"path": str(outside_file)},
        headers=headers,
    )

    assert response.status_code == 403
    assert response.json()["detail"] == {"error": "path_outside_scan_roots"}
    assert outside_file.exists()  # never moved
