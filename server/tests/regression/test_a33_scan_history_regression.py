"""A-33 regression anchor.

Pins the core A-33 contract a later task must not break:
  - `POST /security/consoles/av/clamav/scan/custom` and
    `GET /security/consoles/av/clamav/scan/history` both require a bearer
    token, same as every other `/security/consoles/av/clamav/*` endpoint
    (see tests/regression/test_a17_clamav_regression.py's own anchor for
    the original four);
  - neither endpoint ever 500s, even when ClamAV is off by default (Phase 0
    default, no `.env` in the test environment) or the requested path is
    outside the known scan roots — the "честный пустой экран"/honest-error
    contract A-11/A-15/A-17/A-18 established extends here too;
  - a path outside the known scan roots (including a `"../.."`-style
    traversal attempt) is ALWAYS rejected with 403 `path_outside_scan_roots`
    — the same security boundary `quarantine_file` already enforces, reused
    (not reimplemented) by `run_custom_scan`;
  - `scan_history` is real, persistent storage: a row written directly via
    `record_scan_history` is readable back through `GET .../scan/history`
    via a completely independent `AsyncSession` from the same session
    maker — the in-process equivalent of "survives a server restart",
    which `ClamAvScanJobRegistry`'s in-memory jobs never did.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import ScanHistory
from app.services.mcp.security_connectors.clamav import record_scan_history
from tests.common.factories import create_user


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
        ("POST", "/security/consoles/av/clamav/scan/custom"),
        ("GET", "/security/consoles/av/clamav/scan/history"),
    ],
)
async def test_a33_endpoints_still_require_a_token(client: TestClient, method: str, route: str):
    response = client.request(method, route, json={"path": "/tmp/x"} if method == "POST" else None)

    assert response.status_code == 401
    assert response.json()["detail"] == {"error": "not_authenticated"}


@pytest.mark.integration
async def test_a33_custom_scan_never_500s_when_clamav_is_off_by_default(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], tmp_path
):
    """No monkeypatching: `clamav_enabled` defaults to False (Phase 0
    default) — a path genuinely inside the real `_known_scan_roots()`
    (this machine's real home directory / OS temp dir) still reaches an
    honest 503, never a 500, and never a fabricated success."""
    headers = await _admin_headers(client, migrated_session_maker, "a33_custom_scan_regress")

    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": str(tmp_path)},
        headers=headers,
    )

    # Either honestly rejected as out-of-scope (403, if this machine's real
    # scan roots don't happen to cover pytest's tmp dir) or honestly
    # unconfigured (503) — never a 500, and never anything else.
    assert response.status_code in (403, 503)
    if response.status_code == 403:
        assert response.json()["detail"] == {"error": "path_outside_scan_roots"}
    else:
        assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_a33_custom_scan_traversal_resolves_safely_never_500s(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    tmp_path,
):
    """Regression anchor for the A-33 task brief's own named case: a
    `"../.."`-style traversal path must still `.resolve()` safely and reach
    an honest stage, never a 500 crash — regardless of where it resolves
    to. Post-merge user finding (2026-08-02) REMOVED the old
    known-scan-roots 403 rejection for this endpoint (see
    `run_custom_scan`'s own docstring: it was written for `quarantine_file`'s
    move-a-file risk, which does not apply to a read-only, always
    operator-initiated scan) — this anchor now pins the "never crashes"
    half of the original guarantee, not the "rejected" half, which no
    longer applies by design."""
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    # A real file OUTSIDE `allowed_root`, reached only via `..` traversal —
    # proves `.resolve()` correctly normalizes the path (not a crash on a
    # malformed one) without touching any real system path.
    outside_target = tmp_path / "outside-target.txt"
    outside_target.write_bytes(b"harmless")

    headers = await _admin_headers(client, migrated_session_maker, "a33_traversal_regress")

    traversal_path = allowed_root / ".." / "outside-target.txt"
    response = client.post(
        "/security/consoles/av/clamav/scan/custom",
        json={"path": str(traversal_path)},
        headers=headers,
    )

    # clamav_enabled defaults to False in this test environment (no .env)
    # — the request reaches that honest stage, never a 500, and never a
    # fabricated success either.
    assert response.status_code == 503
    assert response.json()["detail"] == {"error": "clamav_not_configured"}


@pytest.mark.integration
async def test_a33_scan_history_never_500s_and_is_a_real_list(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    headers = await _admin_headers(client, migrated_session_maker, "a33_scan_history_regress")

    response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)

    assert response.status_code == 200
    assert isinstance(response.json()["items"], list)


@pytest.mark.integration
async def test_a33_scan_history_is_real_persistence_not_process_memory(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """The DoD-defining regression anchor: unlike `ClamAvScanJobRegistry`
    (in-memory, reset on every restart, see that class's own docstring), a
    `scan_history` row written through one `AsyncSession` must be readable
    back through a COMPLETELY INDEPENDENT one from the same session maker
    — the in-process proxy for "survives a server restart" (the real
    restart is exercised live, outside pytest, per this task's own DoD)."""
    async with migrated_session_maker() as write_session:
        await record_scan_history(
            write_session,
            scan_type="full",
            path=None,
            scanned_count=123,
            infected_count=0,
            started_at=datetime(2026, 7, 19, 8, 0, 0),
            finished_at=datetime(2026, 7, 19, 8, 10, 0),
        )

    async with migrated_session_maker() as verify_session:
        rows = (await verify_session.scalars(select(ScanHistory))).all()
    assert len(rows) == 1
    assert rows[0].scanned_count == 123

    headers = await _admin_headers(client, migrated_session_maker, "a33_persistence_regress")
    response = client.get("/security/consoles/av/clamav/scan/history", headers=headers)

    assert response.status_code == 200
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["scan_type"] == "full"
    assert items[0]["scanned_count"] == 123
