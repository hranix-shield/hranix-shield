"""A-33: `record_scan_history`/`list_scan_history` — the persistent
`scan_history` table this task adds as the durable counterpart to
`ClamAvScanJobRegistry`'s in-memory jobs (see clamav.py's own docstring on
that registry: "a future task can persist this to the DB if that turns out
to matter" — this is that future task). Exercised against the real,
migrated tmp SQLite DB (`migrated_session_maker`, see tests/conftest.py),
same technique tests/unit/test_metrics_sampler.py already uses for its own
DB-writing functions.
"""

from __future__ import annotations

import sys
from datetime import datetime

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import ScanHistory
from app.services.mcp.security_connectors.clamav import (
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    ScanResult,
    list_scan_history,
    record_scan_history,
    start_full_scan,
)
from tests.common.fake_clamd import FakeClamd

_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _eicar_aware_responder(data: bytes) -> bytes:
    if data == _EICAR:
        return b"stream: Eicar-Test-Signature FOUND\0"
    return b"stream: OK\0"


async def _wait_until_finished(registry: ClamAvScanJobRegistry, job_id: str, *, timeout: float = 5.0):
    import asyncio

    async def _poll():
        while True:
            job = registry.get(job_id)
            assert job is not None
            if job.status != "running":
                return job
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(_poll(), timeout=timeout)


# ---------------------------------------------------------------------------
# record_scan_history / list_scan_history
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_record_scan_history_writes_a_row_with_the_given_fields(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    started = datetime(2026, 7, 19, 10, 0, 0)
    finished = datetime(2026, 7, 19, 10, 0, 5)

    async with migrated_session_maker() as session:
        await record_scan_history(
            session,
            scan_type="custom",
            path="/home/user/project",
            scanned_count=5,
            infected_count=1,
            started_at=started,
            finished_at=finished,
        )

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(ScanHistory))).all()

    assert len(rows) == 1
    row = rows[0]
    assert row.scan_type == "custom"
    assert row.path == "/home/user/project"
    assert row.scanned_count == 5
    assert row.infected_count == 1
    assert row.started_at == started
    assert row.finished_at == finished


@pytest.mark.unit
async def test_record_scan_history_path_is_none_for_quick_and_full(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """quick/full scan a fixed, multi-directory target set, not one
    operator-chosen path — `path` stays honestly `None` for those, only
    `"custom"` rows ever populate it (see `ScanHistory`'s own docstring)."""
    async with migrated_session_maker() as session:
        await record_scan_history(
            session,
            scan_type="quick",
            path=None,
            scanned_count=3,
            infected_count=0,
            started_at=datetime(2026, 7, 19, 9, 0, 0),
            finished_at=datetime(2026, 7, 19, 9, 0, 1),
        )

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(ScanHistory))).all()

    assert rows[0].path is None


@pytest.mark.unit
async def test_record_scan_history_never_raises_when_the_session_commit_fails(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    """A history-write failure must not turn an otherwise-successful scan
    response into a client-facing 500 (see `record_scan_history`'s own
    docstring) — simulated here with a session double whose `commit()`
    always raises."""

    class _BrokenSession:
        def add(self, obj):
            pass

        async def commit(self):
            raise RuntimeError("simulated DB failure")

    # Must not raise.
    await record_scan_history(
        _BrokenSession(),  # type: ignore[arg-type]
        scan_type="quick",
        path=None,
        scanned_count=1,
        infected_count=0,
        started_at=datetime(2026, 7, 19, 9, 0, 0),
        finished_at=datetime(2026, 7, 19, 9, 0, 1),
    )


@pytest.mark.unit
async def test_list_scan_history_orders_newest_finished_first(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    async with migrated_session_maker() as session:
        await record_scan_history(
            session,
            scan_type="quick",
            path=None,
            scanned_count=1,
            infected_count=0,
            started_at=datetime(2026, 7, 19, 9, 0, 0),
            finished_at=datetime(2026, 7, 19, 9, 0, 1),
        )
    async with migrated_session_maker() as session:
        await record_scan_history(
            session,
            scan_type="full",
            path=None,
            scanned_count=2,
            infected_count=0,
            started_at=datetime(2026, 7, 19, 11, 0, 0),
            finished_at=datetime(2026, 7, 19, 11, 0, 5),
        )

    async with migrated_session_maker() as session:
        entries = await list_scan_history(session)

    assert [entry.scan_type for entry in entries] == ["full", "quick"]


@pytest.mark.unit
async def test_list_scan_history_respects_the_limit(
    migrated_session_maker: async_sessionmaker[AsyncSession],
):
    for i in range(5):
        async with migrated_session_maker() as session:
            await record_scan_history(
                session,
                scan_type="quick",
                path=None,
                scanned_count=i,
                infected_count=0,
                started_at=datetime(2026, 7, 19, 9, i, 0),
                finished_at=datetime(2026, 7, 19, 9, i, 1),
            )

    async with migrated_session_maker() as session:
        entries = await list_scan_history(session, limit=2)

    assert len(entries) == 2
    # The two most recently finished (i=4 then i=3).
    assert [entry.scanned_count for entry in entries] == [4, 3]


# ---------------------------------------------------------------------------
# A-33: start_full_scan / _run_full_scan_job persists a scan_history row
# ---------------------------------------------------------------------------


# A-65-0 (из промпта A-64): тест пишет настоящий EICAR-тестфайл, который
# реальный Windows Defender удаляет до скана — артефакт среды, не кода
# (см. CONTRIBUTING.md §1). Семантика теста не меняется.
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Defender перехватывает EICAR-тестфайл до скана (артефакт среды)",
)
@pytest.mark.unit
async def test_full_scan_job_persists_a_scan_history_row_on_completion(
    tmp_path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    # A dedicated SUBDIRECTORY of tmp_path, not tmp_path itself: the
    # `migrated_session_maker` fixture (see tests/conftest.py) also writes
    # its own throwaway sqlite file directly into this same `tmp_path` —
    # scanning `tmp_path` itself would pick that file up too and inflate
    # `scanned_count` by one, unrelated to anything this test is about.
    scan_target = tmp_path / "scan_target"
    scan_target.mkdir()
    (scan_target / "clean.txt").write_bytes(b"clean")
    (scan_target / "eicar.txt").write_bytes(_EICAR)
    registry = ClamAvScanJobRegistry()

    async with FakeClamd(scan_responder=_eicar_aware_responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        job = await start_full_scan(
            registry,
            client=client,
            target_dirs=[scan_target],
            max_files=50,
            session_maker=migrated_session_maker,
        )
        finished = await _wait_until_finished(registry, job.id)
        assert finished.status == "completed"

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(ScanHistory))).all()

    assert len(rows) == 1
    row = rows[0]
    assert row.scan_type == "full"
    assert row.path is None
    assert row.scanned_count == 2
    assert row.infected_count == 1
    assert row.finished_at is not None


class _FlakyClient:
    """Duck-typed stand-in for `ClamdClient` — answers `ping()` fine but
    `scan_bytes()` starts raising after `fail_after` successful calls. Same
    shape as tests/unit/test_clamav_scan.py's own `_FlakyClient`, duplicated
    here (rather than imported) to keep this file's DB-focused tests
    independent of that file's own internal helpers."""

    def __init__(self, *, fail_after: int) -> None:
        self._calls = 0
        self._fail_after = fail_after

    async def ping(self) -> None:
        return None

    async def scan_bytes(self, data: bytes) -> ScanResult:
        self._calls += 1
        if self._calls > self._fail_after:
            raise ClamdError("connection lost mid-scan", reason="unreachable")
        return ScanResult(status="clean", signature=None, raw="stream: OK")


@pytest.mark.unit
async def test_full_scan_job_does_not_persist_history_when_it_fails_mid_scan(
    tmp_path, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """A scan that never genuinely completed must not leave a `scan_history`
    row behind — recording `scanned_count=1` for a job that actually failed
    would misrepresent a real failure as a real, honest completed scan (see
    `record_scan_history`'s own docstring: "never for a scan that never...
    completed")."""
    scan_target = tmp_path / "scan_target"
    scan_target.mkdir()
    (scan_target / "a.txt").write_bytes(b"x")
    (scan_target / "b.txt").write_bytes(b"y")
    (scan_target / "c.txt").write_bytes(b"z")
    registry = ClamAvScanJobRegistry()
    client = _FlakyClient(fail_after=1)

    job = await start_full_scan(
        registry,
        client=client,
        target_dirs=[scan_target],
        max_files=50,
        session_maker=migrated_session_maker,
    )
    finished = await _wait_until_finished(registry, job.id)
    assert finished.status == "failed"

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(ScanHistory))).all()

    assert rows == []
