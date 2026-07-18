"""A-12: PRAGMA integrity_check wrapper — no restic involved, pure aiosqlite
against real tmp files (same "real but local/fast I/O counts as unit" style
already used by tests/unit/test_health_checks.py for the DB health check).
"""

from pathlib import Path

import aiosqlite
import pytest

from app.services.backup.integrity import check_integrity


@pytest.mark.unit
async def test_check_integrity_true_for_a_healthy_sqlite_file(tmp_path: Path):
    db_path = tmp_path / "healthy.db"
    async with aiosqlite.connect(str(db_path)) as conn:
        await conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        await conn.execute("INSERT INTO t (v) VALUES ('hello')")
        await conn.commit()

    assert await check_integrity(db_path) is True


@pytest.mark.unit
async def test_check_integrity_false_for_a_corrupted_file(tmp_path: Path):
    db_path = tmp_path / "corrupted.db"
    # A real SQLite file has a well-defined header; garbage bytes are not
    # a valid database at all, which is exactly the "current file is broken"
    # case the startup auto-restore flow needs to detect.
    db_path.write_bytes(b"this is not a sqlite database file, just garbage bytes" * 50)

    assert await check_integrity(db_path) is False


@pytest.mark.unit
async def test_check_integrity_false_for_a_missing_file_without_creating_one(tmp_path: Path):
    """Distinct from `restic check`'s repository-level integrity: this is
    specifically about the CURRENT live file. A missing file must be
    reported as not-ok (False) here — the caller (see
    services/backup/wiring.py.run_startup_integrity_check) is the one that
    decides "missing" means "first run, do nothing" rather than "restore".

    Also pins the side-effect guard: aiosqlite/sqlite3 silently CREATE an
    empty, validly-structured database file when connecting to a path that
    doesn't exist yet — verified live — which this function must not do.
    """
    db_path = tmp_path / "does-not-exist.db"

    result = await check_integrity(db_path)

    assert result is False
    assert not db_path.exists()


@pytest.mark.unit
async def test_check_integrity_false_for_a_truncated_but_header_valid_file(tmp_path: Path):
    """A file that starts like a real SQLite database (correct magic
    header) but is truncated mid-page is a more realistic "corruption from
    a crash/disk full" scenario than pure garbage bytes."""
    db_path = tmp_path / "truncated.db"
    healthy_path = tmp_path / "source.db"
    async with aiosqlite.connect(str(healthy_path)) as conn:
        await conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        for i in range(200):
            await conn.execute("INSERT INTO t (v) VALUES (?)", (f"row-{i}",))
        await conn.commit()

    original_bytes = healthy_path.read_bytes()
    db_path.write_bytes(original_bytes[: len(original_bytes) // 2])

    assert await check_integrity(db_path) is False
