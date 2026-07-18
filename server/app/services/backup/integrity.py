"""SQLite-file structural soundness check — deliberately separate from
restic's own `restic check` (which validates the *repository*, not the
*live* file). The startup auto-restore flow (app_factory._lifespan) needs to
answer one specific question before it starts serving traffic: is the
current on-disk `assistant.db` readable and structurally sound right now?

`aiosqlite` is already a direct dependency (SQLAlchemy's async sqlite
driver, see server/requirements.txt) — no new dependency needed for this.
"""

from __future__ import annotations

import logging
from pathlib import Path

import aiosqlite

logger = logging.getLogger(__name__)


async def check_integrity(db_path: Path) -> bool:
    """`PRAGMA integrity_check` on the SQLite file at `db_path`.

    Returns False for anything that isn't a clean "ok" — a missing file, a
    non-SQLite file, a truncated/corrupted file, or a locked file that
    can't be opened. A missing file is reported as False from THIS
    function's point of view (not "ok"); it is the CALLER's job to
    distinguish "not ok because there is no file yet" (first run / fresh
    checkout — not corruption, nothing to roll back to) from "not ok
    because the file is there and broken" (real corruption, worth
    restoring over) by checking `db_path.exists()` itself *before* calling
    this (see services/backup/wiring.py.run_startup_integrity_check).

    The explicit existence check below is not just belt-and-suspenders for
    that contract: `aiosqlite.connect()` (like the stdlib `sqlite3` it
    wraps) silently *creates* an empty, validly-structured database file at
    a nonexistent path on connect — verified live — which would otherwise
    make this function report a missing file as a healthy "ok" while
    leaving a stray empty file behind as a side effect. Checking first
    avoids both.
    """
    if not db_path.exists():
        return False
    try:
        async with aiosqlite.connect(str(db_path)) as conn:
            cursor = await conn.execute("PRAGMA integrity_check")
            row = await cursor.fetchone()
        return bool(row) and row[0] == "ok"
    except Exception as exc:
        logger.warning("backup: integrity check raised for %s: %s", db_path, exc)
        return False
