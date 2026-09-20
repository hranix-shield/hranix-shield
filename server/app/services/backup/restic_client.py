"""Thin async wrapper over the `restic` CLI.

Deliberately parameterized (repo_dir/password_file/paths passed in by the
caller) rather than reading `Settings`/global state itself — the same
"pure function, caller resolves config" shape lets tests exercise this
module against a tmp_path repo with zero monkeypatching (see
services/backup/service.py for the layer that resolves real Settings into
these arguments, and app/config.py's resolve_backup_password_file).

Every call goes through `asyncio.create_subprocess_exec` (argv list, never
a shell string) — restic is a real external binary, and the rest of this
codebase's services are async end to end; a blocking `subprocess.run` here
would stall the event loop for the whole duration of a backup/restore.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path

from app.config import is_packaged
from app.services.mcp.security_connectors._local_command import WINDOWS_CREATE_NO_WINDOW

logger = logging.getLogger(__name__)

_ALREADY_INITIALIZED_MARKER = "config file already exists"

# A-61: fallback binary name, unchanged from before this task — resolved
# through whatever `PATH` this process inherits (dev machine with restic
# from a package manager, Docker image with it apt-installed, ...), exactly
# as the bare "restic" literal behaved pre-A-61.
_RESTIC_FALLBACK = "restic"


def _vendored_restic_path() -> Path:
    """Where each OS's native installer places its bundled `restic`
    binary, IF this build vendors one (see `_resolve_restic()`'s docstring)
    — `<PyInstaller bundle root>/vendor/restic/restic[.exe]`.

    Deliberately duplicates (does not import) the exact "`sys._MEIPASS` in
    packaged mode" detection `server/launcher.py`'s `bundled_root()` and
    osquery.py's `_vendored_osqueryi_path()` already established — the
    same circular-import reasoning applies here (launcher -> app_factory ->
    routers -> backup service -> this module), so copying the two-line
    pattern is the established resolution, not an accident to refactor.
    """
    root = Path(sys._MEIPASS)  # type: ignore[attr-defined]  # only called when is_packaged()
    exe_name = "restic.exe" if sys.platform == "win32" else "restic"
    return root / "vendor" / "restic" / exe_name


def _resolve_restic() -> str:
    """What `_run_restic()` should actually invoke for this call —
    re-resolved on every call (never cached at import time), same
    "`is_packaged()` is re-checked on every access" discipline
    `app/config.py`'s resolved_* properties and osquery.py's
    `_resolve_osqueryi` already document.

    Packaged AND the vendored binary is actually present on disk: returns
    its absolute path — the "backups work out of the box" case A-61 exists
    for (a fresh user machine has no restic in PATH). Otherwise (not
    packaged, OR packaged but the vendored binary is missing): returns the
    bare `"restic"` fallback, letting asyncio.create_subprocess_exec
    resolve it through this process's own PATH exactly as before A-61 —
    never removed, only made second-priority."""
    if is_packaged():
        vendored = _vendored_restic_path()
        if vendored.is_file():
            return str(vendored)
    return _RESTIC_FALLBACK


class ResticError(RuntimeError):
    """A `restic` invocation exited non-zero, or its output could not be
    parsed the way the caller expected."""

    def __init__(self, args: list[str], returncode: int, stderr: str):
        self.args = args
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"restic {' '.join(args)} exited {returncode}: {stderr.strip()}")


@dataclass(frozen=True)
class SnapshotSummary:
    """Parsed from restic backup's `--json` summary line (one JSON object
    per line; the last line with message_type=="summary" is the one that
    matters — see `_parse_backup_summary`)."""

    snapshot_id: str
    total_bytes_processed: int
    total_files_processed: int


async def _run_restic(
    *args: str, repo_dir: Path, password_file: Path
) -> str:
    """Runs `restic --repo <repo_dir> --password-file <password_file> <args>`.

    `--password-file`, never `--password`/`RESTIC_PASSWORD` env var: a CLI
    arg is visible to any other local process via `ps`, and an env var is
    visible via /proc/<pid>/environ — the password file (already
    permission-600, see resolve_backup_password_file) avoids both, mirroring
    resolve_jwt_secret's "never put the secret somewhere another process on
    the same box can casually read it" reasoning.

    The binary itself is resolved per-call by `_resolve_restic()` (A-61:
    vendored bundle copy first, PATH fallback second).
    """
    full_args = [
        _resolve_restic(),
        "--repo", str(repo_dir),
        "--password-file", str(password_file),
        *args,
    ]
    try:
        process = await asyncio.create_subprocess_exec(
            *full_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=WINDOWS_CREATE_NO_WINDOW,
        )
    except FileNotFoundError:
        # A-59: a missing binary fails at SPAWN time with a raw
        # FileNotFoundError, never reaching the returncode != 0 branch below
        # — so every `except ResticError` upstream (startup integrity check,
        # scheduler, manual backup/restore) silently missed it and the raw
        # OSError killed the app at startup when BACKUP_ENABLED=True on a
        # machine without restic. Report it as the same failure vocabulary
        # everything here already speaks (returncode -1 = did not run), same
        # shape as _local_command's FileNotFoundError -> LocalCommandNotFound.
        # (A-61 note: the message stays literal — this is the "neither the
        # vendored copy nor PATH produced a runnable binary" terminal case.)
        raise ResticError(full_args, -1, "restic binary not found on PATH")
    stdout_bytes, stderr_bytes = await process.communicate()
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    if process.returncode != 0:
        raise ResticError(list(args), process.returncode, stderr)
    return stdout


async def init_repo(*, repo_dir: Path, password_file: Path) -> bool:
    """Idempotent `restic init`: True if a new repository was created at
    `repo_dir`, False if one already existed there. Every other failure
    (bad password file, no disk space, ...) still raises `ResticError`.
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    try:
        await _run_restic("init", repo_dir=repo_dir, password_file=password_file)
        return True
    except ResticError as exc:
        if _ALREADY_INITIALIZED_MARKER in exc.stderr:
            return False
        raise


def _parse_backup_summary(stdout: str) -> SnapshotSummary:
    """`restic backup --json` prints one JSON object per line (progress
    events, then a final message_type=="summary" line) — take the *last*
    summary line, ignoring anything restic can't parse as JSON (defensive:
    a future restic version adding non-JSON warning lines to stdout should
    not crash this)."""
    summary_line: dict | None = None
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and obj.get("message_type") == "summary":
            summary_line = obj

    if summary_line is None:
        raise ResticError(["backup", "--json"], 0, "no summary line in restic --json output")

    return SnapshotSummary(
        snapshot_id=summary_line["snapshot_id"],
        total_bytes_processed=summary_line.get("total_bytes_processed", 0),
        total_files_processed=summary_line.get("total_files_processed", 0),
    )


async def create_snapshot(
    *,
    repo_dir: Path,
    password_file: Path,
    target_paths: list[Path],
    tags: list[str] | None = None,
) -> SnapshotSummary:
    args = ["backup", "--json"]
    for tag in tags or ():
        args += ["--tag", tag]
    args += [str(path) for path in target_paths]

    stdout = await _run_restic(*args, repo_dir=repo_dir, password_file=password_file)
    return _parse_backup_summary(stdout)


async def list_snapshots(*, repo_dir: Path, password_file: Path) -> list[dict]:
    """Returns restic's own snapshot list (`restic snapshots --json`),
    oldest first (restic's own ordering) — each entry has at least `id`,
    `short_id`, `time`, `paths`, `tags`, `summary.total_bytes_processed`."""
    stdout = await _run_restic(
        "snapshots", "--json", repo_dir=repo_dir, password_file=password_file
    )
    stdout = stdout.strip()
    return json.loads(stdout) if stdout else []


async def restore_snapshot(
    *, repo_dir: Path, password_file: Path, snapshot_id: str, target_dir: Path
) -> None:
    """Restores `snapshot_id` into `target_dir`. restic always reconstructs
    the full absolute source path under `target_dir` (e.g. restoring
    `/a/b/c.db` into `/tmp/x` produces `/tmp/x/a/b/c.db`) — callers that
    need the file back at its original absolute path locate it under
    `target_dir` themselves and copy it there (see
    services/backup/service.py.run_restore) rather than this function ever
    restic-restoring directly onto a live absolute path with `--target /`.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    await _run_restic(
        "restore", snapshot_id, "--target", str(target_dir),
        repo_dir=repo_dir, password_file=password_file,
    )
