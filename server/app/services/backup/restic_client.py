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
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_ALREADY_INITIALIZED_MARKER = "config file already exists"


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
    """
    full_args = [
        "restic",
        "--repo", str(repo_dir),
        "--password-file", str(password_file),
        *args,
    ]
    process = await asyncio.create_subprocess_exec(
        *full_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
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
