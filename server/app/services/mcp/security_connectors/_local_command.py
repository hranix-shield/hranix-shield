"""Tiny shared subprocess helper for A-18's two "штатные средства ОС"
connectors (`os_firewall.py`, `os_disk_encryption.py`) — both need exactly
the same "run one local binary via argv, never a shell string, tell a
missing binary and a timeout apart from a real non-zero exit" shape
`services/backup/restic_client.py` already established for restic; factored
out once here so neither connector re-implements it, rather than each
carrying its own copy. `crowdsec.py` has no sibling local-subprocess
connector to share this with, which is why it has no equivalent module.

Every call goes through `asyncio.create_subprocess_exec` (argv list, never a
shell string) for the same reason restic_client.py gives: the rest of this
codebase's services are async end to end, and a blocking `subprocess.run`
here would stall the event loop for the duration of the call.

Not a connector itself and not registered in `MCPRegistry` — an internal
helper the two connector modules import, analogous to how
`restic_client.py`'s `_run_restic` is private to that one module, just
shared across two modules here instead of kept private to one.
"""

from __future__ import annotations

import asyncio


class LocalCommandNotFound(RuntimeError):
    """The requested binary is not installed / not on `PATH` on this host."""


class LocalCommandTimedOut(RuntimeError):
    """The requested binary did not finish within the given timeout."""


async def run_local_command(*args: str, timeout: float = 5.0) -> tuple[int, str, str]:
    """Runs `args` (an argv list) and returns `(returncode, stdout, stderr)`
    as decoded text (invalid bytes replaced, never raised on decode).

    Raises `LocalCommandNotFound` when the binary itself does not exist and
    `LocalCommandTimedOut` when it does not finish in time — every other
    outcome (including a non-zero exit) is returned normally so callers can
    read stdout/stderr themselves to tell "not installed" apart from
    "installed but refused" (permissions) apart from "ran and said no".
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except FileNotFoundError as exc:
        raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host") from exc

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise LocalCommandTimedOut(f"{args[0]!r} timed out after {timeout}s") from exc

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    assert process.returncode is not None  # communicate() awaited above
    return process.returncode, stdout, stderr


# Phrasings pf/pfctl (macOS), ufw/iptables/cryptsetup (Linux) and
# netsh/manage-bde (Windows) are each documented (or, for the macOS ones,
# empirically confirmed while building this task — see os_firewall.py /
# os_disk_encryption.py) to print when run without the privileges they need.
_PERMISSION_DENIED_MARKERS = (
    "permission denied",
    "must be root",
    "operation not permitted",
    "access is denied",
    "run as administrator",
    "you need to be root",
    "requires elevation",
)


def looks_like_permission_denied(text: str) -> bool:
    """Best-effort text sniff, not a syscall-level check — there is no
    single portable way across three OSes to ask "did this specific command
    fail because of permissions", so callers still treat an unrecognized
    non-zero exit as `unreachable`, not `permission_denied`, when none of
    these markers match rather than guessing."""
    lowered = text.lower()
    return any(marker in lowered for marker in _PERMISSION_DENIED_MARKERS)
