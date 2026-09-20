"""A-18: cross-platform "is full-disk encryption on" check — the second of
the two new connectors this task builds for the `perimeter` console. Same
shape/rationale as this task's `os_firewall.py` sibling — see that module's
docstring for the shared "why subprocess, why these three states" reasoning,
not repeated here.

The Linux path is deliberately weaker than the other two — this task's own
brief calls it out explicitly: "честная best-effort попытка, не
гарантированная поддержка... если не получилось надёжно определить,
возвращай not_configured, не гадай". See `_linux_disk_encryption_active`'s
docstring for exactly what that means in code: this module never returns a
confident `False` on Linux, only `True` or `not_configured`.
"""

from __future__ import annotations

import json
import logging
import platform
import re
from typing import Any

from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
    looks_like_permission_denied,
    run_local_command,
)

logger = logging.getLogger(__name__)

OS_DISK_ENCRYPTION_CONNECTOR_NAME = "os_disk_encryption"


class OSDiskEncryptionError(RuntimeError):
    """`reason` is one of `"not_configured"` / `"permission_denied"` /
    `"unreachable"` — see `os_firewall.py`'s module docstring for what each
    means; identical vocabulary, this module's own sibling."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


async def _run(*args: str) -> tuple[int, str, str]:
    """Translates the shared local-command helper's exceptions into this
    module's own `OSDiskEncryptionError` reasons."""
    try:
        return await run_local_command(*args)
    except LocalCommandNotFound as exc:
        raise OSDiskEncryptionError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise OSDiskEncryptionError(str(exc), reason="unreachable") from exc


async def _macos_disk_encryption_active() -> bool:
    """`fdesetup status` — confirmed live while building this task (no sudo
    needed as a plain user: `fdesetup status` -> `"FileVault is Off."`).
    Prints one of `"FileVault is On."` / `"FileVault is Off."` / a longer
    in-progress-or-scheduled variant (e.g. `"...will be enabled after the
    next restart."`). This module only distinguishes the simple On/Off
    cases — a scheduled-but-not-yet-applied state is read as "off" (data at
    rest is not actually protected yet), a literal reading of fdesetup's own
    first line rather than treating "eventually" the same as "now".
    """
    returncode, stdout, stderr = await _run("fdesetup", "status")
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSDiskEncryptionError("fdesetup status requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSDiskEncryptionError(f"fdesetup status exited {returncode}: {stderr.strip()}", reason="unreachable")
    lowered = stdout.strip().lower()
    if lowered.startswith("filevault is on"):
        return True
    if lowered.startswith("filevault is off"):
        return False
    raise OSDiskEncryptionError("could not parse fdesetup status output", reason="unreachable")


async def _windows_powershell_output(command: str, *, timeout: float = 15.0) -> str:
    """Run a read-only PowerShell one-liner and return its stdout — the
    locale-proof Windows data path (mirrors `os_firewall.py`'s helper of
    the same name: netsh/manage-bde text is MUI-localized, so A-18's
    documented-text parse silently only ever worked on en-US; caught live
    on a real ru-RU host, 2026-09-19 Windows acceptance).

    Same `[Console]::OutputEncoding` UTF-8 prefix as there: a localized
    host otherwise writes denial messages in the legacy OEM codepage
    (cp866 on ru-RU, confirmed live) and `run_local_command`'s UTF-8
    decode turns them into mush no permission marker can match.

    The BitLocker CIM denial for a non-elevated user is measurably slow
    (the CIM query itself must time out server-side before the error is
    formatted — well over 5s observed live), hence the generous default.
    """
    try:
        returncode, stdout, stderr = await run_local_command(
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + command,
            timeout=timeout,
        )
    except LocalCommandNotFound as exc:
        raise OSDiskEncryptionError(str(exc), reason="not_configured") from exc
    except LocalCommandTimedOut as exc:
        raise OSDiskEncryptionError(f"powershell timed out after {timeout}s", reason="unreachable") from exc
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSDiskEncryptionError("PowerShell query requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSDiskEncryptionError(f"powershell exited {returncode}: {stderr.strip()}", reason="unreachable")
    return stdout


async def _windows_disk_encryption_active() -> bool:
    """`Get-BitLockerVolume` (CIM, via `_windows_powershell_output`) —
    at least one volume with `ProtectionStatus` `"On"` reads as active:
    this product targets single-disk laptops, so "the disk" reads as "any
    volume this call can see". Same semantics as the original A-18
    `manage-bde -status` text parse, now locale-proof (the «Protection
    Status: Protection On» text it parsed only exists on en-US — ru-RU
    prints «Состояние защиты»).

    Requires an elevated token — confirmed live on a real Windows host
    (2026-09-19): a non-elevated administrator-group user is denied at the
    CIM layer (`Get-CimInstance: Отказано в доступе`), so the console's
    honest `permission_denied` state is the expected steady state for a
    non-elevated tray run; a console refresh deliberately never triggers
    an elevation prompt (same policy as every other read).
    """
    stdout = await _windows_powershell_output(
        "Get-BitLockerVolume | Select-Object MountPoint,ProtectionStatus | ConvertTo-Json -Compress",
        timeout=45.0,
    )
    try:
        volumes = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise OSDiskEncryptionError(
            f"could not parse Get-BitLockerVolume output: {stdout.strip()[:200]!r}", reason="unreachable"
        ) from exc
    if isinstance(volumes, dict):
        volumes = [volumes]
    statuses = [str(volume.get("ProtectionStatus", "")).strip().lower() for volume in volumes]
    if not statuses:
        raise OSDiskEncryptionError("Get-BitLockerVolume returned no volumes", reason="unreachable")
    if any(status == "on" for status in statuses):
        return True
    if all(status == "off" for status in statuses):
        return False
    raise OSDiskEncryptionError(
        f"unrecognized ProtectionStatus values: {statuses!r}", reason="unreachable"
    )


async def _linux_disk_encryption_active() -> bool:
    """Best-effort LUKS detection for the root filesystem only.

    This never returns a confident `False`: many legitimate encrypted
    setups (filesystem-level fscrypt, ZFS/btrfs native encryption, an
    encrypted LVM chain reached a different way than checked here) would
    not be caught by this simple check, so "this check didn't find LUKS"
    must not be reported as "definitely unencrypted" — that would be
    exactly the "guessed zero" the project's honesty principle forbids.
    It only ever returns `True` (the root filesystem resolves to a
    `/dev/mapper/*` device that `cryptsetup status` confirms is LUKS) or
    raises `not_configured` (cannot confirm either way) — never guesses.
    """
    returncode, stdout, _stderr = await _run("findmnt", "-no", "SOURCE", "/")
    if returncode != 0 or not stdout.strip():
        raise OSDiskEncryptionError(
            "could not resolve the root filesystem's source device", reason="not_configured"
        )

    root_source = stdout.strip()
    if not root_source.startswith("/dev/mapper/"):
        # A plain partition (e.g. /dev/sda2) proves nothing either way for
        # the encryption schemes this check cannot see — stay honest rather
        # than call it unencrypted.
        raise OSDiskEncryptionError(
            "root filesystem is not on a /dev/mapper device; cannot confirm "
            "LUKS without guessing",
            reason="not_configured",
        )

    mapper_name = root_source.rsplit("/", 1)[-1]
    returncode, stdout, stderr = await _run("cryptsetup", "status", mapper_name)
    combined = f"{stdout}\n{stderr}"
    if looks_like_permission_denied(combined):
        raise OSDiskEncryptionError("cryptsetup status requires elevated privileges", reason="permission_denied")
    if returncode != 0:
        raise OSDiskEncryptionError(
            "cryptsetup could not confirm the mapper device's type", reason="not_configured"
        )
    if re.search(r"type:\s*luks", stdout, flags=re.IGNORECASE):
        return True
    raise OSDiskEncryptionError("mapper device is not reported as a LUKS volume", reason="not_configured")


async def _disk_encryption_active_for_current_platform() -> bool:
    system = platform.system()
    if system == "Darwin":
        return await _macos_disk_encryption_active()
    if system == "Windows":
        return await _windows_disk_encryption_active()
    if system == "Linux":
        return await _linux_disk_encryption_active()
    raise OSDiskEncryptionError(f"unsupported platform: {system!r}", reason="not_configured")


async def fetch_disk_encryption_status() -> dict[str, Any]:
    """Real data for the `os_disk_encryption` slice of `GET
    /security/consoles/perimeter` (see
    `security_console.py._perimeter_payload`). Never raises — see
    `os_firewall.fetch_firewall_status`'s docstring, identical contract."""
    try:
        active = await _disk_encryption_active_for_current_platform()
    except OSDiskEncryptionError as exc:
        logger.warning("os_disk_encryption: %s", exc)
        return {"connector": {"status": exc.reason}, "active": None}
    return {"connector": {"status": "ok"}, "active": active}


def register_os_disk_encryption_connector(registry: MCPRegistry) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as `crowdsec.register_crowdsec_connector`."""
    registry.register(
        MCPConnector(
            name=OS_DISK_ENCRYPTION_CONNECTOR_NAME,
            description=(
                "OS full-disk encryption status (FileVault on macOS, "
                "BitLocker on Windows, best-effort LUKS detection on "
                "Linux) — read locally via subprocess, never linked into "
                "this process."
            ),
            transport="subprocess",
            endpoint="",
        )
    )
