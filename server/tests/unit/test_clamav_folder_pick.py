"""Post-merge user request (2026-08-02): `clamav.pick_scan_folder` — a real
native OS folder-picker dialog for "Проверить папку". `runner` is injected
(same seam `elevated.elevated_run`'s own `runner` parameter already
establishes) — none of this ever pops a real OS dialog.
"""

from __future__ import annotations

import pytest

import app.services.mcp.security_connectors.clamav as clamav_module
from app.services.mcp.security_connectors.clamav import (
    ClamAvFolderPickError,
    pick_scan_folder,
)


def _fake_runner(returncode: int, stdout: str = "", stderr: str = ""):
    async def _run(argv, *, timeout):
        return (returncode, stdout, stderr)

    return _run


@pytest.fixture(autouse=True)
def _macos(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(clamav_module.platform, "system", lambda: "Darwin")


@pytest.mark.unit
async def test_pick_scan_folder_ok_returns_the_picked_path():
    runner = _fake_runner(0, stdout="/Users/demo/Downloads/subfolder\n")

    path = await pick_scan_folder(runner=runner)

    assert path == "/Users/demo/Downloads/subfolder"


@pytest.mark.unit
async def test_pick_scan_folder_cancelled_raises_folder_pick_cancelled():
    """AppleScript's own documented behaviour: a cancelled choose-folder
    dialog raises error -128 ("User canceled")."""
    runner = _fake_runner(1, stderr="execution error: User canceled. (-128)")

    with pytest.raises(ClamAvFolderPickError) as exc_info:
        await pick_scan_folder(runner=runner)

    assert exc_info.value.reason == "folder_pick_cancelled"


@pytest.mark.unit
async def test_pick_scan_folder_other_failure_raises_failed():
    runner = _fake_runner(1, stderr="some other osascript error")

    with pytest.raises(ClamAvFolderPickError) as exc_info:
        await pick_scan_folder(runner=runner)

    assert exc_info.value.reason == "failed"


@pytest.mark.unit
async def test_pick_scan_folder_empty_path_raises_failed():
    runner = _fake_runner(0, stdout="   \n")

    with pytest.raises(ClamAvFolderPickError) as exc_info:
        await pick_scan_folder(runner=runner)

    assert exc_info.value.reason == "failed"


@pytest.mark.unit
async def test_pick_scan_folder_unsupported_platform_never_calls_the_runner(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(clamav_module.platform, "system", lambda: "Linux")
    calls: list[int] = []

    async def _run(argv, *, timeout):
        calls.append(1)
        return (0, "/tmp", "")

    with pytest.raises(ClamAvFolderPickError) as exc_info:
        await pick_scan_folder(runner=_run)

    assert exc_info.value.reason == "unsupported_platform"
    assert calls == []
