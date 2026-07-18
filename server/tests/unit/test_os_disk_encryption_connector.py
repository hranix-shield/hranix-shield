"""A-18: `os_disk_encryption.py` — platform dispatch + honest not_configured/
permission_denied/unreachable/ok states, fully offline (same
`run_local_command` monkeypatch technique as test_os_firewall_connector.py)
— no real `fdesetup`/`manage-bde`/`lsblk` invocation, and no dependency on
which OS the test suite itself happens to run on.
"""

import pytest

import app.services.mcp.security_connectors.os_disk_encryption as os_disk_encryption_module
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors._local_command import (
    LocalCommandNotFound,
    LocalCommandTimedOut,
)
from app.services.mcp.security_connectors.os_disk_encryption import (
    OS_DISK_ENCRYPTION_CONNECTOR_NAME,
    fetch_disk_encryption_status,
    register_os_disk_encryption_connector,
)


def _fake_run(responses: dict[str, tuple[int, str, str]]):
    async def _run(*args: str, timeout: float = 5.0):
        if args[0] not in responses:
            raise LocalCommandNotFound(f"{args[0]!r} is not installed on this host")
        return responses[args[0]]

    return _run


@pytest.mark.unit
async def test_macos_ok_when_fdesetup_reports_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run({"fdesetup": (0, "FileVault is On.\n", "")}),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_macos_ok_when_fdesetup_reports_off(monkeypatch: pytest.MonkeyPatch):
    """Confirmed live while building this task: `fdesetup status` needs no
    sudo, and answered exactly this on the dev machine."""
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run({"fdesetup": (0, "FileVault is Off.\n", "")}),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": False}


@pytest.mark.unit
async def test_macos_scheduled_but_not_yet_applied_reads_as_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run(
            {"fdesetup": (0, "FileVault is Off but will be enabled after the next restart.\n", "")}
        ),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": False}


@pytest.mark.unit
async def test_macos_fdesetup_permission_denied(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run({"fdesetup": (1, "", "You must be root to run fdesetup.\n")}),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "permission_denied"}, "active": None}


@pytest.mark.unit
async def test_windows_ok_when_manage_bde_reports_protection_on(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Windows")
    output = "Volume C: []\n[OS Volume]\n    Protection Status:    Protection On\n"
    monkeypatch.setattr(
        os_disk_encryption_module, "run_local_command", _fake_run({"manage-bde": (0, output, "")})
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_windows_ok_when_manage_bde_reports_protection_off(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Windows")
    output = "Volume C: []\n[OS Volume]\n    Protection Status:    Protection Off\n"
    monkeypatch.setattr(
        os_disk_encryption_module, "run_local_command", _fake_run({"manage-bde": (0, output, "")})
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": False}


@pytest.mark.unit
async def test_linux_ok_when_root_is_a_confirmed_luks_mapper(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run(
            {
                "findmnt": (0, "/dev/mapper/vgroot-root\n", ""),
                "cryptsetup": (0, "  type:    LUKS2\n  cipher:  aes-xts-plain64\n", ""),
            }
        ),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "ok"}, "active": True}


@pytest.mark.unit
async def test_linux_not_configured_when_root_is_a_plain_partition(monkeypatch: pytest.MonkeyPatch):
    """The core honesty compromise this task's brief explicitly allows: a
    plain (non-mapper) root device proves nothing either way for schemes
    this simple check cannot see, so this must stay `not_configured`, never
    a guessed `False`."""
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run({"findmnt": (0, "/dev/sda2\n", "")}),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_linux_not_configured_when_findmnt_is_missing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(os_disk_encryption_module, "run_local_command", _fake_run({}))

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_linux_not_configured_when_cryptsetup_does_not_confirm_luks(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        os_disk_encryption_module,
        "run_local_command",
        _fake_run(
            {
                "findmnt": (0, "/dev/mapper/vgroot-root\n", ""),
                "cryptsetup": (1, "", "Device vgroot-root is not active.\n"),
            }
        ),
    )

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_unsupported_platform_is_not_configured_not_a_crash(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "PlanNine")

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "not_configured"}, "active": None}


@pytest.mark.unit
async def test_timeout_is_reported_as_unreachable_never_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(os_disk_encryption_module.platform, "system", lambda: "Darwin")

    async def _run(*args: str, timeout: float = 5.0):
        raise LocalCommandTimedOut(f"{args[0]!r} timed out")

    monkeypatch.setattr(os_disk_encryption_module, "run_local_command", _run)

    result = await fetch_disk_encryption_status()

    assert result == {"connector": {"status": "unreachable"}, "active": None}


@pytest.mark.unit
def test_register_os_disk_encryption_connector_registers_the_expected_metadata():
    registry = MCPRegistry()

    register_os_disk_encryption_connector(registry)

    connector = registry.get(OS_DISK_ENCRYPTION_CONNECTOR_NAME)
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "subprocess"
    assert connector.endpoint == ""
