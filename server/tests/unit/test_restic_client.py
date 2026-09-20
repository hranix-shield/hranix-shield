"""A-59: restic_client spawn-failure coverage — no real restic binary needed
(unlike tests/integration/test_restic_client.py, which drives the real CLI
against a tmp repo and skips when it isn't installed). These pin the
"binary not on PATH" path: `create_subprocess_exec` fails at SPAWN time with
a raw FileNotFoundError, which every upstream `except ResticError` missed —
the raw OSError used to fly straight through run_startup_integrity_check and
kill the whole app at startup (BACKUP_ENABLED=True + no restic, see the A-59
plan-spec). `_run_restic` must translate it into the ResticError vocabulary
every caller already speaks.

A-61 adds the vendored-binary resolver coverage (`_resolve_restic`/
`_vendored_restic_path`) — packaged mode must prefer the bundle's own
`vendor/restic/restic[.exe]` over PATH, mirroring osquery.py's
`_resolve_osqueryi` (whose test shape — the `_set_packaged` helper below —
this file mirrors rather than imports, since it has to patch THIS module's
`sys` reference).
"""

import asyncio
import sys
from pathlib import Path

import pytest

from app.services.backup import restic_client as restic_client_module
from app.services.backup.restic_client import (
    ResticError,
    _resolve_restic,
    _run_restic,
    _vendored_restic_path,
)


def _set_packaged(monkeypatch: pytest.MonkeyPatch, meipass: str) -> None:
    """Mocks the exact PyInstaller bootloader detection pattern
    `app.config.is_packaged()` checks — same helper shape as
    test_osquery_connector.py's `_set_packaged()`, patched on THIS module's
    `sys` so the module-level `import sys` reference in restic_client.py
    observes the mock."""
    monkeypatch.setattr(restic_client_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(restic_client_module.sys, "_MEIPASS", meipass, raising=False)


@pytest.fixture
def no_restic_binary(monkeypatch: pytest.MonkeyPatch):
    """Simulates `restic` missing from PATH entirely: the spawn itself
    raises FileNotFoundError from the await, before any process object (and
    therefore any returncode/stderr) ever exists. Patching the asyncio
    module attribute (not a capture of the real function) is what makes the
    patch visible to restic_client's bare `asyncio.create_subprocess_exec`
    lookup, and monkeypatch restores the original afterward."""

    async def _raise_file_not_found(*args, **kwargs):
        raise FileNotFoundError(2, "The system cannot find the file specified")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _raise_file_not_found)


@pytest.mark.unit
async def test_run_restic_raises_restic_error_when_binary_is_missing(
    tmp_path: Path, no_restic_binary
):
    with pytest.raises(ResticError) as excinfo:
        await _run_restic(
            "snapshots", "--json", repo_dir=tmp_path / "repo", password_file=tmp_path / "pw"
        )

    assert "restic binary not found" in str(excinfo.value)


@pytest.mark.unit
async def test_missing_binary_reports_a_negative_returncode_and_the_full_argv(
    tmp_path: Path, no_restic_binary
):
    """returncode -1 = "the process never ran" (distinct from any real restic
    exit code), and the message carries the FULL argv (starting with the
    binary name) so an operator sees which invocation could not even start —
    the same information-carrying shape a non-zero exit already produces.
    (`stderr` carries the human-readable reason; the public `.args` attribute
    itself is a tuple of the formatted message, a pre-existing ResticError
    quirk this task deliberately does not touch.)"""
    with pytest.raises(ResticError) as excinfo:
        await _run_restic(
            "snapshots", "--json", repo_dir=tmp_path / "repo", password_file=tmp_path / "pw"
        )

    assert excinfo.value.returncode == -1
    assert excinfo.value.stderr == "restic binary not found on PATH"
    assert str(tmp_path / "repo") in str(excinfo.value)
    assert str(tmp_path / "pw") in str(excinfo.value)


@pytest.mark.unit
async def test_public_wrappers_surface_restic_error_not_file_not_found(
    tmp_path: Path, no_restic_binary
):
    """The DoD's real point, one level up: the public client functions are
    what wiring.py/service.py call inside their `except ResticError` blocks —
    none of them may ever leak the raw FileNotFoundError anymore."""
    from app.services.backup.restic_client import (
        create_snapshot,
        init_repo,
        list_snapshots,
        restore_snapshot,
    )

    repo_dir = tmp_path / "repo"
    password_file = tmp_path / "pw"

    with pytest.raises(ResticError):
        await init_repo(repo_dir=repo_dir, password_file=password_file)
    with pytest.raises(ResticError):
        await list_snapshots(repo_dir=repo_dir, password_file=password_file)
    with pytest.raises(ResticError):
        await create_snapshot(
            repo_dir=repo_dir, password_file=password_file, target_paths=[tmp_path]
        )
    with pytest.raises(ResticError):
        await restore_snapshot(
            repo_dir=repo_dir,
            password_file=password_file,
            snapshot_id="abc",
            target_dir=tmp_path / "restore",
        )


# ---------------------------------------------------------------------------
# A-61: _resolve_restic() / _vendored_restic_path() — packaged (vendored
# binary first) vs not-packaged (bare PATH lookup) resolution, mirroring
# test_osquery_connector.py's resolver tests.
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_restic_not_packaged_returns_bare_fallback():
    """Every environment this whole test suite runs in (pytest itself never
    sets `sys.frozen`) must resolve to the same bare `"restic"` string the
    module used pre-A-61 — a developer/Docker image with restic from a
    package manager keeps working unchanged."""
    assert _resolve_restic() == "restic"


@pytest.mark.unit
def test_resolve_restic_packaged_but_vendored_binary_missing_falls_back(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Packaged, but nothing was vendored at build time — must not raise,
    must not fabricate a nonexistent path: fall back to PATH exactly like
    the not-packaged case."""
    _set_packaged(monkeypatch, str(tmp_path))

    assert _resolve_restic() == "restic"


@pytest.mark.unit
def test_resolve_restic_packaged_with_vendored_binary_returns_its_absolute_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """The A-61 happy path: the native installer vendored a real `restic`
    at `<bundle root>/vendor/restic/restic[.exe]` — preferred over the bare
    PATH lookup, which is what makes backups work out of the box on a
    machine without restic installed. Both names are created so the test
    is host-OS-agnostic (the resolver must pick the one matching
    sys.platform); the suffix-branch correctness itself is pinned by the
    dedicated win32 test below."""
    vendor_dir = tmp_path / "vendor" / "restic"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "restic").write_text("fake restic binary (posix name)")
    (vendor_dir / "restic.exe").write_text("fake restic binary (windows name)")
    _set_packaged(monkeypatch, str(tmp_path))

    expected = "restic.exe" if restic_client_module.sys.platform == "win32" else "restic"
    assert _resolve_restic() == str(vendor_dir / expected)
    assert _vendored_restic_path() == vendor_dir / expected


@pytest.mark.unit
def test_resolve_restic_packaged_windows_looks_for_exe_suffix(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """Windows' vendored binary is named `restic.exe` (see
    packaging/windows/vendor-restic.sh / hranix-shield.spec) — on a win32
    `sys.platform` the resolver must look for that suffix specifically and
    must NOT pick up a same-named-but-wrong-suffix file sitting next to it.
    sys.platform is patched to "win32" so the branch is exercised even
    though this suite itself runs on any host OS."""
    _set_packaged(monkeypatch, str(tmp_path))
    monkeypatch.setattr(restic_client_module.sys, "platform", "win32")
    vendor_dir = tmp_path / "vendor" / "restic"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "restic").write_text("not the windows binary")

    assert _resolve_restic() == "restic"


@pytest.mark.unit
async def test_run_restic_uses_the_resolved_vendored_binary_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    """`_run_restic` builds its argv from the resolver, not the bare
    literal: in packaged mode with a vendored binary present, argv[0] must
    be that absolute path (captured from the spawn call), so the subprocess
    actually runs the bundled copy."""
    vendor_dir = tmp_path / "vendor" / "restic"
    vendor_dir.mkdir(parents=True)
    binary = vendor_dir / "restic.exe"
    binary.write_text("fake restic binary")
    _set_packaged(monkeypatch, str(tmp_path))
    monkeypatch.setattr(restic_client_module.sys, "platform", "win32")

    captured_argv: list[list[str]] = []

    class _FakeProcess:
        async def communicate(self):
            return (b"", b"")

        @property
        def returncode(self):
            return 0

    def _fake_exec(*args, **kwargs):
        captured_argv.append(list(args))
        future = asyncio.get_running_loop().create_future()
        future.set_result(_FakeProcess())
        return future

    monkeypatch.setattr(restic_client_module.asyncio, "create_subprocess_exec", _fake_exec)

    await _run_restic(
        "snapshots", "--json", repo_dir=tmp_path / "repo", password_file=tmp_path / "pw"
    )

    assert captured_argv[0][0] == str(binary)
