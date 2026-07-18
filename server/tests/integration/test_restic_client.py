"""A-12: restic_client — real subprocess calls to a real, installed `restic`
binary against a throwaway tmp_path repository (never `data/`/`infra/backups/`,
per the task's explicit instruction not to touch the developer's real backup
repo from the test suite). Skips cleanly (not a fake pass) if `restic` isn't
on PATH — see the task report for why the DoD demands this be genuinely
exercised, not mocked.
"""

import shutil
from pathlib import Path

import pytest

from app.services.backup.restic_client import (
    ResticError,
    create_snapshot,
    init_repo,
    list_snapshots,
    restore_snapshot,
)

pytestmark = pytest.mark.skipif(
    shutil.which("restic") is None, reason="restic CLI is not installed on PATH"
)


def _password_file(tmp_path: Path) -> Path:
    path = tmp_path / ".restic_password"
    path.write_text("test-password-for-restic-client-tests")
    path.chmod(0o600)
    return path


@pytest.mark.integration
async def test_init_repo_creates_a_new_repository(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)

    created = await init_repo(repo_dir=repo_dir, password_file=password_file)

    assert created is True
    assert (repo_dir / "config").exists()


@pytest.mark.integration
async def test_init_repo_is_idempotent_on_an_existing_repository(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)

    first = await init_repo(repo_dir=repo_dir, password_file=password_file)
    second = await init_repo(repo_dir=repo_dir, password_file=password_file)

    assert first is True
    assert second is False  # already existed — no error, no re-creation


@pytest.mark.integration
async def test_init_repo_with_wrong_password_on_existing_repo_is_still_idempotent(tmp_path: Path):
    """Verified live: `restic init` decides "already initialized" purely
    from the config file's on-disk presence, before any password check —
    so a *wrong* password file against an already-initialized repo still
    hits the same "config file already exists" marker as the real password
    would, and `init_repo` still correctly reports it as "not newly
    created," not an error. (The wrong password only actually surfaces as
    a failure on an operation that needs to decrypt something — see
    `test_operation_requiring_decryption_with_wrong_password_raises` below,
    which is where `init_repo`'s idempotency swallow must NOT apply.)"""
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    wrong_password_file = tmp_path / ".wrong_password"
    wrong_password_file.write_text("not-the-real-password")

    created_again = await init_repo(repo_dir=repo_dir, password_file=wrong_password_file)

    assert created_again is False


@pytest.mark.integration
async def test_operation_requiring_decryption_with_wrong_password_raises(tmp_path: Path):
    """Unlike `init`, any operation that actually needs to read repository
    contents (snapshots/backup/restore) genuinely fails against a wrong
    password — this is the real place a bad restic_password would surface."""
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    wrong_password_file = tmp_path / ".wrong_password"
    wrong_password_file.write_text("not-the-real-password")

    with pytest.raises(ResticError):
        await list_snapshots(repo_dir=repo_dir, password_file=wrong_password_file)


@pytest.mark.integration
async def test_create_snapshot_reports_the_real_backed_up_size(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    source_file = tmp_path / "data" / "assistant.db"
    source_file.parent.mkdir(parents=True)
    payload = b"pretend this is sqlite file content" * 10
    source_file.write_bytes(payload)

    summary = await create_snapshot(
        repo_dir=repo_dir, password_file=password_file, target_paths=[source_file], tags=["database"]
    )

    assert summary.total_bytes_processed == len(payload)
    assert summary.total_files_processed == 1
    assert len(summary.snapshot_id) == 64  # full restic object id, not the short_id


@pytest.mark.integration
async def test_list_snapshots_reflects_created_snapshots_oldest_first(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    source_file = tmp_path / "data" / "assistant.db"
    source_file.parent.mkdir(parents=True)

    source_file.write_bytes(b"version one")
    first = await create_snapshot(
        repo_dir=repo_dir, password_file=password_file, target_paths=[source_file]
    )
    source_file.write_bytes(b"version two, longer than before")
    second = await create_snapshot(
        repo_dir=repo_dir, password_file=password_file, target_paths=[source_file]
    )

    snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)

    assert len(snapshots) == 2
    assert snapshots[0]["id"] == first.snapshot_id
    assert snapshots[1]["id"] == second.snapshot_id


@pytest.mark.integration
async def test_list_snapshots_on_a_fresh_empty_repo_is_empty(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    snapshots = await list_snapshots(repo_dir=repo_dir, password_file=password_file)

    assert snapshots == []


@pytest.mark.integration
async def test_restore_snapshot_reconstructs_the_full_absolute_source_path(tmp_path: Path):
    """Verified live against restic 0.19.0: a restore's --target directory
    gets the FULL absolute source path underneath it, not just the file's
    basename — this is exactly why services/backup/service.py.run_restore
    locates the file via `target_dir / source.relative_to(source.anchor)`
    rather than assuming it lands directly at `target_dir / source.name`."""
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    source_file = tmp_path / "data" / "assistant.db"
    source_file.parent.mkdir(parents=True)
    source_file.write_bytes(b"the real database contents")
    summary = await create_snapshot(
        repo_dir=repo_dir, password_file=password_file, target_paths=[source_file]
    )

    restore_dir = tmp_path / "restore-here"
    await restore_snapshot(
        repo_dir=repo_dir,
        password_file=password_file,
        snapshot_id=summary.snapshot_id,
        target_dir=restore_dir,
    )

    expected_path = restore_dir / source_file.relative_to(source_file.anchor)
    assert expected_path.read_bytes() == b"the real database contents"


@pytest.mark.integration
async def test_restore_snapshot_with_unknown_id_raises(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    password_file = _password_file(tmp_path)
    await init_repo(repo_dir=repo_dir, password_file=password_file)

    with pytest.raises(ResticError):
        await restore_snapshot(
            repo_dir=repo_dir,
            password_file=password_file,
            snapshot_id="0000000000000000000000000000000000000000000000000000000000000000",
            target_dir=tmp_path / "restore-nowhere",
        )
