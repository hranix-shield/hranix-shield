"""A-12: resolve_backup_password_file — pure Settings/file logic, no restic
subprocess involved (mirrors tests/unit/test_auth_service.py's
resolve_jwt_secret tests, same fallback shape, same "AGPL source can't ship
a working constant" reasoning)."""

from pathlib import Path

import pytest

from app.config import Settings
from app.services.backup.service import resolve_backup_password_file


@pytest.mark.unit
def test_resolve_backup_password_file_persists_an_explicit_setting(tmp_path: Path):
    secret_file = tmp_path / ".restic_password"
    settings = Settings(_env_file=None, restic_password="explicit-configured-password")

    resolved = resolve_backup_password_file(settings, secret_file=secret_file)

    assert resolved == secret_file
    assert secret_file.read_text().strip() == "explicit-configured-password"


@pytest.mark.unit
def test_resolve_backup_password_file_generates_and_persists_when_unset(tmp_path: Path):
    secret_file = tmp_path / ".restic_password"
    settings = Settings(_env_file=None, restic_password=None)

    resolved = resolve_backup_password_file(settings, secret_file=secret_file)

    assert resolved == secret_file
    assert secret_file.exists()
    assert len(secret_file.read_text().strip()) >= 32


@pytest.mark.unit
def test_resolve_backup_password_file_is_stable_across_independent_settings_instances(
    tmp_path: Path,
):
    """Simulates surviving a restart: two independent Settings() constructions,
    neither with RESTIC_PASSWORD set, must resolve to a file holding the SAME
    password rather than regenerating a new one each time (which would make
    every previously created restic snapshot unreadable after a restart)."""
    secret_file = tmp_path / ".restic_password"
    settings_before_restart = Settings(_env_file=None, restic_password=None)
    settings_after_restart = Settings(_env_file=None, restic_password=None)

    resolve_backup_password_file(settings_before_restart, secret_file=secret_file)
    first_password = secret_file.read_text().strip()
    resolve_backup_password_file(settings_after_restart, secret_file=secret_file)
    second_password = secret_file.read_text().strip()

    assert first_password == second_password


@pytest.mark.unit
def test_resolve_backup_password_file_sets_restrictive_permissions(tmp_path: Path):
    secret_file = tmp_path / ".restic_password"
    settings = Settings(_env_file=None, restic_password=None)

    resolve_backup_password_file(settings, secret_file=secret_file)

    mode = secret_file.stat().st_mode & 0o777
    assert mode == 0o600


@pytest.mark.unit
def test_resolve_backup_password_file_updates_stale_file_when_setting_changes(tmp_path: Path):
    """If RESTIC_PASSWORD is set explicitly and differs from whatever is
    already on disk (e.g. an operator changed it in .env), the file is
    rewritten to match — the env var is the source of truth when present."""
    secret_file = tmp_path / ".restic_password"
    secret_file.write_text("old-stale-value")

    settings = Settings(_env_file=None, restic_password="new-explicit-value")
    resolve_backup_password_file(settings, secret_file=secret_file)

    assert secret_file.read_text().strip() == "new-explicit-value"
