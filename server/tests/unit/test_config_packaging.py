"""A-19: `platformdirs` instead of a hardcoded `REPO_ROOT` for native
(PyInstaller) installer builds — see docs/план-спецификация-фаза-0-нативные-
установщики-2026-07-17.md's "A-19" section.

Two things this file has to prove, per that task's DoD:

1. **Non-packaged mode (`is_packaged()` False — Docker/venv/pytest, i.e.
   every environment this whole test suite otherwise runs in) resolves
   every `resolved_*`/`*_file()` path BYTE FOR BYTE the same as before
   A-19** — REPO_ROOT-relative, unchanged. This is the regression half of
   the DoD: one test per existing `resolved_*` property/module-level file
   function, not just "did not crash".

2. **Packaged mode (`sys.frozen`/`sys._MEIPASS` mocked) resolves the same
   paths through `platformdirs.user_data_dir("Hranix Shield", "Hranix")` /
   `platformdirs.user_log_dir("Hranix Shield", "Hranix")` instead of
   REPO_ROOT.** Assertions compare against a *live* `platformdirs` call
   with the same appname/appauthor (not a hardcoded OS-specific string),
   so this test is itself cross-platform — it would pass identically if
   run on Windows/Linux CI, not just this macOS dev machine.

Every test here uses `monkeypatch.setattr(sys, "frozen", ..., raising=False)`
/ `monkeypatch.delattr` — pytest's monkeypatch fixture undoes both at
teardown, so no test here can leak `sys.frozen`/`sys._MEIPASS` into any
other test in the suite (confirmed: the ordinary, non-packaged tests in
this very file run both before AND after the packaged-mode ones below and
still see `is_packaged() is False`, proving isolation rather than assuming
it).
"""

from pathlib import Path

import platformdirs
import pytest

from app import config
from app.config import (
    APP_AUTHOR,
    APP_NAME,
    REPO_ROOT,
    Settings,
    is_packaged,
    jwt_secret_file,
    resolve_env_file,
    restic_password_file,
)


def _set_packaged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mocks the exact PyInstaller bootloader detection pattern
    is_packaged() checks — see that function's own docstring for the
    citation (pyinstaller.org/en/stable/runtime-information.html)."""
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.setattr(config.sys, "_MEIPASS", "/fake/pyinstaller/bundle", raising=False)


# --- is_packaged(): every combination of the two attributes it checks ---


@pytest.mark.unit
def test_is_packaged_false_by_default():
    assert is_packaged() is False


@pytest.mark.unit
def test_is_packaged_true_when_both_frozen_and_meipass_set(monkeypatch: pytest.MonkeyPatch):
    _set_packaged(monkeypatch)

    assert is_packaged() is True


@pytest.mark.unit
def test_is_packaged_false_when_only_frozen_set_without_meipass(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config.sys, "frozen", True, raising=False)
    monkeypatch.delattr(config.sys, "_MEIPASS", raising=False)

    assert is_packaged() is False


@pytest.mark.unit
def test_is_packaged_false_when_only_meipass_set_without_frozen(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(config.sys, "frozen", False, raising=False)
    monkeypatch.setattr(config.sys, "_MEIPASS", "/fake/pyinstaller/bundle", raising=False)

    assert is_packaged() is False


@pytest.mark.unit
def test_app_identity_constants_are_exact():
    """`resolved_*`/`*_file()` packaged-mode assertions below all lean on
    these two constants matching the A-19 spec's literal values — pinned
    here explicitly so a typo'd rename shows up as a failure right here,
    not as a silent divergence between this test file's own expectations
    and config.py."""
    assert APP_NAME == "Hranix Shield"
    assert APP_AUTHOR == "Hranix"


# --- Non-packaged (default) mode: byte-for-byte REPO_ROOT regression ---


@pytest.mark.unit
def test_resolved_database_url_not_packaged_is_repo_root_relative():
    settings = Settings(_env_file=None)

    assert settings.resolved_database_url == f"sqlite+aiosqlite:///{REPO_ROOT / 'data' / 'assistant.db'}"


@pytest.mark.unit
def test_resolved_database_url_not_packaged_passes_through_non_sqlite_url():
    settings = Settings(_env_file=None, database_url="postgresql+asyncpg://user:pw@localhost/db")

    assert settings.resolved_database_url == "postgresql+asyncpg://user:pw@localhost/db"


@pytest.mark.unit
def test_resolved_database_url_not_packaged_passes_through_absolute_sqlite_path():
    settings = Settings(_env_file=None, database_url="sqlite+aiosqlite:////abs/db.sqlite")

    assert settings.resolved_database_url == "sqlite+aiosqlite:////abs/db.sqlite"


@pytest.mark.unit
def test_resolved_log_file_not_packaged_is_repo_root_relative():
    settings = Settings(_env_file=None)

    assert settings.resolved_log_file == str(REPO_ROOT / "logs" / "assistant.log")


@pytest.mark.unit
def test_resolved_log_file_not_packaged_empty_disables_file_logging():
    settings = Settings(_env_file=None, log_file="")

    assert settings.resolved_log_file is None


@pytest.mark.unit
def test_resolved_log_file_not_packaged_absolute_path_passes_through(tmp_path: Path):
    absolute = tmp_path / "custom.log"
    settings = Settings(_env_file=None, log_file=str(absolute))

    assert settings.resolved_log_file == str(absolute)


@pytest.mark.unit
def test_resolved_backup_dir_not_packaged_is_repo_root_relative():
    settings = Settings(_env_file=None)

    assert settings.resolved_backup_dir == REPO_ROOT / "infra" / "backups"


@pytest.mark.unit
def test_resolved_backup_dir_not_packaged_absolute_path_passes_through(tmp_path: Path):
    settings = Settings(_env_file=None, backup_dir=str(tmp_path))

    assert settings.resolved_backup_dir == tmp_path


@pytest.mark.unit
def test_resolved_clamav_quarantine_dir_not_packaged_is_repo_root_relative():
    settings = Settings(_env_file=None)

    assert settings.resolved_clamav_quarantine_dir == REPO_ROOT / "data" / "quarantine"


@pytest.mark.unit
def test_resolved_clamav_quarantine_dir_not_packaged_absolute_path_passes_through(tmp_path: Path):
    settings = Settings(_env_file=None, clamav_quarantine_dir=str(tmp_path))

    assert settings.resolved_clamav_quarantine_dir == tmp_path


@pytest.mark.unit
def test_resolved_sqlite_path_not_packaged_matches_database_url():
    settings = Settings(_env_file=None)

    assert settings.resolved_sqlite_path == REPO_ROOT / "data" / "assistant.db"


@pytest.mark.unit
def test_resolved_sqlite_path_not_packaged_none_for_non_sqlite_url():
    settings = Settings(_env_file=None, database_url="postgresql+asyncpg://user:pw@localhost/db")

    assert settings.resolved_sqlite_path is None


@pytest.mark.unit
def test_jwt_secret_file_not_packaged_is_repo_root_relative():
    assert jwt_secret_file() == REPO_ROOT / "data" / ".jwt_secret"


@pytest.mark.unit
def test_restic_password_file_not_packaged_is_repo_root_relative():
    assert restic_password_file() == REPO_ROOT / "data" / ".restic_password"


@pytest.mark.unit
def test_resolve_env_file_not_packaged_is_repo_root_relative():
    assert resolve_env_file() == REPO_ROOT / ".env"


# --- Packaged mode: everything routes through platformdirs instead ---


@pytest.mark.unit
def test_resolved_database_url_packaged_uses_platformdirs_user_data_dir(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert settings.resolved_database_url == (
        f"sqlite+aiosqlite:///{(expected_base / 'data' / 'assistant.db')}"
    )


@pytest.mark.unit
def test_resolved_database_url_packaged_still_passes_through_non_sqlite_url(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None, database_url="postgresql+asyncpg://user:pw@localhost/db")

    assert settings.resolved_database_url == "postgresql+asyncpg://user:pw@localhost/db"


@pytest.mark.unit
def test_resolved_database_url_packaged_still_passes_through_absolute_path(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None, database_url="sqlite+aiosqlite:////abs/db.sqlite")

    assert settings.resolved_database_url == "sqlite+aiosqlite:////abs/db.sqlite"


@pytest.mark.unit
def test_resolved_log_file_packaged_uses_platformdirs_user_log_dir(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None)
    expected_base = Path(platformdirs.user_log_dir(APP_NAME, APP_AUTHOR))

    assert settings.resolved_log_file == str(expected_base / "logs" / "assistant.log")


@pytest.mark.unit
def test_resolved_log_file_packaged_empty_still_disables_file_logging(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None, log_file="")

    assert settings.resolved_log_file is None


@pytest.mark.unit
def test_resolved_log_file_packaged_absolute_path_still_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _set_packaged(monkeypatch)
    absolute = tmp_path / "custom.log"
    settings = Settings(_env_file=None, log_file=str(absolute))

    assert settings.resolved_log_file == str(absolute)


@pytest.mark.unit
def test_resolved_backup_dir_packaged_uses_platformdirs_user_data_dir(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert settings.resolved_backup_dir == expected_base / "infra" / "backups"


@pytest.mark.unit
def test_resolved_backup_dir_packaged_absolute_path_still_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None, backup_dir=str(tmp_path))

    assert settings.resolved_backup_dir == tmp_path


@pytest.mark.unit
def test_resolved_clamav_quarantine_dir_packaged_uses_platformdirs_user_data_dir(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert settings.resolved_clamav_quarantine_dir == expected_base / "data" / "quarantine"


@pytest.mark.unit
def test_resolved_clamav_quarantine_dir_packaged_absolute_path_still_passes_through(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None, clamav_quarantine_dir=str(tmp_path))

    assert settings.resolved_clamav_quarantine_dir == tmp_path


@pytest.mark.unit
def test_resolved_sqlite_path_packaged_matches_database_url(monkeypatch: pytest.MonkeyPatch):
    _set_packaged(monkeypatch)
    settings = Settings(_env_file=None)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert settings.resolved_sqlite_path == expected_base / "data" / "assistant.db"


@pytest.mark.unit
def test_jwt_secret_file_packaged_uses_platformdirs_user_data_dir(monkeypatch: pytest.MonkeyPatch):
    _set_packaged(monkeypatch)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert jwt_secret_file() == expected_base / "data" / ".jwt_secret"


@pytest.mark.unit
def test_restic_password_file_packaged_uses_platformdirs_user_data_dir(
    monkeypatch: pytest.MonkeyPatch,
):
    _set_packaged(monkeypatch)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert restic_password_file() == expected_base / "data" / ".restic_password"


@pytest.mark.unit
def test_resolve_env_file_packaged_uses_platformdirs_user_data_dir(monkeypatch: pytest.MonkeyPatch):
    _set_packaged(monkeypatch)
    expected_base = Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))

    assert resolve_env_file() == expected_base / "config.env"


# --- Cross-cutting: packaged-mode paths must actually differ from REPO_ROOT ---
# (guards against a future edit accidentally making is_packaged() a no-op —
# e.g. both branches of an `if` collapsing to the same expression).


@pytest.mark.unit
def test_packaged_paths_genuinely_differ_from_repo_root_paths(monkeypatch: pytest.MonkeyPatch):
    not_packaged_jwt = jwt_secret_file()
    not_packaged_restic = restic_password_file()
    not_packaged_env = resolve_env_file()

    _set_packaged(monkeypatch)

    assert jwt_secret_file() != not_packaged_jwt
    assert restic_password_file() != not_packaged_restic
    assert resolve_env_file() != not_packaged_env
    assert REPO_ROOT not in jwt_secret_file().parents
