import sys
from functools import lru_cache
from pathlib import Path

import platformdirs
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# A-19: identifies this app to platformdirs for the packaged-mode data/log
# directories below (native installers, A-20..A-22) — platformdirs (MIT
# license, verified against the installed package's own LICENSE file,
# matching https://github.com/tox-dev/platformdirs) turns these into the
# OS-correct per-user directory, e.g. `~/Library/Application Support/Hranix
# Shield` on macOS, `%APPDATA%\Hranix\Hranix Shield` on Windows,
# `~/.local/share/Hranix Shield` on Linux.
APP_NAME = "Hranix Shield"
APP_AUTHOR = "Hranix"


def is_packaged() -> bool:
    """True iff this process is a PyInstaller-frozen native-installer build
    (A-20..A-22), not `python -m ...`/Docker/pytest from a source checkout.

    PyInstaller's bootloader sets BOTH `sys.frozen` and `sys._MEIPASS` for
    every bundled app — one-file AND one-folder mode alike — before any of
    this project's own code ever runs; this is the exact detection pattern
    documented at https://pyinstaller.org/en/stable/runtime-information.html
    ("if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')").
    Checking both attributes (not just one) keeps this honest even if a
    future PyInstaller release only changes one of them.

    Always False in Docker/venv/pytest (nothing in this repo sets
    `sys.frozen` itself) — every `resolved_*` property below, and
    `jwt_secret_file()`/`restic_password_file()`/`resolve_env_file()`,
    stay on the REPO_ROOT path exactly as before this function existed.
    """
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def _packaged_data_dir() -> Path:
    """Base directory for packaged-mode data — the SQLite DB, the
    auto-generated JWT/restic secrets, the ClamAV quarantine dir, and the
    restic backup repository all live under here (A-19 spec:
    `platformdirs.user_data_dir(...)`)."""
    return Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))


def _packaged_log_dir() -> Path:
    """Base directory for the packaged-mode log file —
    `platformdirs.user_log_dir(...)`, deliberately kept separate from
    `_packaged_data_dir()` above per the A-19 spec: some OSes place logs
    outside the data dir (e.g. macOS's `~/Library/Logs/Hranix Shield` vs
    `~/Library/Application Support/Hranix Shield`)."""
    return Path(platformdirs.user_log_dir(APP_NAME, APP_AUTHOR))


def jwt_secret_file() -> Path:
    """Where the auto-generated JWT signing secret is persisted (used only
    when JWT_SECRET is unset — see services.auth.resolve_jwt_secret).
    REPO_ROOT/data/.jwt_secret when not packaged (byte-for-byte unchanged
    from before A-19); `<platformdirs data dir>/data/.jwt_secret` when
    `is_packaged()` — never committed either way, data/ is gitignored."""
    base = _packaged_data_dir() if is_packaged() else REPO_ROOT
    return base / "data" / ".jwt_secret"


def restic_password_file() -> Path:
    """Where the auto-generated restic repository-encryption password is
    persisted (used only when RESTIC_PASSWORD is unset — see
    services.backup.service.resolve_backup_password_file). Same "never a
    constant baked into AGPL source" reasoning, and same REPO_ROOT-vs-
    platformdirs split, as jwt_secret_file() above."""
    base = _packaged_data_dir() if is_packaged() else REPO_ROOT
    return base / "data" / ".restic_password"


def resolve_env_file() -> Path:
    """Where pydantic-settings reads its `.env`-style config file from.
    REPO_ROOT/.env when not packaged (byte-for-byte unchanged) — a
    packaged binary has no "repo root" at all (PyInstaller unpacks into a
    temp/app dir, see is_packaged() above), so packaged mode instead
    points at `config.env` inside the platformdirs data dir, alongside
    `data/`. Named `config.env`, not `.env`: nothing about a packaged
    install implies the usual "hidden dotfile in a repo checkout"
    convention the plain `.env` name comes from (A-19 spec)."""
    if is_packaged():
        return _packaged_data_dir() / "config.env"
    return REPO_ROOT / ".env"


# Class-level `Settings.model_config` below is built once, at import time —
# exactly like the old REPO_ROOT-only ENV_FILE constant it replaces. That is
# still correct in a real packaged binary: PyInstaller's bootloader sets
# `sys.frozen` before ANY of this project's own code, including this very
# import, ever runs — so "resolved once here" and "resolved fresh on every
# call" agree for every real process this code executes in. (The A-19 task
# brief's packaged-mode unit tests exercise `resolve_env_file()` — and
# `jwt_secret_file()`/`restic_password_file()` below — directly, with
# `sys.frozen`/`sys._MEIPASS` mocked, rather than through this cached
# class-level attribute, precisely so they don't need an `importlib.reload`
# to see a freshly-mocked mode.)
ENV_FILE = resolve_env_file()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    server_host: str = "127.0.0.1"
    server_port: int = 8080

    cors_allowed_origins: str = "http://localhost:8080"

    database_url: str = "sqlite+aiosqlite:///data/assistant.db"

    # No hardcoded fallback here on purpose: this repo is AGPL-licensed source,
    # so any constant string baked in as a "default secret" is public and lets
    # anyone forge admin JWTs (see A-3 security review, 2026-07-14). When unset,
    # services.auth.resolve_jwt_secret() generates a random secret on first use
    # and persists it to jwt_secret_file() (A-19) so tokens survive restarts.
    jwt_secret: str | None = None
    jwt_expiry_seconds: int = 3600

    # Bootstrap admin: created once at startup iff the users table is empty.
    # Left unset by default => bootstrap is skipped, no public registration exists.
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None

    # A-5: structured logging (see app/infra/logger_config.py). log_file is
    # relative-to-REPO_ROOT by default, same convention as database_url below.
    log_level: str = "INFO"
    log_file: str = "logs/assistant.log"

    # A-7: InferenceBackend abstraction (see services/inference/). Not
    # wired to any router yet — ai_enabled defaults to False and nothing
    # reads it in Phase 0; it exists only so a future phase's feature flag
    # has somewhere to live without another Settings edit.
    ollama_host: str = "http://localhost:11434"
    llm_model: str = "gemma4:e4b"
    ai_enabled: bool = False

    # A-12: backups (restic; see services/backup/). backup_dir is relative to
    # REPO_ROOT by default (same convention as database_url/log_file above) —
    # that directory IS the restic repository root, not a staging area.
    #
    # backup_enabled gates ALL automatic behavior at once (startup integrity
    # check + auto-restore-on-corruption + the daily scheduler) — off by
    # default, same "safe default, explicit opt-in" reasoning as ai_enabled
    # above: with it unset, every existing test that runs the real lifespan
    # (e.g. test_auth_startup.py) keeps touching nothing under data/ or
    # infra/backups/, exactly as before this task. Manual snapshot/restore
    # (the two new /security/consoles/backup/* endpoints) are NOT gated by
    # this flag — a manual escape hatch should work regardless of whether
    # the automatic schedule is turned on. See A-12 task report: a shipped
    # end-user distribution should probably default this to True, since
    # "backups happen automatically out of the box" is the actual product
    # promise (analytical plan §7) — flagged there as a follow-up, not
    # decided unilaterally here.
    backup_enabled: bool = False
    backup_dir: str = "infra/backups"
    backup_schedule_hour: int = 4
    backup_schedule_minute: int = 0

    # No hardcoded fallback here either, same reasoning as jwt_secret above:
    # services.backup.resolve_backup_password_file() generates+persists a
    # random repository-encryption password to restic_password_file() (A-19)
    # when unset.
    restic_password: str | None = None

    # A-13: notification channels (§5.4 of the analytical plan). Quiet hours
    # default to 22:00-08:00, matching the plan's own example — configurable,
    # same style as backup_schedule_hour/minute above, but "HH:MM" strings
    # (not two ints) since a window needs a start AND an end.
    quiet_hours_enabled: bool = True
    quiet_hours_start: str = "22:00"
    quiet_hours_end: str = "08:00"

    # Critical notifications unacknowledged for this long get escalated (see
    # services/notifications/escalation.py) — in Phase 0 that only means a
    # channel-6 (SMS/call) attempt is logged as an explicit no-op, since the
    # phone-terminal that channel needs does not exist yet (backlog, §9.1).
    notifications_escalation_minutes: int = 15
    # How often the background sweep checks for overdue critical
    # notifications — independent of the escalation window itself, same
    # "recurring background job" shape as BackupScheduler but on a fixed
    # interval rather than once a day (see services/notifications/escalation.py).
    notifications_escalation_check_interval_seconds: int = 60

    # Doverennye litsa (trusted contacts) who receive channel-5 (email) and
    # escalation notifications — comma-separated, same list-from-string
    # convention as cors_allowed_origins above. Seeds the in-memory
    # TrustedContactRegistry at create_app() time (see A-13 task report for
    # why this stays in-memory rather than a DB table in Phase 0).
    trusted_contact_emails: str = ""

    # Channel 5 (email) — stdlib smtplib client (services/notifications/smtp_client.py).
    # No hardcoded default here either: this is a third-party external
    # service (the user's own mail provider/relay), it has no "default"
    # value the way jwt_secret/restic_password can auto-generate one. Left
    # unset, the email channel is simply unavailable — logged clearly at the
    # point of use, not a silent failure (see A-13 spec point 5).
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None

    # A-11: CrowdSec (MIT license) — the "Обнаружение вторжений" console's
    # real data source (services/mcp/security_connectors/crowdsec.py). Runs
    # as a fully separate Docker container (infra/security/crowdsec/), never
    # linked into this process — this platform only talks to its LAPI over
    # HTTP as a registered bouncer (CLAUDE.md's licence gate: GPL/AGPL/MIT
    # security tools are network services, not linked-in dependencies).
    #
    # No hardcoded default for either setting, same reasoning as
    # smtp_host/smtp_from above: a third-party external service has no sane
    # in-repo default. Left unset, the console honestly reports
    # `connector.status == "not_configured"` rather than a fabricated
    # all-zero "healthy" state. Osquery/Wazuh/ClamAV are explicitly out of
    # scope for A-11 (see task brief) and get no Settings fields yet.
    crowdsec_lapi_url: str | None = None
    crowdsec_api_key: str | None = None

    # A-17: ClamAV (GPLv2) — signature scanner completing the `av` console's
    # sources (osquery A-15 process telemetry is the first; Wazuh A-16 is
    # still pending). Runs as a fully separate Docker container
    # (infra/security/clamav/), speaking clamd's own line protocol over a
    # plain TCP socket — never linked into this process, same licence-gate
    # shape as CrowdSec (services/mcp/security_connectors/clamav.py).
    #
    # Unlike crowdsec_lapi_url/crowdsec_api_key above, clamd normally needs
    # no credential at all once its container is up — a bare host:port is
    # enough, so nothing would otherwise stop a fresh install from
    # immediately reporting "unreachable" instead of an honest "you haven't
    # turned this on yet". clamav_enabled is that explicit signal: defaults
    # to False, same "safe default, explicit opt-in" reasoning as
    # ai_enabled/backup_enabled above — this connector only ever opens a
    # socket once an operator has deliberately turned it on (normally right
    # after standing up infra/security/clamav/docker-compose.yml). host/port
    # DO get real defaults (unlike the crowdsec pair) because they have a
    # genuinely sane one: 127.0.0.1:3310 is clamd's own documented default
    # port, and exactly what that docker-compose.yml publishes.
    clamav_enabled: bool = False
    clamav_host: str = "127.0.0.1"
    clamav_port: int = 3310
    # Quarantined files are moved (never deleted, see clamav.py) under this
    # directory — relative to REPO_ROOT by default, same convention as
    # backup_dir/log_file above, and already covered by the app's own
    # data/ Docker volume (see root docker-compose.yml), so quarantined
    # files survive a container restart exactly like the SQLite DB does.
    clamav_quarantine_dir: str = "data/quarantine"

    # A-16: Wazuh Manager (GPLv2) — the "Журналы ОС" console's real data
    # source (services/mcp/security_connectors/wazuh.py): FIM (file
    # integrity monitoring) findings read through the manager's own REST
    # API. Runs as a fully separate Docker container
    # (infra/security/wazuh/), speaking plain HTTP to port 55000 (TLS
    # deliberately disabled on that container's API — see
    # infra/security/wazuh/config/api.yaml — so this connector needs no
    # `verify=False`/self-signed-cert workaround) — never linked into this
    # process, same licence-gate shape as CrowdSec/ClamAV.
    #
    # No hardcoded default for any of the three, same reasoning as
    # crowdsec_lapi_url/crowdsec_api_key above: a third-party external
    # service's own credentials have no sane in-repo default, and unlike
    # clamav_host/clamav_port (a bare host:port with no credential to
    # leak), a wrong-but-present wazuh_api_url with empty username/password
    # would otherwise make a fresh install immediately attempt (and fail)
    # an authentication call instead of honestly reporting
    # "not_configured". wazuh_agent_id DOES get a real default: "000" is
    # Wazuh's own reserved id for the manager's built-in local agent (it
    # monitors itself — see infra/security/wazuh/docker-compose.yml's
    # header comment for why this deployment never registers a second,
    # separate agent), the only agent id this deployment's
    # docker-compose.yml ever produces.
    wazuh_api_url: str | None = None
    wazuh_api_username: str | None = None
    wazuh_api_password: str | None = None
    wazuh_agent_id: str = "000"

    @property
    def trusted_contact_emails_list(self) -> list[str]:
        return [
            email.strip()
            for email in self.trusted_contact_emails.split(",")
            if email.strip()
        ]

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.cors_allowed_origins.split(",")
            if origin.strip()
        ]

    @property
    def resolved_database_url(self) -> str:
        """Resolve a relative SQLite file path against REPO_ROOT, not
        process cwd — or against the platformdirs data dir when
        `is_packaged()` (A-19), same split as jwt_secret_file() etc. in
        this module. `is_packaged()` is re-checked on every access (not
        cached), so mocking `sys.frozen`/`sys._MEIPASS` in a test is
        observed immediately, with no import/reload required."""
        prefix = "sqlite+aiosqlite:///"
        if self.database_url.startswith(prefix):
            relative_path = self.database_url[len(prefix):]
            if not relative_path.startswith("/"):
                base = _packaged_data_dir() if is_packaged() else REPO_ROOT
                absolute_path = (base / relative_path).resolve()
                return f"{prefix}{absolute_path}"
        return self.database_url

    @property
    def resolved_log_file(self) -> str | None:
        """Resolve a relative log file path against REPO_ROOT, not process
        cwd — or against the platformdirs LOG dir when `is_packaged()`
        (A-19). Deliberately a *different* packaged-mode base than the
        other three resolved_* properties below (platformdirs' own
        data-vs-log directory distinction, see _packaged_log_dir()).

        Empty string disables file logging (console-only) — same "falsy
        means off" convention as jwt_secret/bootstrap_admin_* above.
        """
        if not self.log_file:
            return None
        path = Path(self.log_file)
        if not path.is_absolute():
            base = _packaged_log_dir() if is_packaged() else REPO_ROOT
            path = (base / path).resolve()
        return str(path)

    @property
    def resolved_backup_dir(self) -> Path:
        """Resolve a relative backup dir against REPO_ROOT, not process cwd
        — or against the platformdirs data dir when `is_packaged()`
        (A-19), same convention as resolved_database_url above."""
        path = Path(self.backup_dir)
        if not path.is_absolute():
            base = _packaged_data_dir() if is_packaged() else REPO_ROOT
            path = (base / path).resolve()
        return path

    @property
    def resolved_clamav_quarantine_dir(self) -> Path:
        """Resolve a relative quarantine dir against REPO_ROOT, not process
        cwd — or against the platformdirs data dir when `is_packaged()`
        (A-19), same convention as resolved_backup_dir above."""
        path = Path(self.clamav_quarantine_dir)
        if not path.is_absolute():
            base = _packaged_data_dir() if is_packaged() else REPO_ROOT
            path = (base / path).resolve()
        return path

    @property
    def resolved_sqlite_path(self) -> Path | None:
        """The on-disk SQLite file path backed by `resolved_database_url`, or
        None when the configured database is not SQLite (e.g. a future
        Postgres URL, §4.5 Phase 3+) — A-12's restic backup only ever
        targets the SQLite file itself, see services/backup/service.py."""
        prefix = "sqlite+aiosqlite:///"
        url = self.resolved_database_url
        if not url.startswith(prefix):
            return None
        return Path(url[len(prefix):])


@lru_cache
def get_settings() -> Settings:
    return Settings()
