"""A-25: first-run check for the official Wazuh agent (GPLv2, an external
OS service — never linked into this process, same licence-gate shape
CLAUDE.md already applies to the Wazuh Manager's own separate Docker
container, see `server/app/services/mcp/security_connectors/wazuh.py`).

Closes the gap A-16/A-19..A-22 left open: the "Журналы ОС" console's FIM
data used to come only from the Manager container watching ITSELF
(`Settings.wazuh_agent_id`'s default `"000"`, `infra/security/wazuh/
docker-compose.yml`'s Decision #2's `/monitored/data`,`/monitored/logs`
bind-mounts) — a native macOS install writes its real data to
`~/Library/Application Support/Hranix Shield/...` (A-19's
`app.config._packaged_data_dir()`), which the Manager container can never
see. This module gets a REAL native agent enrolled and watching THAT real
directory instead.

Architectural decision (а) vs (б) — see
docs/план-спецификация-фаза-0-контур-безопасности-100-2026-07-18.md's
"A-25" section for the exact wording of both options:

  (а) replace A-20's already-built, already-documented `.dmg`/onedir `.app`
      pipeline with a `.pkg` + `pkgbuild`/`productbuild` installer that
      bundles the Wazuh agent's own vendor `.pkg` as a second component,
      installed by one combined installer.
  (б) keep A-20's `.dmg` pipeline entirely as-is; the already-installed
      `.app` checks, on its very first launch only, whether the agent is
      present, and if not, shows ONE system dialog offering to install it.

**(б) was chosen**, for three concrete reasons:
  1. It does not touch or re-litigate A-20's already-built, already-
     reviewed `.dmg`/onedir pipeline (onedir-vs-onefile investigation,
     Gatekeeper workaround doc, etc.) — (а) would have made all of that
     work moot for no functional gain, a large blast radius for a
     narrowly-scoped task.
  2. It decouples "install Hranix Shield" from "install a persistent
     system-wide GPLv2 EDR daemon" — a user who does not want the latter
     can decline (see `maybe_setup_wazuh_agent`'s `prompt` callback) without
     that blocking the base product at all. A merged `.pkg` (а) would make
     the Wazuh agent an unskippable gate in front of the ENTIRE product's
     install, a materially different (and more invasive) product decision
     than this task was scoped to make unilaterally.
  3. It matches the "visible, one-time, standard OS prompt — never a
     silent background privilege escalation" principle used everywhere
     else in this project (see CLAUDE.md, A-18's `os_firewall.py`/
     `os_disk_encryption.py`): `osascript ... with administrator
     privileges` pops the exact same system authorization dialog macOS
     shows for any other admin action — the standard mechanism the task
     brief itself named, not a workaround invented here.

Every side-effecting step below is a separate, independently testable
function (module-level, no hidden global state) so
`packaging/macos/test/test_wazuh_agent_setup.py` can exercise the real
logic (architecture selection, marker persistence, config.env upsert,
shell-script construction, manager-host parsing) with the GUI (`rumps`)
and the actual privilege escalation (`osascript`) both replaced by plain
Python callables — a real GUI dialog and a real macOS admin-password
prompt both require a human physically at the keyboard, which no
automated test in this repository can supply (see this task's own report
for the exact same limitation on the LIVE end-to-end path).
"""

from __future__ import annotations

import asyncio
import logging
import platform
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import platformdirs

from app.config import APP_AUTHOR, APP_NAME, Settings, get_settings, resolve_env_file
from app.services.mcp.security_connectors.wazuh import create_wazuh_client

logger = logging.getLogger(__name__)

# Pinned to the SAME version as infra/security/wazuh/docker-compose.yml's
# `wazuh/wazuh-manager:4.14.6` image tag — Wazuh's own documentation
# recommends agent/manager version parity, and this is also the exact
# version verified live against documentation.wazuh.com while building
# this task (2026-07-18): the macOS agent package for THIS version really
# exists at the URL `_agent_pkg_url()` builds
# (https://packages.wazuh.com/4.x/macos/wazuh-agent-4.14.6-1.<arch>.pkg,
# confirmed via a live HTTPS HEAD request, 7.6MB, HTTP 200).
AGENT_VERSION = "4.14.6"

# Official, root-owned install locations the vendor `.pkg` creates —
# confirmed against documentation.wazuh.com's macOS agent guide
# (2026-07-18): default install path `/Library/Ossec/`, LaunchDaemon
# `com.wazuh.agent.plist`.
AGENT_CONTROL_BINARY = Path("/Library/Ossec/bin/wazuh-control")
AGENT_CONF_PATH = Path("/Library/Ossec/etc/ossec.conf")
AGENT_LAUNCH_DAEMON_PLIST = Path("/Library/LaunchDaemons/com.wazuh.agent.plist")

# The official package installer reads this exact path (NOT a real shell
# environment variable — a marker FILE at a fixed, documented location)
# to auto-configure `<server><address>`/enrollment during install —
# confirmed against documentation.wazuh.com's macOS agent guide, matches
# the exact mechanism the CLI walkthrough there uses
# (`echo "WAZUH_MANAGER='...'" > /tmp/wazuh_envs`).
WAZUH_ENVS_FILE = Path("/tmp/wazuh_envs")

_PROMPTED_MARKER_NAME = ".wazuh_agent_prompted"


def is_agent_installed() -> bool:
    """True iff the official Wazuh agent's own control binary exists on
    disk. Deliberately a plain existence check, not `launchctl print
    system/com.wazuh.agent` (which needs no special privilege either, but
    a stopped-but-installed agent should still count as "already handled"
    here — this function answers "was this ever installed", not "is it
    currently running")."""
    return AGENT_CONTROL_BINARY.exists()


def _data_dir() -> Path:
    """Same `platformdirs` call `app.config._packaged_data_dir()` makes
    (A-19) — duplicated here (rather than importing that underscored,
    "private" helper) so this packaging-only module stays decoupled from
    `config.py`'s own internal naming, using only its two PUBLIC
    constants (`APP_NAME`/`APP_AUTHOR`)."""
    return Path(platformdirs.user_data_dir(APP_NAME, APP_AUTHOR))


def prompted_marker_path() -> Path:
    return _data_dir() / _PROMPTED_MARKER_NAME


def already_prompted() -> bool:
    return prompted_marker_path().exists()


def mark_prompted() -> None:
    """Idempotent, one-time marker — per the task brief's own wording,
    the first-run check happens once ever (not "once per launch until
    installed"), regardless of whether the user accepts or declines."""
    path = prompted_marker_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("prompted\n", encoding="utf-8")


def agent_display_name() -> str:
    """Deterministic per-machine agent name, used both as
    `WAZUH_AGENT_NAME` (so `authd` records it) and later to look the
    resulting agent id back up (`get_agent_id_by_name`,
    `discover_and_persist_agent_id` below)."""
    return f"hranix-shield-{socket.gethostname()}"


def _agent_pkg_arch() -> str:
    """Maps `platform.machine()` to the two architecture tokens
    documentation.wazuh.com's macOS package filenames use
    (`wazuh-agent-<version>-1.<arch>.pkg`) — confirmed live 2026-07-18:
    `arm64` for Apple Silicon, `intel64` for Intel Macs (everything else
    `platform.machine()` could plausibly report on macOS falls back to
    `intel64`, matching Rosetta-translated processes reporting `x86_64`)."""
    return "arm64" if platform.machine() == "arm64" else "intel64"


def agent_pkg_filename() -> str:
    return f"wazuh-agent-{AGENT_VERSION}-1.{_agent_pkg_arch()}.pkg"


def agent_pkg_url() -> str:
    return f"https://packages.wazuh.com/4.x/macos/{agent_pkg_filename()}"


def download_agent_pkg(dest_dir: Path) -> Path:
    """Downloads the real vendor `.pkg` from Wazuh's own package server
    into `dest_dir` (a caller-owned, short-lived temp directory — see
    `_install_worker` below) and returns the local path.

    Plain `urllib.request` (stdlib), not `httpx`: same reasoning as
    `server/launcher.py`'s own `_wait_for_health` — this is a single,
    fixed-URL, non-interactive GET with no reason to pull in a second HTTP
    client just for this one call.

    No published checksum exists to verify against (checked live
    2026-07-18: `<url>.sha256`/`.sha512` both return HTTP 403 from
    Wazuh's own CDN) — integrity here rests on HTTPS + the hostname being
    the vendor's own official domain, the same trust boundary this
    project already extends to `docker pull wazuh/wazuh-manager:...` in
    `infra/security/wazuh/docker-compose.yml`.
    """
    url = agent_pkg_url()
    dest = dest_dir / agent_pkg_filename()
    logger.info("wazuh_agent_setup: downloading %s", url)
    with urllib.request.urlopen(url, timeout=60) as response, open(dest, "wb") as f:  # noqa: S310 (fixed vendor URL, not user input)
        f.write(response.read())
    return dest


def write_wazuh_envs_file(*, manager_host: str, agent_name: str, path: Path = WAZUH_ENVS_FILE) -> None:
    """Writes the marker file the vendor `.pkg`'s own install scripts read
    to auto-configure enrollment (see `WAZUH_ENVS_FILE`'s docstring) —
    single-quoted `KEY='value'` lines, matching
    documentation.wazuh.com's own documented format exactly."""
    path.write_text(
        f"WAZUH_MANAGER='{manager_host}'\n"
        f"WAZUH_REGISTRATION_SERVER='{manager_host}'\n"
        f"WAZUH_AGENT_NAME='{agent_name}'\n",
        encoding="utf-8",
    )


def build_privileged_setup_script(*, pkg_path: Path, data_dir: Path, log_dir: Path) -> str:
    """Builds the bash script this module runs ONCE, elevated (see
    `run_privileged_install` below), that does everything the vendor
    `.pkg` install needs plus this project's own local FIM configuration:

      1. `installer -pkg ... -target /` — the real, official install
         (picks up `WAZUH_ENVS_FILE` written just before this runs).
      2. Inject THIS project's own `<syscheck><directories>` entries into
         the agent's own local config (`AGENT_CONF_PATH` —
         `/Library/Ossec/etc/ossec.conf`, the AGENT's config, NOT the
         Manager's `infra/security/wazuh/config/ossec.conf` — two
         different files with the same name, see this task's own brief
         for why that distinction matters) — pointed at the REAL
         platformdirs data/log dirs (A-19), never the Docker-only
         `/monitored/*` paths A-16/Decision #2 used. Idempotent: the
         `grep -qF` guard skips the `sed` on a re-run that already has it
         (e.g. a retried/failed prior attempt).
      3. `launchctl bootstrap system ...plist` starts the daemon for the
         FIRST time — documentation.wazuh.com's own CLI walkthrough lists
         this as a required separate step after `installer`, confirmed
         live (2026-07-18) against the fetched page: the vendor `.pkg`
         does not appear to auto-start it. Falls back to `launchctl
         kickstart -k` (restart) if bootstrap fails because it is already
         loaded from an earlier attempt.

    A single bash script file (not one giant inline command string) so
    `osascript ... with administrator privileges` only has to quote ONE
    thing (the script's own path), and so this function's OUTPUT is
    itself a plain string this module's tests can assert against without
    any privilege escalation at all.
    """
    quoted_pkg = str(pkg_path).replace('"', '\\"')
    quoted_data_dir = str(data_dir).replace('"', '\\"')
    quoted_log_dir = str(log_dir).replace('"', '\\"')
    return (
        "#!/bin/bash\n"
        "set -e\n"
        f'/usr/sbin/installer -pkg "{quoted_pkg}" -target /\n'
        f'CONF="{AGENT_CONF_PATH}"\n'
        f'DATA_DIR="{quoted_data_dir}"\n'
        f'LOG_DIR="{quoted_log_dir}"\n'
        'if [ -f "$CONF" ] && ! grep -qF "$DATA_DIR" "$CONF"; then\n'
        '  /usr/bin/sed -i \'\' "s#</syscheck>#'
        '    <directories realtime=\\"yes\\" report_changes=\\"yes\\" check_all=\\"yes\\">${DATA_DIR}</directories>\\n'
        '    <directories realtime=\\"yes\\" report_changes=\\"yes\\" check_all=\\"yes\\">${LOG_DIR}</directories>\\n'
        '  </syscheck>#" "$CONF"\n'
        "fi\n"
        # Real bug found live (2026-07-18, not hypothetical): the vendor
        # .pkg's OWN postinstall script already `launchctl load`s the
        # daemon as part of `installer -pkg` above, on this exact machine
        # — so by the time this line used to run `bootstrap` (which only
        # succeeds against a NOT-YET-loaded service), the daemon was
        # already running with the STOCK config read at ITS OWN auto-start
        # moment, before the `sed` edit above ever took effect for it.
        # `bootstrap` failed as expected (already loaded) and fell back to
        # `kickstart -k` — which, empirically, did NOT reliably make the
        # already-running daemon re-read the file either (confirmed: a
        # human running the exact same `sudo launchctl kickstart -k
        # system/com.wazuh.agent` command interactively, moments later,
        # DID fix it — so this is a timing/environment difference in this
        # script's own elevated invocation, not that the command is wrong
        # in principle). The trailing `|| true` then silently swallowed
        # this, so `_install_worker` reported success while FIM was still
        # watching only the stock directories — no error surfaced
        # anywhere, only found by manually creating a file and confirming
        # no realtime event appeared.
        #
        # Fix: unconditionally unload first (`bootout` — a harmless no-op,
        # errors ignored, if it was not loaded at all), THEN bootstrap —
        # this guarantees a genuinely fresh process start that reads
        # `$CONF` from disk at the moment this script runs, never
        # depending on guessing whatever state the vendor installer's own
        # postinstall left the daemon in. No trailing `|| true` on the
        # final `bootstrap` line either: `set -e` means a real failure
        # here now correctly fails this whole script (surfaced to
        # `_install_worker` as a non-zero returncode -> a real "install
        # failed" notification), instead of being swallowed as if nothing
        # went wrong — verified live: after this exact bootout+bootstrap
        # sequence, a real file change in the app's own data directory
        # produced a real FIM event within seconds.
        f'/bin/launchctl bootout system "{AGENT_LAUNCH_DAEMON_PLIST}" 2>/dev/null || true\n'
        f'/bin/launchctl bootstrap system "{AGENT_LAUNCH_DAEMON_PLIST}"\n'
    )


def run_privileged_install(
    script_path: Path,
    *,
    runner: Callable[..., "subprocess.CompletedProcess[str]"] = subprocess.run,
) -> "subprocess.CompletedProcess[str]":
    """Runs `script_path` once, elevated, via macOS's own standard
    authorization dialog (`osascript ... with administrator privileges` —
    the exact mechanism the A-25 task brief itself names) — NOT a silent
    background privilege escalation: this pops the same system password
    prompt any other admin action on macOS shows, and the user can
    decline it (a non-zero/`errAEEventNotPermitted` result from
    `osascript`, surfaced to the caller as a non-zero returncode, same as
    any other failed step here).

    `script_path` (not an inline command string) is what actually gets
    elevated privileges — `do shell script "bash '<path>'"` is the only
    string osascript's own AppleScript parser has to see, so escaping is
    reduced to one path, not this module's much longer script body.
    """
    quoted_path = str(script_path).replace("\\", "\\\\").replace('"', '\\"')
    applescript = f'do shell script "/bin/bash \'{quoted_path}\'" with administrator privileges'
    return runner(["osascript", "-e", applescript], capture_output=True, text=True, timeout=300)


def _manager_host(settings: Settings) -> str:
    """The host part of `settings.wazuh_api_url` if configured, else the
    same `127.0.0.1` default this whole task's docker-compose/README
    changes standardize on (native install + Docker companions on
    loopback, see `infra/security/wazuh/docker-compose.yml`'s Decision
    #3)."""
    if settings.wazuh_api_url:
        parsed = urlparse(settings.wazuh_api_url)
        if parsed.hostname:
            return parsed.hostname
    return "127.0.0.1"


def upsert_config_env(key: str, value: str, *, env_path: Path) -> None:
    """Sets `KEY=value` in the `config.env`/`.env`-style file at
    `env_path` — replaces an existing `KEY=...` line in place (preserving
    every other line and their order), or appends a new one if absent.
    Creates `env_path`'s parent directory (not the file itself, if
    missing — an absent file is treated as "zero existing lines", same
    as `python-dotenv`'s own tolerant-of-a-missing-file behavior) since a
    genuinely fresh install may not have written `config.env` yet."""
    prefix = f"{key}="
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
    replaced = False
    for i, line in enumerate(lines):
        if line.startswith(prefix):
            lines[i] = f"{prefix}{value}"
            replaced = True
            break
    if not replaced:
        lines.append(f"{prefix}{value}")
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


async def _discover_agent_id(
    *, agent_name: str, settings: Settings, timeout: float = 30.0, interval: float = 2.0
) -> str | None:
    """Looks the just-enrolled agent's real numeric id up by name (see
    `WazuhClient.get_agent_id_by_name`, added in this same task) — `None`
    if `Settings.wazuh_api_url`/`wazuh_api_username`/`wazuh_api_password`
    are not (yet) configured (see `packaging/macos/README.md`'s
    documented setup-before-first-run flow: an operator who has not set
    those up yet cannot have this discovered automatically, that is not
    this function's fault to fix), or if the manager has genuinely not
    seen this agent name after `timeout` seconds (e.g. `authd` enrollment
    itself failed).

    Real bug found live (2026-07-18): this used to be a single, immediate
    lookup right after the elevated install script returned — but that
    script's own exit only confirms `launchctl bootstrap`'s command
    syntax ran, not that the daemon's own internal `authd` enrollment
    handshake against the manager has actually COMPLETED yet (a separate,
    genuinely asynchronous step the daemon does on its own after starting)
    — a race, confirmed empirically: calling the exact same lookup by
    hand roughly a minute later found the agent immediately. Polling
    (same "poll, don't guess a fixed delay" discipline `server/launcher.py`'s
    own `_wait_for_health` already established for this project) instead
    of a single attempt closes that race without guessing a single magic
    sleep duration.
    """
    client = create_wazuh_client(settings)
    if client is None:
        return None
    try:
        deadline = time.monotonic() + timeout
        while True:
            agent_id = await client.get_agent_id_by_name(agent_name)
            if agent_id is not None:
                return agent_id
            if time.monotonic() >= deadline:
                return None
            await asyncio.sleep(interval)
    finally:
        await client.aclose()


def _install_worker(
    *,
    manager_host: str,
    notify: Callable[[str, str], None],
    runner: Callable[..., "subprocess.CompletedProcess[str]"] | None = None,
) -> None:
    """The slow, blocking part (network download + elevated install +
    manager round-trip) — run on a background thread by
    `maybe_setup_wazuh_agent` so the caller's own UI event loop (`rumps`)
    stays responsive. Never raises: every failure path ends in a
    `notify(...)` call instead, matching this whole project's "an
    external companion tool failing must not crash the app" discipline
    (`services/mcp/security_connectors/*.py`)."""
    agent_name = agent_display_name()
    try:
        with tempfile.TemporaryDirectory(prefix="hranix-wazuh-agent-") as tmp:
            tmp_path = Path(tmp)
            pkg_path = download_agent_pkg(tmp_path)
            write_wazuh_envs_file(manager_host=manager_host, agent_name=agent_name)
            settings = get_settings()
            script = build_privileged_setup_script(
                pkg_path=pkg_path,
                data_dir=_data_dir(),
                log_dir=Path(platformdirs.user_log_dir(APP_NAME, APP_AUTHOR)),
            )
            script_path = tmp_path / "hranix-wazuh-agent-install.sh"
            script_path.write_text(script, encoding="utf-8")
            result = (runner or run_privileged_install)(script_path)
            if result.returncode != 0:
                logger.error(
                    "wazuh_agent_setup: privileged install failed (rc=%s): %s",
                    result.returncode,
                    getattr(result, "stderr", ""),
                )
                notify(
                    "Не удалось установить Wazuh-агент",
                    "Установка отменена или завершилась ошибкой — консоль «Журналы ОС» "
                    "продолжит показывать только самомониторинг Manager, пока агент не "
                    "будет установлен вручную.",
                )
                return

        agent_id = asyncio.run(_discover_agent_id(agent_name=agent_name, settings=settings))
        if agent_id:
            upsert_config_env("WAZUH_AGENT_ID", agent_id, env_path=resolve_env_file())
            notify(
                "Wazuh-агент установлен",
                f"Агент «{agent_name}» зарегистрирован (id {agent_id}) — консоль «Журналы ОС» "
                "теперь наблюдает за реальными файлами этой установки.",
            )
        else:
            notify(
                "Wazuh-агент установлен, id не обнаружен",
                "Агент установлен и должен был зарегистрироваться, но идентификатор не "
                "удалось найти автоматически (проверьте WAZUH_API_URL/USERNAME/PASSWORD в "
                "config.env) — задайте WAZUH_AGENT_ID вручную после проверки `GET /agents`.",
            )
    except Exception:
        logger.exception("wazuh_agent_setup: unexpected failure installing the Wazuh agent")
        notify(
            "Не удалось установить Wazuh-агент",
            "Непредвиденная ошибка при установке — см. логи приложения.",
        )


def maybe_setup_wazuh_agent(
    *,
    prompt: Callable[[str, str], bool],
    notify: Callable[[str, str], None],
    settings: Settings | None = None,
) -> None:
    """Orchestrates the whole first-run flow — call once, synchronously,
    from the packaging wrapper's own startup path (see
    `hranix_shield_app.py`'s `main()`), AFTER `server.launcher.launch()`.

    `prompt`/`notify` are injected rather than importing `rumps` directly
    here, so this module's own logic (which branch runs, what gets
    persisted) is testable without a real GUI session — see this module's
    docstring and `packaging/macos/test/test_wazuh_agent_setup.py`.

    Fast, synchronous checks only happen on this calling thread (presence
    + marker + the consent dialog itself, which IS expected to block
    until the user answers — same as any other first-run consent dialog);
    the actual download/install (slow, and — critically — the admin
    authorization dialog, which must not freeze `rumps`' own event loop
    while it waits) runs on a background thread via `_install_worker`.
    """
    if already_prompted():
        return
    if is_agent_installed():
        # Already installed by some other means (a prior run that
        # completed after marking-but-before... no: mark_prompted() is
        # only ever called from this same function, see below — this
        # branch covers an operator who installed the vendor `.pkg`
        # themselves, outside this flow entirely) — nothing to ask.
        mark_prompted()
        return

    settings = settings or get_settings()
    proceed = prompt(
        "Wazuh — мониторинг целостности файлов",
        "Hranix Shield может установить официальный агент Wazuh (GPLv2, отдельная "
        "системная служба — https://wazuh.com) для отслеживания изменений файлов "
        "приложения в реальном времени. Установить сейчас?",
    )
    mark_prompted()
    if not proceed:
        return

    manager_host = _manager_host(settings)
    threading.Thread(
        target=_install_worker,
        kwargs={"manager_host": manager_host, "notify": notify},
        name="hranix-wazuh-agent-setup",
        daemon=True,
    ).start()
