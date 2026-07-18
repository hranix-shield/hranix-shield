"""A-20: single, OS-agnostic startup sequence shared by every native
installer build (macOS now; Windows/Linux — A-21/A-22 — reuse this exact
module unchanged, see the "Один launcher, не три реализации" rule in
docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md).

Lives at `server/launcher.py`, a SIBLING of `server/app/` (not inside the
`app` package) — this is the PyInstaller *entry point's* business logic,
not a FastAPI router/service; each OS's packaging wrapper
(`packaging/macos/hranix_shield_app.py` for A-20) imports and calls into
this module rather than re-implementing any of it.

Sequence (`launch()`):
  1. resolve the packaged-vs-dev environment — already fully handled by
     `app.config.is_packaged()`/`resolved_*` (A-19); this module adds two
     things A-19 did not need to: pointing Alembic at the right
     `alembic.ini`/`alembic/` (see `_alembic_config()` below — Alembic has
     no `is_packaged()`-aware resolution of its own), and creating the
     SQLite file's parent directory before anything tries to open it (see
     `_ensure_data_directories()` — a genuinely clean `platformdirs` data
     dir has nothing in it yet, unlike a source checkout's
     `server/data/.gitkeep` or the Docker image's own `mkdir -p`).
  2. apply pending migrations *programmatically* — `alembic.command.upgrade`
     in-process, never `subprocess`/`python -m alembic`: a frozen
     PyInstaller binary has no separate interpreter+`alembic` console
     script reliably reachable the way `docker-entrypoint.sh` assumes.
  3. start `uvicorn` serving the real app in a background thread — the
     macOS `rumps` event loop (and any future Windows/Linux GUI loop) needs
     the *main* thread for itself, so the server cannot simply call
     `uvicorn.run()` on the thread that also has to run a native UI loop.
  4. poll `/health` with retries (not a blind `sleep`) until it answers,
     then let the caller decide what to do next (open a browser, flip a
     menu-bar item to "ready", ...).

Nothing here is macOS-specific — see `packaging/macos/hranix_shield_app.py`
for the `rumps` menu-bar shell that wraps this module for A-20.
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path

import uvicorn
from alembic import command
from alembic.config import Config

from app.app_factory import create_app
from app.config import REPO_ROOT, Settings, get_settings, is_packaged

logger = logging.getLogger(__name__)


def bundled_root() -> Path:
    """Directory containing this build's `alembic.ini` / `alembic/` /
    `app/static/` resources.

    Packaged (`is_packaged()`, A-19's PyInstaller detection): PyInstaller's
    bootloader sets `sys._MEIPASS` to wherever it unpacked/mounted this
    build's `datas` — `hranix-shield.spec` (A-20) puts `alembic.ini`,
    `alembic/`, and `app/` directly there (see that file's `datas=[...]`),
    so this mirrors the source layout one level down from `server/`.

    Not packaged (venv/Docker/pytest, unchanged by this task): `REPO_ROOT
    / "server"` — the same directory `alembic.ini`/`app/` already live in
    today (see `app/config.py`'s own `REPO_ROOT` and the Dockerfile's
    `WORKDIR /app/server` comment for why `server/` is the fixed anchor,
    not `REPO_ROOT` itself).
    """
    if is_packaged():
        # mypy/pyright don't know about PyInstaller's bootloader attribute;
        # is_packaged() already confirmed hasattr(sys, "_MEIPASS") above.
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return REPO_ROOT / "server"


def _alembic_config() -> Config:
    """Builds an in-process Alembic `Config` pointed at this build's own
    `alembic.ini`/`alembic/` (see `bundled_root()`).

    `alembic.ini`'s `script_location = %(here)s/alembic` only resolves
    correctly when Alembic is invoked as a CLI from that file's own
    directory (`%(here)s` is relative to `-c`'s path) — calling
    `command.upgrade()` in-process from an arbitrary cwd (guaranteed to be
    true for the packaged binary, and not something this module should
    assume even in dev) does not reliably reproduce that, so
    `script_location` is set explicitly here rather than trusted to
    `%(here)s` alone (flagged as a "check after first build" risk in the
    A-20 task brief — confirmed live: without this explicit override,
    `command.upgrade()` run from a cwd other than `server/` raises
    `FileNotFoundError` looking for `./alembic`, not `server/alembic`).
    """
    root = bundled_root()
    cfg = Config(str(root / "alembic.ini"))
    cfg.set_main_option("script_location", str(root / "alembic"))
    return cfg


def _ensure_data_directories(settings: Settings) -> None:
    """Creates the on-disk directory this app's very first run on a clean
    machine needs before ANYTHING else can work — the SQLite database
    file's own parent directory.

    Dev/Docker never surface this gap: a source checkout ships
    `server/data/.gitkeep` (so `data/` already exists before the app ever
    runs), and the Docker image's build step (`Dockerfile`: `mkdir -p
    /app/data ...`) does the same for the container. A packaged install
    has neither — `platformdirs.user_data_dir(...)` (A-19,
    `app.config._packaged_data_dir()`) returns a path nothing has ever
    created on a genuinely clean machine, and neither
    `sqlalchemy.create_async_engine` (`app/db/session.py`) nor Alembic's
    `env.py` create a missing parent directory themselves — both simply
    hand the resolved path straight to `aiosqlite`, which refuses to
    create one. Confirmed live building this task: the very first run of
    the packaged `.app` on a machine that had never run it before failed
    at the migrations step with `sqlite3.OperationalError: unable to open
    database file` — not a hypothetical, an actual crash — see the A-20
    task report.

    Every OTHER directory this app writes under (`jwt_secret_file()`'s and
    `restic_password_file()`'s own parent, the restic repo dir, the ClamAV
    quarantine dir) already creates itself lazily at first use elsewhere
    in `app/` (see `services.auth.resolve_jwt_secret`,
    `services.backup.restic_client`, `services.mcp.security_connectors.clamav`)
    — this function deliberately does not duplicate that, only the one
    directory nothing else was creating.
    """
    sqlite_path = settings.resolved_sqlite_path
    if sqlite_path is not None:
        sqlite_path.parent.mkdir(parents=True, exist_ok=True)


def run_migrations() -> None:
    """Applies pending migrations up to `head`, in-process (see module
    docstring for why this is never a `subprocess`/`python -m alembic`
    call). Idempotent, same as `docker-entrypoint.sh`'s `alembic upgrade
    head`: a fresh DB is created+migrated on first run, an already-current
    DB is a fast no-op on every later start.

    `alembic/env.py` itself needed no changes for this (it already calls
    `get_settings().resolved_database_url`, mode-aware since A-19) — this
    function only has to get Alembic to find its *own* `alembic.ini`/
    `alembic/` scripts in a frozen bundle, not the database URL.
    """
    logger.info("launcher: applying database migrations (target=head)")
    command.upgrade(_alembic_config(), "head")
    logger.info("launcher: migrations up to date")


def _start_server(settings: Settings) -> tuple[uvicorn.Server, threading.Thread]:
    """Starts `uvicorn` serving the real app on a background thread.

    `uvicorn.Server.run()` (not the `uvicorn.run(...)` convenience
    function, and never `reload=True` — reload spawns a *second* process
    via `multiprocessing`/`subprocess`, meaningless and not safely
    supported for a frozen single-binary app) builds its own asyncio event
    loop for that thread via `asyncio.run()`, independent of whatever loop
    (or none) the caller's own thread runs. `uvicorn.Server` skips
    installing OS signal handlers when it detects it is not running on the
    process's main thread (see uvicorn's own `Server.install_signal_handlers`),
    which is exactly the documented, supported way to embed it — the
    caller is responsible for signalling shutdown via
    `LauncherHandle.stop()` below instead of relying on SIGINT/SIGTERM.
    """
    app = create_app()
    config = uvicorn.Config(
        app,
        host=settings.server_host,
        port=settings.server_port,
        log_config=None,  # app.infra.logger_config already configured logging (create_app())
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run, name="hranix-shield-uvicorn", daemon=True
    )
    thread.start()
    return server, thread


def _wait_for_health(base_url: str, *, timeout: float) -> bool:
    """Polls `GET {base_url}/health` with short retries instead of a blind
    `sleep` before declaring the server up (see this module's docstring
    point 4) — plain `urllib.request` (stdlib): the only other HTTP client
    already used at runtime anywhere in `app/` is `httpx`
    (`services/inference/ollama_backend.py`), which is not wired into any
    router in Phase 0 and is deliberately not added to
    `requirements-packaged.txt` for that reason (A-20 task brief) — no
    reason to pull it in just for this one local polling loop.
    """
    deadline = time.monotonic() + timeout
    url = f"{base_url}/health"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:  # noqa: S310 (fixed http(s) localhost URL, not user input)
                if response.status == 200:
                    body = json.loads(response.read().decode("utf-8"))
                    if body.get("status") == "ok":
                        return True
        except (urllib.error.URLError, ConnectionError, TimeoutError, ValueError):
            pass
        time.sleep(0.2)
    return False


@dataclass
class LauncherHandle:
    """Returned by `launch()` — lets the OS-specific packaging wrapper (the
    `rumps` "Выход" menu item, for A-20) shut the background server down
    cleanly instead of just killing the process."""

    server: uvicorn.Server
    thread: threading.Thread
    base_url: str
    healthy: bool

    def stop(self, *, timeout: float = 5.0) -> None:
        """Signals uvicorn's `Server` to exit its serve loop and waits for
        the background thread to finish — the documented, supported way to
        stop a `uvicorn.Server` started via `.run()` on another thread
        (setting `should_exit` is what `Server.serve()`'s own loop polls,
        the in-process equivalent of the SIGTERM handling it would
        otherwise install on the main thread)."""
        self.server.should_exit = True
        self.thread.join(timeout=timeout)


def launch(*, open_browser: bool = True, health_timeout: float = 10.0) -> LauncherHandle:
    """Runs the full sequence described in this module's docstring and
    returns a `LauncherHandle` for the caller to hold onto (and eventually
    `.stop()`). Never raises on a slow/failed health check — a False
    `LauncherHandle.healthy` is reported to the caller (which decides how
    to surface that, e.g. the macOS menu bar wrapper logs it and still
    offers "Открыть панель" rather than pretending nothing is wrong) rather
    than an exception that would otherwise crash a GUI event loop that
    hasn't started yet.
    """
    settings = get_settings()
    _ensure_data_directories(settings)
    run_migrations()
    server, thread = _start_server(settings)
    base_url = f"http://{settings.server_host}:{settings.server_port}"
    healthy = _wait_for_health(base_url, timeout=health_timeout)
    if not healthy:
        logger.warning(
            "launcher: /health did not answer within %.1fs — opening the "
            "panel anyway, but it may not be ready yet",
            health_timeout,
        )
    if open_browser:
        webbrowser.open(f"{base_url}/panel/")
    return LauncherHandle(server=server, thread=thread, base_url=base_url, healthy=healthy)


if __name__ == "__main__":
    # Plain-console fallback entry point (no menu-bar/tray UI) — useful for
    # smoke-testing this module directly (`python server/launcher.py`,
    # packaged or not) without going through any OS-specific wrapper.
    logging.basicConfig(level=logging.INFO)
    handle = launch()
    logger.info(
        "launcher: serving on %s (healthy=%s) — Ctrl+C to stop",
        handle.base_url,
        handle.healthy,
    )
    try:
        while handle.thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        handle.stop()
