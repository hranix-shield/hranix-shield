"""A-22: Linux systemd-service shell around `server/launcher.py` (see that
module's docstring for the OS-agnostic startup sequence this wraps —
resolve environment -> migrate -> start uvicorn in a background thread ->
poll /health -> [macOS/A-20 only: open the panel in the system browser]).

This file IS the PyInstaller entry point built by `hranix-shield.spec`
(`Analysis(['packaging/linux/hranix_shield_service.py'], ...)`) — it
contains only Linux-specific service glue, never a second copy of the
startup sequence itself (see the "Один launcher" rule in
docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md).

Two things this file does that `packaging/macos/hranix_shield_app.py` does
NOT need, both from architect decisions fixed in the A-22 task brief before
this was written (not reopened here):

1. **No browser, no GUI at all** (decision #2). The target for the `.deb`
   build is a `systemd` *system* service (decision #1 — not
   `systemctl --user`, see `packaging/linux/hranix-shield.service`'s own
   comments for why), which very often runs on a headless
   Debian/Ubuntu box with no `DISPLAY`/desktop session — `webbrowser.open()`
   would either silently no-op or spew warnings to a log nobody is
   watching. `launch(open_browser=False, ...)` below, and
   `packaging/linux/README.md`, tell the operator to open
   `http://127.0.0.1:8080/panel/` by hand instead.

2. **A real SIGTERM/SIGINT handler on the main thread** (decision #3).
   `server/launcher.py`'s `_start_server()` runs `uvicorn.Server.run()` on
   a background thread specifically *because* uvicorn detects it is not on
   the process's main thread and (correctly, per its own documented
   behaviour) skips installing its own OS signal handlers there — see that
   function's docstring. Nothing in this project installs a SIGTERM
   handler for it except this file. Without one, `systemctl stop` would
   have nothing to catch its request; systemd's `TimeoutStopSec` would
   elapse and it would fall back to SIGKILL — the service technically
   stops either way, but not cleanly (no `LauncherHandle.stop()`, no
   waiting for uvicorn's own graceful-shutdown handling of in-flight
   requests), which is not the standard debian packaging expects of a
   well-behaved unit.

Can also be run directly, unpackaged, from a normal dev checkout, for
iterating on this shell without a full PyInstaller rebuild each time:
`server/venv/bin/python packaging/linux/hranix_shield_service.py` — Ctrl+C
(SIGINT) exercises the exact same shutdown path a packaged install's
`systemctl stop` (SIGTERM) does.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from pathlib import Path
from types import FrameType

# Only needed for the unpackaged dev-run case above: a frozen PyInstaller
# build already has `server/launcher.py` (and, via it, `app/`) collected
# onto its own sys.path by `hranix-shield.spec`'s `pathex` — see that
# file — so this adjustment is a no-op in a packaged build (and must stay
# one: `__file__` inside a frozen bundle does not sit under a real
# "packaging/linux/../.." repo layout, so blindly running this
# unconditionally would compute a nonsense path there). Same guard as
# `packaging/macos/hranix_shield_app.py` uses for the same reason.
if not getattr(sys, "frozen", False):
    _SERVER_DIR = Path(__file__).resolve().parents[2] / "server"
    if str(_SERVER_DIR) not in sys.path:
        sys.path.insert(0, str(_SERVER_DIR))

from launcher import LauncherHandle, launch  # noqa: E402 (see sys.path adjustment above)

logger = logging.getLogger(__name__)

# Set by the signal handler below (installed on the main thread, where
# CPython actually delivers signals — see the `signal` module's own docs:
# "a Python signal handler ... will be called ... from the main thread"),
# read by the polling loop in main(). A threading.Event, not a plain bool,
# so the polling loop can `.wait(timeout=...)` on it instead of a busy loop.
_shutdown_requested = threading.Event()


def _handle_signal(signum: int, _frame: FrameType | None) -> None:
    logger.info(
        "service: received %s — stopping (systemctl stop / Ctrl+C)",
        signal.Signals(signum).name,
    )
    _shutdown_requested.set()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    handle: LauncherHandle = launch(open_browser=False, health_timeout=15.0)
    if not handle.healthy:
        logger.warning(
            "service: /health did not answer within the startup timeout — "
            "continuing anyway (see launcher.launch()'s docstring); check "
            "the log above for what failed"
        )
    logger.info(
        "service: serving on %s — open it manually in a browser (see "
        "packaging/linux/README.md); waiting for SIGTERM/SIGINT to stop",
        handle.base_url,
    )

    # Block the main thread until either a signal sets the event above, or
    # the uvicorn background thread dies on its own (e.g. an unhandled
    # startup exception inside create_app()) — whichever comes first, so a
    # crashed server thread does not leave this process hanging forever
    # with nothing left to catch a signal for. `wait(timeout=...)`, not a
    # blocking `Event.wait()` with no timeout, so this loop also notices
    # the thread dying instead of only reacting to signals.
    while not _shutdown_requested.is_set() and handle.thread.is_alive():
        _shutdown_requested.wait(timeout=0.5)

    if not handle.thread.is_alive() and not _shutdown_requested.is_set():
        logger.error("service: uvicorn thread exited unexpectedly — exiting with an error status")
        sys.exit(1)

    handle.stop()
    logger.info("service: stopped cleanly")


if __name__ == "__main__":
    main()
