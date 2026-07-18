"""A-20: macOS menu-bar shell around `server/launcher.py` (see that
module's docstring for the OS-agnostic startup sequence this wraps —
resolve environment -> migrate -> start uvicorn in a background thread ->
poll /health -> open the panel in the system browser).

This file IS the PyInstaller entry point built by `hranix-shield.spec`
(`Analysis(['packaging/macos/hranix_shield_app.py'], ...)`) — it contains
only macOS-specific menu-bar glue, never a second copy of the startup
sequence itself (see the "Один launcher" rule in
docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md).

Target user is a non-technical executive (see CLAUDE.md's целевая
аудитория) — the entire UI surface is one status-bar icon with two items:
"Открыть панель" (opens the real panel in the system browser) and "Выход"
(stops uvicorn cleanly, then quits). No Dock icon: `LSUIElement=True` is
set in `hranix-shield.spec`'s `BUNDLE(..., info_plist={...})`, not here —
"an icon that's just there while it works" is the whole mental model for
this target user, no window to manage.

Can also be run directly, unpackaged, for iterating on the menu-bar shell
without a full PyInstaller rebuild each time: `server/venv/bin/python -m
pip install rumps` (BSD-3-Clause — see `server/requirements-packaged.txt`'s
comment for where this was verified) then `python
packaging/macos/hranix_shield_app.py` from a normal dev checkout.
"""

from __future__ import annotations

import logging
import sys
import webbrowser
from pathlib import Path

import rumps

# Only needed for the unpackaged dev-run case above: a frozen PyInstaller
# build already has `server/launcher.py` (and, via it, `app/`) collected
# onto its own sys.path by `hranix-shield.spec`'s `pathex` — see that
# file — so this adjustment is a no-op (and must stay a no-op: `__file__`
# inside a frozen bundle does not sit under a real "packaging/macos/../.."
# repo layout, so blindly running this unconditionally would compute a
# nonsense path in the packaged build).
if not getattr(sys, "frozen", False):
    _SERVER_DIR = Path(__file__).resolve().parents[2] / "server"
    if str(_SERVER_DIR) not in sys.path:
        sys.path.insert(0, str(_SERVER_DIR))

from launcher import LauncherHandle, launch  # noqa: E402 (see sys.path adjustment above)

logger = logging.getLogger(__name__)

_OPEN_PANEL = "Открыть панель"
_QUIT = "Выход"


class HranixShieldMenuBarApp(rumps.App):
    """The whole panel-facing UI for A-20: one status-bar item, two menu
    entries. `handle` is set once, synchronously, in `main()` below —
    before `run()` (and therefore before either menu callback can possibly
    fire), so neither callback needs to defensively handle a `None` case.
    """

    def __init__(self) -> None:
        super().__init__(
            "Hranix Shield",
            title="Hranix Shield",
            # Suppress rumps' own default "Quit" item — our own `_QUIT`
            # item below replaces it so shutdown can stop uvicorn first
            # (see `quit_clicked`), not just call quit_application() directly.
            quit_button=None,
            menu=[_OPEN_PANEL, _QUIT],
        )
        self.handle: LauncherHandle | None = None

    @rumps.clicked(_OPEN_PANEL)
    def open_panel_clicked(self, _sender: "rumps.MenuItem") -> None:
        if self.handle is None:
            rumps.alert("Hranix Shield", "Сервер ещё запускается — попробуйте через несколько секунд.")
            return
        webbrowser.open(f"{self.handle.base_url}/panel/")

    @rumps.clicked(_QUIT)
    def quit_clicked(self, _sender: "rumps.MenuItem") -> None:
        if self.handle is not None:
            logger.info("menu bar: stopping server before quit")
            self.handle.stop()
        rumps.quit_application()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    app = HranixShieldMenuBarApp()
    # Synchronous, on the main thread, BEFORE app.run() below hands the
    # main thread over to Cocoa's event loop (rumps.App.run() blocks it —
    # see that method's own docstring) — launch() itself starts uvicorn on
    # a background thread and only *this* call (migrations + the /health
    # poll) is synchronous, so the icon appears a few seconds after the
    # app is opened, once the backend is confirmed up (or the health
    # timeout has honestly elapsed — see launch()'s docstring for why that
    # is reported, not swallowed).
    app.handle = launch(open_browser=True, health_timeout=15.0)
    if not app.handle.healthy:
        logger.warning(
            "menu bar: starting anyway despite /health not answering in time — "
            "'%s' may show an error the first time it's clicked",
            _OPEN_PANEL,
        )
    app.run()


if __name__ == "__main__":
    main()
