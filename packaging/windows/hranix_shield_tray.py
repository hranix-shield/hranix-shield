"""A-21: Windows system-tray shell around `server/launcher.py` (see that
module's docstring for the OS-agnostic startup sequence this wraps —
resolve environment -> migrate -> start uvicorn in a background thread ->
poll /health -> open the panel in the system browser).

This file IS the PyInstaller entry point built by `hranix-shield.spec`
(`Analysis(['packaging/windows/hranix_shield_tray.py'], ...)`) — it
contains only Windows-specific tray-icon glue, never a second copy of the
startup sequence itself (see the "Один launcher" rule in
docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md).

Target user is a non-technical executive on a personal laptop (see
CLAUDE.md's целевая аудитория) — same audience/model as A-20's macOS
menu-bar build, NOT A-22's headless Linux systemd service (architect
decision #1 in the A-21 task brief: a tray icon, not a Windows NT service
via `pywin32`'s `win32serviceutil`). The whole UI surface is one
notification-area icon with two menu entries: "Открыть панель" (opens the
real panel in the system browser) and "Выход" (stops uvicorn cleanly).

LIBRARY HISTORY (read before assuming this always used infi.systray):
this file originally used `pystray`, but that library is LGPLv3 — flagged
by the developer, escalated to the user, who chose to switch to
**`infi.systray`==0.1.12.1 (BSD-3-Clause)** instead — a strictly better
fit for CLAUDE.md's license gate (MIT/Apache/BSD for the platform core).
Verified against infi.systray's own GitHub repo (`Infinidat/infi.systray`,
`develop` branch, `LICENSE` file — BSD 3-Clause, copyright INFINIDAT 2017;
GitHub's own license detector agrees) and its PyPI METADATA (`License:
BSD`, `Classifier: License :: OSI Approved :: BSD License`) — not recalled
from memory. See `server/requirements-packaged.txt`'s own comment for the
full citation, and `packaging/windows/README.md`'s license table.

Two concrete API differences from the `pystray` version this replaces,
both handled below — read these before changing this file again:

1. **`SysTrayIcon`'s `icon` parameter is a PATH TO A REAL `.ico` FILE ON
   DISK** (`infi/systray/traybar.py`'s `_load_icon()`:
   `os.path.isfile(self._icon)`), not an in-memory `PIL.Image.Image` the
   way `pystray.Icon(icon=...)` accepted. `_generate_icon_file()` below
   draws the exact same placeholder shield-with-"H" glyph as before, but
   SAVES it to a real file (under the OS temp dir, regenerated — cheap —
   on every launch) instead of just returning the in-memory image. Pillow
   is therefore still a dependency (see requirements-packaged.txt's own
   comment for why the library swap did not eliminate it, only repurposed
   it — confirmed by `grep`, not assumed, that nothing else in this
   project uses PIL/Pillow).

2. **`SysTrayIcon.start()` is NON-BLOCKING** (`traybar.py`'s `start()`
   spawns its own Win32-message-loop thread and returns immediately —
   unlike `pystray.Icon.run()`/`rumps.App.run()`, both of which block the
   calling thread until told to stop). `main()` below therefore waits on
   its own `threading.Event`, set by the `on_quit` callback — the exact
   same "block the main thread on an Event a callback sets" idiom
   `packaging/linux/hranix_shield_service.py` already uses for its
   SIGTERM/SIGINT handler (there, the event is set by a Unix signal
   handler; here, by infi.systray's own `on_quit` hook — same shape,
   different trigger).

A THIRD, unavoidable quirk of this exact library version worth reading
before being surprised by it in a screenshot: `SysTrayIcon.__init__`
(`traybar.py`) unconditionally appends its OWN `('Quit', None,
SysTrayIcon.QUIT)` menu entry — hardcoded, English, no constructor
parameter to suppress or relabel it. This file's own "Выход" entry (see
`main()` below) is added ALONGSIDE that, not instead of it — the real
tray menu will show BOTH "Выход" (ours, Russian) and "Quit" (the
library's own, English), both fully functional (both trigger the
identical `DestroyWindow` -> `on_quit(...)` path). A cosmetic, unavoidable
duplicate in infi.systray==0.1.12.1's public API, not a bug in this file
— documented here and in README.md rather than hidden. Mapping our own
"Выход" entry to the same `SysTrayIcon.QUIT` sentinel action (not a custom
callback that calls `.shutdown()` itself) is deliberate: a callback
calling `.shutdown()` would try to `.join()` the very message-loop thread
it is running ON (menu callbacks fire from `WndProc`, invoked on that
thread) — a self-join deadlock. Reusing the library's own `QUIT` sentinel
avoids that entirely, since `_execute_menu_option` handles it with a
plain `DestroyWindow` call, not a join.

**Cyrillic menu text — a real, open risk, not silently assumed fine.**
infi.systray binds Win32's ANSI API variants exclusively
(`RegisterWindowMessageA`, `InsertMenuItemA`, ... — see
`infi/systray/win32_adapter.py`'s own module-level bindings), and encodes
all text through its own `encode_for_locale()` helper
(`text.encode(locale.getpreferredencoding(), 'ignore')`). On
`windows-latest`'s default en-US locale (conventionally `cp1252`, which
has NO Cyrillic glyphs at all), this does not raise (the `'ignore'` error
handler silently drops unencodable characters) — but it means the actual
on-screen label for a pure-Cyrillic string like "Открыть панель" likely
renders BLANK, not garbled-but-readable, on an English-locale Windows
install. See `packaging/windows/test/check_tray_locale.py` (run by
`.github/workflows/windows-build.yml`) for the closest thing to a real,
non-interactive measurement of this achievable in CI, and
`packaging/windows/README.md`'s own honesty section for what remains
unverified (actual visual rendering needs a human looking at a real
Windows screen — not something this session or CI can do).

Can also be run directly, unpackaged, from a normal dev checkout, for
iterating on the tray shell without a full PyInstaller rebuild each time:
`server\\venv\\Scripts\\pip install infi.systray Pillow` (see
`server/requirements-packaged.txt` for the exact pinned versions this was
verified against) then `python packaging\\windows\\hranix_shield_tray.py`
— on a NON-Windows machine `infi.systray` itself will fail to import at
all (its `win32_adapter.py` does `ctypes.windll.user32...` at module
level, and `ctypes.windll` does not exist outside Windows), which is
expected: this file only ever runs on Windows, packaged or not.
"""

from __future__ import annotations

import ctypes
import logging
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path

from infi.systray import SysTrayIcon

# Only needed for the unpackaged dev-run case above: a frozen PyInstaller
# build already has `server/launcher.py` (and, via it, `app/`) collected
# onto its own sys.path by `hranix-shield.spec`'s `pathex` — see that
# file — so this adjustment is a no-op in a packaged build (and must stay
# one: `__file__` inside a frozen bundle does not sit under a real
# "packaging/windows/../.." repo layout, so blindly running this
# unconditionally would compute a nonsense path there). Same guard as
# `packaging/macos/hranix_shield_app.py` and
# `packaging/linux/hranix_shield_service.py` use for the same reason.
if not getattr(sys, "frozen", False):
    _SERVER_DIR = Path(__file__).resolve().parents[2] / "server"
    if str(_SERVER_DIR) not in sys.path:
        sys.path.insert(0, str(_SERVER_DIR))

from launcher import LauncherHandle, launch  # noqa: E402 (see sys.path adjustment above)

logger = logging.getLogger(__name__)

_OPEN_PANEL = "Открыть панель"
_DIAGNOSTICS = "Диагностика"
_QUIT = "Выход"
_ICON_FILENAME = "hranix-shield-tray.ico"

# IDYES из Win32 MessageBoxW; MB_-константы — документированные значения
# user32, ctypes-обёрток для них в стандартной библиотеке нет.
_MB_YESNO = 0x4
_MB_ICONQUESTION = 0x20
_MB_ICONINFORMATION = 0x40
_MB_ICONWARNING = 0x30
_MB_TOPMOST = 0x40000
_MB_SETFOREGROUND = 0x10000
_IDYES = 6


def _ask_yes_no(text: str) -> bool:
    """Уведомление-вопрос сторожа («Запустить Docker Desktop?»). Вызывается
    из потока-сторожа — message-loop трея (другой поток) не блокирует."""
    flags = _MB_YESNO | _MB_ICONQUESTION | _MB_TOPMOST | _MB_SETFOREGROUND
    return ctypes.windll.user32.MessageBoxW(0, text, "Hranix Shield", flags) == _IDYES


def _notify(text: str, *, warning: bool = False) -> None:
    icon = _MB_ICONWARNING if warning else _MB_ICONINFORMATION
    flags = icon | _MB_TOPMOST | _MB_SETFOREGROUND
    ctypes.windll.user32.MessageBoxW(0, text, "Hranix Shield", flags)


def _run_watchdog(state: "_TrayState") -> None:
    """Уровень 0 реанимации (план-спецификация A-65): стартовая проверка
    машины и самопомощь — движок Docker лежит, но Desktop установлен →
    вопрос «Запустить?»; контейнеры Down → идемпотентный compose up;
    сервер не поднялся → уведомление с путём журнала. Вся логика решений —
    в app.services.health.watchdog (покрыта автотестами); здесь только
    исполнение: потоки, окна-вопросы, запуск Remediation-функций. Любая
    ошибка сторожа — залогирована и проглочена: сторож не может быть
    причиной неработающего трея."""
    import asyncio

    try:
        from app.services.health import remediation, watchdog

        assessment = asyncio.run(watchdog.gather_startup_assessment())

        if assessment["suggest_start_docker_desktop"]:
            if _ask_yes_no(
                "Docker запущен, но движок не отвечает.\n"
                "Запустить Docker Desktop?"
            ):
                result = asyncio.run(remediation.start_docker_desktop())
                if result["status"] == "ok":
                    _notify("Docker Desktop запускается — это занимает до минуты…")
                    if asyncio.run(watchdog.wait_for_engine()):
                        _notify("Docker-движок поднялся.")
                    else:
                        _notify(
                            "Docker-движок так и не ответил — откройте "
                            "«Диагностику» в меню трея для деталей.",
                            warning=True,
                        )
                else:
                    _notify(
                        "Не удалось запустить Docker Desktop ("
                        + str(result["detail"]) + ").",
                        warning=True,
                    )

        if assessment["suggest_compose_up"]:
            stopped = ", ".join(assessment["containers_absent_or_stopped"])
            _notify(
                "Контейнеры защиты не запущены (" + stopped + ").\n"
                "Поднимаю стек — это может занять несколько минут…"
            )
            bootstrap = asyncio.run(remediation.compose_up_stack())
            if bootstrap["status"] == "ok":
                _notify(
                    "Стек защиты поднят. Коннекторы прочитают настройки "
                    "после перезапуска приложения."
                )
            else:
                logger.info("tray watchdog: compose up result: %s", bootstrap["status"])
                _notify(
                    "Не удалось поднять стек защиты автоматически — "
                    "откройте панель: «Здоровье → Компоненты системы».",
                    warning=True,
                )

        if state.handle is not None and not state.handle.healthy:
            _notify(
                "Сервер панели не ответил вовремя — интерфейс может не "
                "открыться.\nЖурнал: " + watchdog.resolve_assistant_log_path(),
                warning=True,
            )
    except Exception:
        logger.exception("tray: watchdog crashed — ignoring, tray stays alive")


def _generate_icon_file() -> Path:
    """Draws the same placeholder shield-with-"H" glyph the original
    `pystray`-based version of this file drew directly in memory, but
    SAVES it as a real `.ico` file — `SysTrayIcon`'s `icon` parameter is a
    filesystem path (see this module's docstring, point 1), not an
    in-memory image object.

    Written under the OS temp dir (`tempfile.gettempdir()`), not
    `app.config`'s `platformdirs`-resolved data directory: this is a
    disposable, deterministically-regenerated-on-every-launch UI asset,
    not user data (unlike the SQLite DB/secrets under
    `_packaged_data_dir()`) — no `is_packaged()`-aware resolution is
    needed, `tempfile.gettempdir()` is always writable by the current user
    on every OS PyInstaller targets.

    Regenerating (and overwriting) this file on every single launch is a
    deliberate, cheap simplification over trying to cache/reuse it across
    runs — sub-millisecond cost, and it means this function never has to
    reason about a stale or partially-written leftover from a previous
    crashed run.
    """
    from PIL import Image, ImageDraw

    size = 64
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Shield outline: a rectangle tapering to a point at the bottom, the
    # same "security" visual shorthand as the product's own console icons
    # — no brand asset exists yet in Phase 0 (see CLAUDE.md: визуальный
    # дизайн бренда не решён), so the exact fill color here is an
    # arbitrary placeholder, not a locked brand color.
    margin = size * 0.08
    left, right = margin, size - margin
    top = margin
    notch = size * 0.55
    bottom = size - margin
    mid_x = size / 2
    shield = [
        (left, top),
        (right, top),
        (right, notch),
        (mid_x, bottom),
        (left, notch),
    ]
    draw.polygon(shield, fill=(19, 78, 122, 255))

    # Letter "H" as three plain white rectangles (two vertical bars + one
    # horizontal crossbar) rather than rendered text — avoids needing a
    # bundled `.ttf` font file (a real `datas=[...]` entry PyInstaller
    # would otherwise need, the same "must be a real file, not just
    # importable" constraint `hranix-shield.spec` already documents for
    # `app/static/`/`alembic/`) for a placeholder glyph that reads clearly
    # enough at tray-icon sizes without one.
    bar_w = size * 0.10
    h_top = size * 0.28
    h_bottom = size * 0.72
    left_bar_x = size * 0.32
    right_bar_x = size * 0.68 - bar_w
    draw.rectangle([left_bar_x, h_top, left_bar_x + bar_w, h_bottom], fill=(255, 255, 255, 255))
    draw.rectangle([right_bar_x, h_top, right_bar_x + bar_w, h_bottom], fill=(255, 255, 255, 255))
    cross_h = size * 0.14
    cross_y = size / 2 - cross_h / 2
    draw.rectangle(
        [left_bar_x, cross_y, right_bar_x + bar_w, cross_y + cross_h],
        fill=(255, 255, 255, 255),
    )

    icon_dir = Path(tempfile.gettempdir()) / "hranix-shield"
    icon_dir.mkdir(parents=True, exist_ok=True)
    icon_path = icon_dir / _ICON_FILENAME
    # Pillow's ICO plugin packs this single 64x64 RGBA frame into a valid
    # .ico container — one frame is enough for a Phase-0 placeholder (see
    # the macOS/Linux equivalents' own "not a design task" reasoning),
    # not independently confirmed to look correct in Windows Explorer/the
    # notification area in this session (no Windows machine — see
    # README.md's honesty section), only confirmed to save/reload without
    # error via Pillow itself (see the A-21 task report).
    image.save(icon_path, format="ICO", sizes=[(64, 64)])
    return icon_path


class _TrayState:
    """Holds the mutable state both the menu callback and `main()` need:
    `handle` (the running server, set once before `.start()` — see
    `main()`) and `shutdown_event` (see this module's docstring, point 2,
    for why `main()` needs an `Event` to wait on at all, unlike the
    `pystray` version's blocking `icon.run()`)."""

    def __init__(self) -> None:
        self.handle: LauncherHandle | None = None
        self.shutdown_event = threading.Event()

    def open_panel(self, _systray: SysTrayIcon) -> None:
        # infi.systray menu-item callbacks receive the SysTrayIcon
        # instance as their sole argument (see traybar.py's
        # `_execute_menu_option`) — unused here, same shape as
        # `hranix_shield_app.py`'s rumps callbacks receiving `_sender`.
        if self.handle is None:
            # Cannot actually happen in practice: `main()` sets
            # `self.handle` synchronously before `.start()` (and
            # therefore before this callback could ever fire) — kept as a
            # defensive check anyway, same reasoning the macOS wrapper
            # documents for its own equivalent `None` guard.
            logger.warning("tray: '%s' clicked before launch() finished", _OPEN_PANEL)
            return
        webbrowser.open(f"{self.handle.base_url}/panel/")

    def open_diagnostics(self, _systray: SysTrayIcon) -> None:
        # A-65-6: «Диагностика» — та же панель, сразу на вкладке
        # «Компоненты системы» (deep-link #system-components обрабатывает
        # showPanel() в app.js).
        if self.handle is None:
            logger.warning("tray: '%s' clicked before launch() finished", _DIAGNOSTICS)
            return
        webbrowser.open(f"{self.handle.base_url}/panel/#system-components")

    def quit(self, _systray: SysTrayIcon) -> None:
        # Invoked by infi.systray's `on_quit` hook (traybar.py's
        # `_destroy()`) whenever EITHER quit-capable menu entry is
        # clicked — our own "Выход" (mapped to the SysTrayIcon.QUIT
        # sentinel, see main()) or the library's own auto-appended
        # English "Quit" (see this module's docstring for why both
        # exist) — or the tray window is closed for any other reason.
        if self.handle is not None:
            logger.info("tray: stopping server before quit")
            self.handle.stop()
        self.shutdown_event.set()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    state = _TrayState()
    icon_path = _generate_icon_file()

    menu_options = (
        (_OPEN_PANEL, None, state.open_panel),
        # A-65-6: панель сразу на вкладке «Компоненты системы».
        (_DIAGNOSTICS, None, state.open_diagnostics),
        # Mapped to the SAME built-in QUIT sentinel action infi.systray's
        # own auto-appended ('Quit', None, SysTrayIcon.QUIT) entry uses
        # (see this module's docstring for why both end up in the menu,
        # and why this reuses the sentinel rather than a custom callback
        # calling `.shutdown()` directly).
        (_QUIT, None, SysTrayIcon.QUIT),
    )
    systray = SysTrayIcon(str(icon_path), "Hranix Shield", menu_options, on_quit=state.quit)

    # Synchronous, BEFORE systray.start() below — launch() itself starts
    # uvicorn on its own background thread (see server/launcher.py's
    # docstring), so this is only the migrations + /health poll. Same
    # sequencing the macOS/pystray-era wrapper used, kept even though
    # `SysTrayIcon.start()` itself does not block the calling thread the
    # way `pystray.Icon.run()`/`rumps.App.run()` did (see this module's
    # docstring, point 2, and the blocking wait below for how this file
    # stays alive without that).
    state.handle = launch(open_browser=True, health_timeout=15.0)
    if not state.handle.healthy:
        logger.warning(
            "tray: starting anyway despite /health not answering in time — "
            "'%s' may show an error the first time it's clicked",
            _OPEN_PANEL,
        )

    systray.start()
    # A-65-6: сторож стартует ПОСЛЕ systray.start() — иконка уже в трее,
    # когда появляется вопрос «Запустить Docker Desktop?». Daemon-поток:
    # выход из трея не должен ждать ни MessageBox, ни compose up.
    watchdog_thread = threading.Thread(
        target=_run_watchdog, args=(state,), name="hranix-shield-watchdog", daemon=True
    )
    watchdog_thread.start()
    # SysTrayIcon.start() spawns its own Win32-message-loop thread and
    # returns immediately — this process is kept alive by explicitly
    # waiting on the same "block on an Event a callback sets" idiom
    # packaging/linux/hranix_shield_service.py already uses for its
    # SIGTERM/SIGINT handler (see this module's docstring, point 2).
    state.shutdown_event.wait()
    logger.info("tray: shutdown complete")


if __name__ == "__main__":
    main()
