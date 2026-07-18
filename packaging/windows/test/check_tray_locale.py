"""A-21: standalone, non-packaged smoke check for a specific risk flagged
when `infi.systray` (BSD-3-Clause) replaced `pystray` (LGPLv3) as this
build's system-tray library: `infi.systray==0.1.12.1` binds Win32's ANSI
API variants exclusively (`RegisterWindowMessageA`, `InsertMenuItemA`,
... — see `infi/systray/win32_adapter.py`'s own module-level bindings, not
the Unicode `...W` variants), and encodes all text through its own
`encode_for_locale()` helper: `text.encode(locale.getpreferredencoding(),
'ignore')`.

Hranix Shield's tray menu labels ("Открыть панель"/"Выход") are Cyrillic —
this is a RU-first product (see CLAUDE.md) — but `windows-latest`'s
GitHub Actions runner defaults to an en-US locale, whose preferred
encoding is conventionally `cp1252` (Windows-1252, Western European) — a
codepage with NO Cyrillic glyphs at all.

Run standalone by `.github/workflows/windows-build.yml`, against the same
build-venv used for the PyInstaller build itself (NOT the packaged .exe —
there is no supported way to drive a packaged app's tray icon from
outside the process; this instead exercises infi.systray's own public and
internal functions directly on a real Windows OS, which is the closest
thing to a real check achievable non-interactively in CI).

Two separate things are checked, deliberately kept apart:

  1. `_check_encoding()` — what `encode_for_locale()` actually DOES to our
     exact Cyrillic labels on THIS runner's real locale, read back from
     the actual encoded bytes rather than guessed. With `errors='ignore'`
     (see win32_adapter.py), a codepage with no Cyrillic glyphs at all
     does NOT raise — it silently drops every unencodable character, so a
     pure-Cyrillic label most likely round-trips to an EMPTY string, not
     visible "mojibake". This reports the exact behaviour observed on
     THIS runner, whatever it turns out to be, rather than asserting one
     specific expected outcome — a real, pre-existing encoding gap in a
     third-party library is not something this script can fix, only
     surface honestly (see packaging/windows/README.md's own honesty
     section for how this is written up).

  2. `_check_construction_and_start()` — whether constructing a real
     `SysTrayIcon` with these exact Cyrillic `menu_options` and calling
     `.start()` (which DOES run on a real Win32 message-loop thread,
     unlike check 1's pure string check) raises ANY exception on this
     runner. Deliberately does NOT call `_show_menu()`/`TrackPopupMenu`
     (the actual right-click popup-rendering code path that would call
     `encode_for_locale()` on the menu text itself) — that Win32 call is
     MODAL and blocks the calling thread until a human dismisses the
     popup, which no CI runner can do; forcing it here would hang this
     step instead of giving a clean pass/fail. Check 1 above is what
     substitutes for exercising that exact code path safely.

Exit code 0 either way for check 1's finding on its own (a codepage that
cannot render Cyrillic is a real, pre-existing constraint of
infi.systray==0.1.12.1 on an English-locale Windows install, not a bug
this script introduces or can silently fix — failing the whole build over
a cosmetic, honestly-reported localization gap would be the wrong
response). This script exits non-zero ONLY if check 2 (construction/
start, or the encoding helper itself) raises an actual exception — a real
crash, not a label-rendering gap, which WOULD be a genuine regression
worth failing the build over.
"""

from __future__ import annotations

import locale
import sys
import time

from infi.systray import SysTrayIcon
from infi.systray.win32_adapter import encode_for_locale

# Real bug, found by the first actual windows-latest CI run of this script
# (not hypothetical — see the A-21 CI run this comment was added in response
# to): this script's OWN diagnostic `print(...)` calls embed the raw
# Cyrillic labels (via `{label!r}`) to report exactly what encode_for_locale()
# did to them — but `print()` writes through `sys.stdout`, whose encoding on
# a `windows-latest` runner defaults to the console's legacy codepage
# (`cp1252` here, confirmed by the crash), NOT UTF-8. `encode_for_locale()`
# itself never raised (see its own `'ignore'` error handler) — the crash was
# one layer up, in THIS script's own attempt to report the finding, on the
# very first line that tried to print a Cyrillic character. Reconfiguring
# stdout to UTF-8 with `errors="backslashreplace"` (never silently drops or
# crashes on a character stdout can't show, unlike `"ignore"`) fixes this
# script's own reporting without changing anything about what it measures.
sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")

_LABELS = ("Открыть панель", "Выход", "Hranix Shield")


def _check_encoding() -> bool:
    preferred = locale.getpreferredencoding()
    print(f"locale.getpreferredencoding() on this runner = {preferred!r}")
    all_round_tripped = True
    for label in _LABELS:
        try:
            encoded = encode_for_locale(label)
        except Exception as exc:  # noqa: BLE001 - deliberately broad, see module docstring
            print(f"FAIL: encode_for_locale({label!r}) raised {type(exc).__name__}: {exc}")
            return False
        decoded = encoded.decode(preferred, "replace")
        round_tripped = decoded == label
        all_round_tripped = all_round_tripped and round_tripped
        print(
            f"encode_for_locale({label!r}) -> {encoded!r} "
            f"(decodes back to {decoded!r}, round_tripped={round_tripped})"
        )
    if not all_round_tripped:
        print(
            "NOTE (not a failure): at least one Cyrillic label did not "
            "round-trip through this runner's locale encoding - the real "
            "tray menu will likely show blank/garbled text for that label "
            "on an English-locale Windows install. This is a pre-existing "
            "constraint of infi.systray==0.1.12.1's ANSI-API design (see "
            "this script's own module docstring), not something this "
            "script can fix - flagged honestly in "
            "packaging/windows/README.md rather than hidden."
        )
    return True


def _check_construction_and_start() -> bool:
    def _noop(_systray: SysTrayIcon) -> None:
        return None

    menu_options = (
        (_LABELS[0], None, _noop),
        (_LABELS[1], None, SysTrayIcon.QUIT),
    )
    try:
        # icon="" (not a real .ico path): os.path.isfile("") is False, so
        # infi.systray falls back to its own default system icon (see
        # traybar.py's _load_icon()) - this check is only about menu-text
        # encoding and construction/start, not icon loading, which
        # hranix_shield_tray.py's own _generate_icon_file() covers
        # separately.
        systray = SysTrayIcon("", _LABELS[2], menu_options, on_quit=_noop)
        systray.start()
        time.sleep(2.0)
        alive = systray._message_loop_thread.is_alive()  # noqa: SLF001 - no public "is running" API, see module docstring
        systray.shutdown()
    except Exception as exc:  # noqa: BLE001 - see module docstring
        print(
            "FAIL: constructing/starting SysTrayIcon with Cyrillic "
            f"menu_options raised {type(exc).__name__}: {exc}"
        )
        return False
    if not alive:
        print("FAIL: the tray message-loop thread was not alive 2s after start() - it exited unexpectedly")
        return False
    print("OK: SysTrayIcon constructed and started with Cyrillic menu_options, ran for 2s, and shut down cleanly")
    return True


def main() -> int:
    encoding_ok = _check_encoding()
    construction_ok = _check_construction_and_start()
    if not encoding_ok or not construction_ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
