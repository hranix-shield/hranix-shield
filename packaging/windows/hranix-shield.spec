# -*- mode: python ; coding: utf-8 -*-
"""A-21: PyInstaller spec building Hranix Shield's Windows onedir bundle.

Entry point is `packaging/windows/hranix_shield_tray.py` (the
`infi.systray` tray-icon shell — no console window, see that file's
docstring for why it is `infi.systray`, BSD-3-Clause, not the originally
used `pystray`, LGPLv3), which imports and calls into `server/launcher.py`
(the OS-agnostic startup sequence shared with A-20's macOS build and
A-22's Linux build — see that module's docstring). This spec's only job
is getting both of those, plus `app/` and the runtime resources it needs
(`app/static/`, `alembic.ini`, `alembic/`), correctly onto disk — no
business logic lives here, same split as `packaging/macos/hranix-shield.spec`
and `packaging/linux/hranix-shield.spec`.

**onedir, not onefile** — same choice A-20 measured empirically for macOS
(see `packaging/macos/README.md`'s "onedir vs onefile" section: onefile
re-extracts its whole bundle to a fresh temp dir on EVERY launch, adding
latency on top of this app's own migration/startup work) and A-22 carried
over unmeasured-but-consistent for Linux. **Not independently re-measured
on Windows in this task either** (no Windows machine available — see
`packaging/windows/README.md`'s honesty section) — flagged here rather
than silently assumed identical, same "don't reason about what tools do,
check" discipline already applied twice; the macOS finding is about
PyInstaller's own packed-runtime extraction behaviour, which is not
platform-specific in PyInstaller's own documentation, so onedir is the
reasonable default to ship with pending an actual Windows measurement.

`icon=None` on the `EXE(...)` below (no custom `.ico` for the executable
itself, Explorer/Start-menu will show PyInstaller's own default icon) —
same decision already made for macOS's `BUNDLE(..., icon=None, ...)`:
Phase 0 is explicitly not about visual/brand design (see
`hranix_shield_tray.py`'s own placeholder-icon docstring for the same
reasoning applied to the *tray* (notification-area) icon, which IS
generated — at runtime, into a real temp-dir `.ico` file `infi.systray`
requires, see that module's docstring point 1 — rather than baked into
this .exe at build time).

Build (from repo root, ONLY possible on an actual Windows machine —
PyInstaller does not cross-compile, see `packaging/windows/README.md`; in
this project that means the `windows-latest` GitHub Actions runner via
`.github/workflows/windows-build.yml`, not a developer's local macOS
checkout — a lean build venv, `server/requirements-packaged.txt`, NOT the
full dev `server/venv`):

    <build-venv>\\Scripts\\pyinstaller packaging\\windows\\hranix-shield.spec ^
        --distpath packaging\\windows\\dist --workpath packaging\\windows\\build

`--noconfirm` is convenient for repeat CI builds; not baked into this file
so a stray leftover `dist/`/`build/` is never silently clobbered by an
unattended invocation without the caller opting in — same convention as
the macOS/Linux specs (the workflow itself passes `--noconfirm`
explicitly).
"""

from pathlib import Path

# SPECPATH is injected by PyInstaller's own exec() of this file — points
# at this .spec's own directory (packaging/windows/), NOT repo root.
REPO_ROOT = Path(SPECPATH).resolve().parent.parent  # packaging/windows -> packaging -> repo root
SERVER_DIR = REPO_ROOT / "server"

a = Analysis(
    [str(REPO_ROOT / "packaging" / "windows" / "hranix_shield_tray.py")],
    pathex=[str(SERVER_DIR)],
    binaries=[],
    datas=[
        # StaticFiles mount (app_factory.py's STATIC_DIR) reads these as
        # real files off disk at request time — Analysis only follows
        # Python imports, so the actual HTML/CSS/JS must be listed
        # explicitly here, at the same "app/static" path PyInstaller's
        # PyiFrozenImporter reproduces under sys._MEIPASS for
        # app/app_factory.py's own `Path(__file__).resolve().parent /
        # "static"` computation. Identical to the macOS/Linux specs' row
        # — this is `app/`'s own layout, not an OS-specific concern.
        (str(SERVER_DIR / "app" / "static"), "app/static"),
        # alembic's ScriptDirectory loads `env.py` + every versions/*.py
        # file straight off disk via its own import machinery (not
        # PyInstaller's) — same "must be real files, not just importable
        # modules" reasoning as app/static above. See launcher.py's
        # bundled_root()/`_alembic_config()` for the matching read side.
        (str(SERVER_DIR / "alembic"), "alembic"),
        (str(SERVER_DIR / "alembic.ini"), "."),
    ],
    hiddenimports=[
        # Same list as packaging/macos/hranix-shield.spec and
        # packaging/linux/hranix-shield.spec, verbatim — these are all
        # plugin-discovery-by-string imports inside
        # uvicorn/passlib/jose/aiosqlite, none of it OS-specific (see the
        # macOS spec's comments for the empirical failure each row fixes;
        # not re-derived independently here since the underlying libraries
        # and requirements-packaged.txt versions are identical across all
        # three OS builds).
        "uvicorn.loops.auto",
        "uvicorn.loops.uvloop",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        "passlib.handlers.bcrypt",
        "jose.backends.cryptography_backend",
        "aiosqlite",
        # infi.systray (traybar.py/win32_adapter.py) imports only `ctypes`,
        # `ctypes.wintypes`, `locale`, `sys`, `threading`, `uuid`, `os` —
        # all stdlib, all plain top-level imports PyInstaller's Analysis
        # traces without any help. Unlike pystray's multi-backend
        # `pystray/__init__.py` (the previous version of this spec had a
        # defensive `"pystray._win32"` hiddenimport for exactly that), no
        # hiddenimport is needed for infi.systray itself.
        #
        # PIL.IcoImagePlugin IS listed, defensively: `hranix_shield_tray.py`'s
        # `_generate_icon_file()` calls `Image.save(path, format="ICO")`,
        # which needs Pillow's own ICO plugin loaded — Pillow's `Image.init()`
        # normally imports every built-in plugin module by name via
        # `importlib.import_module` (a string-driven pattern, the same class
        # of problem the passlib/jose rows above exist for), and PyInstaller
        # ships a mature, dedicated Pillow hook (via `pyinstaller-hooks-contrib`)
        # that should already collect all of PIL's plugin submodules on its
        # own — this row is cheap insurance in case that hook's coverage ever
        # changes, not a confirmed-necessary fix (not verified empirically on
        # a real Windows build in this session — see README.md).
        "PIL.IcoImagePlugin",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # rumps (macOS menu-bar lib, requirements-packaged.txt's
    # `sys_platform == "darwin"` marker) is simply never installed in a
    # Windows build venv, so PyInstaller's Analysis never sees an import
    # of it in the first place (this entry point does not import it
    # either, see hranix_shield_tray.py) — no explicit exclude needed,
    # same reasoning as the Linux spec's identical comment. infi.systray
    # has no multi-backend structure to worry about here either (unlike
    # the pystray version this spec previously had to reason about,
    # imported unconditionally for every platform in that library's own
    # `__init__.py`) — infi.systray is Windows-only by construction
    # (`win32_adapter.py` calls `ctypes.windll...` at module import time,
    # which simply does not exist outside Windows), so there is nothing
    # analogous to exclude.
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Hranix Shield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # console=False (unlike the Linux spec's console=True): this build has
    # a tray icon, no GUI window and no terminal — same reasoning as the
    # macOS spec's console=False for its menu-bar app. A visible console
    # window flashing behind a "background utility with a tray icon" would
    # be exactly the confusing, non-standard experience this app's target
    # user (a non-technical executive, see this file's own docstring and
    # hranix_shield_tray.py's) should never see.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="Hranix Shield",
)
