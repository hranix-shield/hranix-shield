# -*- mode: python ; coding: utf-8 -*-
"""A-20: PyInstaller spec building Hranix Shield's macOS `.app` bundle.

Entry point is `packaging/macos/hranix_shield_app.py` (the `rumps`
menu-bar shell), which imports and calls into `server/launcher.py` (the
OS-agnostic startup sequence shared with the future A-21/A-22 Windows/
Linux builds — see that module's docstring). This spec's only job is
getting both of those, plus `app/` and the runtime resources it needs
(`app/static/`, `alembic.ini`, `alembic/`, and — A-24 — a vendored
`osqueryi` binary, see `vendor-osquery.sh` and the `datas=[...]` row
below), correctly onto disk inside a `.app` — no business logic lives here.

**onedir, not onefile** (`COLLECT`+`BUNDLE` below, not a single-file
`EXE`) — decided empirically while building this task, see
`packaging/macos/README.md`'s "onedir vs onefile" section for the actual
measured startup-time comparison and reasoning; short version: onefile
re-extracts its entire bundle to a fresh temp directory on EVERY launch
(this app already does DB-migration work at startup, adding onefile's
extraction on top made cold start noticeably slower with no offsetting
benefit for an app that isn't distributed as a single double-clickable
file anyway — it's wrapped in a `.dmg`, see A-20's `README.md`).

Build (from repo root, with a lean build venv — see
`server/requirements-packaged.txt`, NOT the full dev `server/venv`):

    <build-venv>/bin/pyinstaller packaging/macos/hranix-shield.spec \
        --distpath packaging/macos/dist --workpath packaging/macos/build

`--noconfirm` is convenient for repeat local builds; not baked into this
file so a stray leftover `dist/`/`build/` is never silently clobbered by
an unattended CI-style invocation without the caller opting in.
"""

from pathlib import Path

# SPECPATH is injected by PyInstaller's own exec() of this file — points
# at this .spec's own directory (packaging/macos/), NOT repo root.
REPO_ROOT = Path(SPECPATH).resolve().parent.parent  # packaging/macos -> packaging -> repo root
SERVER_DIR = REPO_ROOT / "server"

# A-24: `vendor-osquery.sh` (this same directory) must run ONCE before this
# spec — it downloads the official osquery release and extracts a
# standalone `osqueryi` binary here. Checked explicitly (not left to
# PyInstaller's own "datas" error, which is correct but less specific)
# so a developer who forgot that step gets a clear, actionable message
# pointing at the exact script to run, not a generic file-not-found deep
# in PyInstaller's own Analysis phase.
VENDOR_OSQUERYI = REPO_ROOT / "packaging" / "macos" / "vendor" / "osquery" / "osqueryi"
if not VENDOR_OSQUERYI.is_file():
    raise FileNotFoundError(
        f"A-24: vendored osqueryi binary not found at {VENDOR_OSQUERYI} — "
        "run packaging/macos/vendor-osquery.sh once before building this spec "
        "(see that script's own docstring)."
    )

# A-40: `vendor-geoip.sh` (this same directory) must run ONCE before this
# spec — it downloads the offline IP -> country CSV dataset. Same explicit
# check as VENDOR_OSQUERYI above, for the same reason (a clear, actionable
# message instead of a generic PyInstaller "datas" error).
VENDOR_GEOIP_DIR = REPO_ROOT / "packaging" / "macos" / "vendor" / "geoip"
if not (VENDOR_GEOIP_DIR / "user-country-ipv4.csv").is_file():
    raise FileNotFoundError(
        f"A-40: vendored geoip dataset not found at {VENDOR_GEOIP_DIR} — "
        "run packaging/macos/vendor-geoip.sh once before building this spec "
        "(see that script's own docstring, and geoip.py's module docstring "
        "for the licence research behind this dataset choice)."
    )

a = Analysis(
    [str(REPO_ROOT / "packaging" / "macos" / "hranix_shield_app.py")],
    # A-25: packaging/macos itself, so PyInstaller's modulegraph analysis
    # can resolve `hranix_shield_app.py`'s `from wazuh_agent_setup import
    # ...` at BUILD time — that sibling module lives in the same
    # directory as the entry script (unpackaged dev-mode already works
    # for free: Python auto-prepends a script's own directory to
    # sys.path), but PyInstaller's static analysis needs it in `pathex`
    # explicitly, the same reason SERVER_DIR is already here for
    # `from launcher import ...`.
    pathex=[str(SERVER_DIR), str(REPO_ROOT / "packaging" / "macos")],
    binaries=[],
    datas=[
        # StaticFiles mount (app_factory.py's STATIC_DIR) reads these as
        # real files off disk at request time — Analysis only follows
        # Python imports, so the actual HTML/CSS/JS must be listed
        # explicitly here, at the same "app/static" path PyInstoller's
        # PyiFrozenImporter reproduces under sys._MEIPASS for app/app_factory.py's
        # own `Path(__file__).resolve().parent / "static"` computation.
        (str(SERVER_DIR / "app" / "static"), "app/static"),
        # alembic's ScriptDirectory loads `env.py` + every versions/*.py
        # file straight off disk via its own import machinery (not
        # PyInstaller's) — same "must be real files, not just importable
        # modules" reasoning as app/static above. See launcher.py's
        # bundled_root()/`_alembic_config()` for the matching read side.
        (str(SERVER_DIR / "alembic"), "alembic"),
        (str(SERVER_DIR / "alembic.ini"), "."),
        # A-24: vendored `osqueryi` binary (see vendor-osquery.sh above) —
        # lands at sys._MEIPASS/vendor/osquery/osqueryi, exactly where
        # osquery.py's `_vendored_osqueryi_path()` looks for it in packaged
        # mode. Declared as a `datas` row (not `binaries=[...]`): it is not
        # a Python C-extension shared library some other module `dlopen`s,
        # which is what `binaries=[...]`'s own dependency bookkeeping is
        # really for. In practice PyInstaller's Analysis step still
        # auto-reclassifies it into the same internal "binary" bucket
        # regardless of which list it was declared under (its own log line
        # says so: "Performing binary vs. data reclassification" — it
        # detects the Mach-O magic bytes itself, not this file's origin
        # list) — confirmed empirically while building this task: the
        # collected copy (under `Contents/Resources/vendor/osquery/
        # osqueryi`, a symlink into `Contents/Frameworks/`, the same
        # macOS-BUNDLE convention every other native binary in this build
        # already gets) came out THINNED to arm64-only (PyInstaller's own
        # `--target-arch` conversion, the same step the main `Hranix
        # Shield` executable goes through) and RE-SIGNED during BUNDLE's
        # whole-app signing pass, on top of the ad hoc signature
        # vendor-osquery.sh already applied — belt and suspenders, not a
        # conflict: `codesign -dv` on the collected copy still shows a
        # valid ad hoc signature, and it actually runs (`osqueryi
        # --version` invoked from inside the real built .app) — see the
        # A-24 task report for the exact commands and output.
        (str(VENDOR_OSQUERYI), "vendor/osquery"),
        # A-40: vendored geoip CSV dataset (see vendor-geoip.sh above) —
        # lands at sys._MEIPASS/vendor/geoip/, exactly where geoip.py's
        # `_vendored_geoip_dir()` looks for it in packaged mode. A whole
        # directory as `SOURCE` (not a single file), same shape as
        # `app/static` above — PyInstaller recursively collects everything
        # under it, preserving the relative layout `_tables_for_dir()`
        # expects (`user-country-ipv4.csv`/`user-country-ipv6.csv` sitting
        # directly inside). Plain data (CSV text), not a Mach-O binary like
        # VENDOR_OSQUERYI above — no codesign/thinning step applies to it.
        (str(VENDOR_GEOIP_DIR), "vendor/geoip"),
    ],
    hiddenimports=[
        # uvicorn's "auto" loop/protocol selection (uvicorn[standard],
        # requirements-packaged.txt) imports its concrete backends by
        # string at runtime — pyinstaller-hooks-contrib ships a
        # hook-uvicorn.py that covers most of this automatically, but
        # these are kept explicit too: confirmed empirically (A-20 task
        # report) that the first build attempt without them still failed
        # at server-start time with "ImportError: uvloop is not
        # installed" style errors even with the contrib hook present.
        "uvicorn.loops.auto",
        "uvicorn.loops.uvloop",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.http.httptools_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.protocols.websockets.websockets_impl",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
        # passlib's bcrypt backend and python-jose's cryptography backend
        # are both selected by passlib/jose probing `importlib` at runtime
        # (a plugin-discovery pattern PyInstaller's static Analysis cannot
        # see) — services/auth.py needs both for password hashing / JWT
        # signing respectively.
        "passlib.handlers.bcrypt",
        "jose.backends.cryptography_backend",
        # aiosqlite is selected by SQLAlchemy's async engine via the
        # "sqlite+aiosqlite" dialect string in resolved_database_url
        # (app/config.py) — same string-driven-plugin-selection reasoning.
        "aiosqlite",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
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
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
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

app = BUNDLE(
    coll,
    name="Hranix Shield.app",
    icon=None,
    bundle_identifier="com.hranix.shield",
    info_plist={
        # No Dock icon / app-switcher entry — this is a menu-bar-only
        # utility app, see hranix_shield_app.py's module docstring and the
        # A-20 task brief's explicit architect decision.
        "LSUIElement": True,
        "CFBundleShortVersionString": "0.1.0",
        "CFBundleVersion": "0.1.0",
        "NSHumanReadableCopyright": "Hranix",
        # Unsigned build (A-20 explicitly out of scope for code signing/
        # notarization) — Gatekeeper's "unidentified developer" prompt on
        # first launch is documented, not hidden, in packaging/macos/README.md.
        "NSHighResolutionCapable": True,
    },
)
