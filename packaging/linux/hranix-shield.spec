# -*- mode: python ; coding: utf-8 -*-
"""A-22: PyInstaller spec building Hranix Shield's Linux onedir bundle.

Entry point is `packaging/linux/hranix_shield_service.py` (the SIGTERM/
SIGINT-aware systemd-service shell — no GUI, see that file's docstring),
which imports and calls into `server/launcher.py` (the OS-agnostic startup
sequence shared with A-20's macOS build and the future A-21 Windows build —
see that module's docstring). This spec's only job is getting both of
those, plus `app/` and the runtime resources it needs (`app/static/`,
`alembic.ini`, `alembic/`), correctly onto disk — no business logic lives
here, same split as `packaging/macos/hranix-shield.spec`.

**onedir, not onefile** — same reasoning A-20 already measured empirically
for macOS (see `packaging/macos/README.md`'s "onedir vs onefile" section:
onefile re-extracts its whole bundle to a fresh temp dir on EVERY launch,
adding latency on top of this app's own migration/startup work, for a build
that is not distributed as a single double-clickable file anyway — here it
is laid out under `/opt/hranix-shield/` by the `.deb`, see
`packaging/linux/README.md`). Not re-measured independently for Linux in
this task (the macOS finding is about PyInstaller's own packed-runtime
extraction behaviour, not anything macOS-specific) — flagged here rather
than silently assumed identical, per the same "don't reason about what
tools do, check" discipline this project already applies to build tooling.

No `BUNDLE(...)` step here (unlike the macOS spec) — `BUNDLE` builds a
Cocoa `.app`, meaningless outside macOS; a Linux PyInstaller onedir build
IS its own final layout (`COLLECT`'s output directory), nothing further to
wrap it in.

Build (from repo root, inside a Linux container — PyInstaller does not
cross-compile a Linux binary from macOS, see `packaging/linux/README.md`'s
"Сборка" section for the container-based build this spec is meant to run
under, and a lean build venv — `server/requirements-packaged.txt`, NOT the
full dev `server/venv`):

    <linux-build-venv>/bin/pyinstaller packaging/linux/hranix-shield.spec \\
        --distpath packaging/linux/dist --workpath packaging/linux/build

`--noconfirm` is convenient for repeat local builds; not baked into this
file so a stray leftover `dist/`/`build/` is never silently clobbered by an
unattended invocation without the caller opting in — same convention as the
macOS spec.
"""

from pathlib import Path

# SPECPATH is injected by PyInstaller's own exec() of this file — points at
# this .spec's own directory (packaging/linux/), NOT repo root.
REPO_ROOT = Path(SPECPATH).resolve().parent.parent  # packaging/linux -> packaging -> repo root
SERVER_DIR = REPO_ROOT / "server"

a = Analysis(
    [str(REPO_ROOT / "packaging" / "linux" / "hranix_shield_service.py")],
    pathex=[str(SERVER_DIR)],
    binaries=[],
    datas=[
        # StaticFiles mount (app_factory.py's STATIC_DIR) reads these as
        # real files off disk at request time — Analysis only follows
        # Python imports, so the actual HTML/CSS/JS must be listed
        # explicitly here, at the same "app/static" path PyInstaller's
        # PyiFrozenImporter reproduces under sys._MEIPASS for
        # app/app_factory.py's own `Path(__file__).resolve().parent /
        # "static"` computation. Identical to the macOS spec's row — this
        # is `app/`'s own layout, not an OS-specific concern.
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
        # Same list as packaging/macos/hranix-shield.spec, verbatim —
        # these are all plugin-discovery-by-string imports inside
        # uvicorn/passlib/jose/aiosqlite, none of it macOS-specific (see
        # that spec's comments for the empirical failure each row fixes;
        # not re-derived independently here since the underlying libraries
        # and requirements-packaged.txt versions are identical on Linux).
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
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # rumps (macOS menu-bar lib, requirements-packaged.txt's
    # `sys_platform == "darwin"` marker) is simply never installed in a
    # Linux build venv, so PyInstaller's Analysis never sees an import of
    # it in the first place (this entry point does not import it either,
    # see hranix_shield_service.py) — no explicit exclude needed.
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
    name="hranix-shield",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # console=True (unlike the macOS spec's console=False): this build has
    # no windowed/menu-bar UI at all (see hranix_shield_service.py) — it is
    # a plain foreground process, exactly what systemd's `ExecStart`
    # (`packaging/linux/hranix-shield.service`) expects to supervise, and
    # what an operator running it by hand (`sudo -u hranix-shield
    # /opt/hranix-shield/hranix-shield`, see README.md) expects to see
    # logging to its own stdout/stderr.
    console=True,
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
    name="hranix-shield",
)
