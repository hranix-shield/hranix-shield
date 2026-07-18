#!/usr/bin/env bash
# A-22: builds the Linux PyInstaller onedir bundle INSIDE a real Linux
# Docker container running on this (macOS) machine — PyInstaller does not
# cross-compile a Linux binary from macOS any more than it cross-compiles a
# Windows one (docs/план-спецификация-фаза-0-нативные-установщики-2026-07-17.md's
# A-22 section); running the whole build inside `python:3.12-slim` is the
# practical workaround the plan calls out for Linux specifically (Windows
# has no equivalent trick available in this environment — see A-21).
#
# Usage (from repo root):
#   packaging/linux/build-in-docker.sh
#
# Result: packaging/linux/dist/hranix-shield/ — a onedir bundle (matches
# packaging/linux/hranix-shield.spec's COLLECT(..., name="hranix-shield")),
# owned by the invoking host user (see the final `chown` step below — the
# container runs as root internally, so without this the bundle would land
# on the host owned by root).
#
# --platform linux/amd64: explicit, not left to Docker's default. On an
# Apple Silicon build host (arm64), `docker run python:3.12-slim` without a
# --platform flag silently pulls and runs the arm64 image — PyInstaller
# then produces an aarch64 ELF binary (confirmed empirically building this
# task: the first build attempt, with no --platform flag, produced exactly
# that). `debian/control`'s `Architecture: amd64` (the far more common
# target for self-hosted Debian/Ubuntu servers, the audience this package
# is for — see packaging/linux/README.md) would then be a straight lie
# about what is actually inside the .deb. Docker Desktop on Apple Silicon
# transparently runs amd64 images under QEMU emulation (confirmed: `docker
# run --rm --platform linux/amd64 python:3.12-slim uname -m` -> x86_64) —
# slower than a native build, acceptable for this task's build-once,
# install-many use case. An arm64 target build is also possible (drop
# --platform, or pass linux/arm64 explicitly + Architecture: arm64 in
# debian/control) but out of scope here; document which one shipped, don't
# silently assume.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# python:3.12-slim-bullseye, NOT the bare `python:3.12-slim` tag — found the
# hard way building this task: `python:3.12-slim` currently resolves to
# Debian 13 "trixie" (glibc 2.41), and a PyInstaller build done there fails
# to even START in a clean Ubuntu 22.04 container (the very target this
# package's control file/README claim to support, and the DoD install-test
# target, see packaging/linux/README.md):
#   [PYI-328:ERROR] Failed to load Python shared library
#   '/opt/hranix-shield/_internal/libpython3.12.so.1.0':
#   /lib/x86_64-linux-gnu/libm.so.6: version `GLIBC_2.38' not found
# glibc is forward-compatible only (a binary linked against an OLDER glibc
# runs fine on a newer one, never the reverse) — so the fix is building
# against the OLDEST glibc that still ships a Python 3.12: Debian 11
# "bullseye", glibc 2.31 (confirmed via `ldd --version` inside the image),
# safely older than Ubuntu 22.04 (2.35), Ubuntu 24.04 (2.39), and Debian
# 12/13 (2.36/2.41) alike. Not a hypothetical fix — the exact same build
# with only this one line changed is what packaging/linux/README.md's
# "Проверено" section describes actually installing and (mostly) running
# under real systemd in a clean ubuntu:22.04-based test container.
IMAGE="python:3.12-slim-bullseye"
PLATFORM="linux/amd64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

echo "[build-in-docker] building Linux onedir bundle inside ${IMAGE} (${PLATFORM}) ..."

docker run --rm \
    --platform "${PLATFORM}" \
    -v "${REPO_ROOT}:/repo" \
    -w /repo \
    "${IMAGE}" \
    bash -euxc '
        # build-essential: passlib[bcrypt]/bcrypt (requirements-packaged.txt)
        # need a C compiler for their native extensions — same reasoning as
        # the Dockerfile'"'"'s builder stage (server/Dockerfile). binutils:
        # PyInstaller'"'"'s Linux bootloader analysis step shells out to
        # objdump/ldd to resolve shared-library dependencies.
        apt-get update
        apt-get install -y --no-install-recommends build-essential binutils
        rm -rf /var/lib/apt/lists/*

        python -m venv /tmp/build-venv
        /tmp/build-venv/bin/pip install --upgrade pip
        /tmp/build-venv/bin/pip install -r server/requirements-packaged.txt

        /tmp/build-venv/bin/pyinstaller packaging/linux/hranix-shield.spec \
            --distpath packaging/linux/dist \
            --workpath packaging/linux/build \
            --noconfirm
    '

# The container ran as root, so everything it wrote under packaging/linux/
# on the bind-mounted repo landed owned by root:root on the host — hand it
# back to whoever invoked this script.
docker run --rm \
    --platform "${PLATFORM}" \
    -v "${REPO_ROOT}:/repo" \
    "${IMAGE}" \
    chown -R "${HOST_UID}:${HOST_GID}" \
        /repo/packaging/linux/dist /repo/packaging/linux/build

echo "[build-in-docker] done: packaging/linux/dist/hranix-shield/"
