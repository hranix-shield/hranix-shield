#!/usr/bin/env bash
# A-22: assembles the .deb package around the already-built PyInstaller
# onedir bundle (packaging/linux/dist/hranix-shield/ — run
# build-in-docker.sh first if that does not exist yet).
#
# Tool choice: `dpkg-deb`, not `fpm`. Both were considered (план-спецификация
# A-22 leaves the choice to the developer). `dpkg-deb` is part of `dpkg`
# itself — present on any Debian/Ubuntu system (including the very
# `python:3.12-slim-bullseye`/`ubuntu:22.04` containers this task already
# needs for the PyInstaller build and the install test, see README.md;
# confirmed `/usr/bin/dpkg-deb` ships out of the box, no extra `apt-get
# install` needed), needs no extra install (fpm is a Ruby gem with its own
# runtime dependency chain), and for a package this simple (one onedir tree
# + one systemd unit + three maintainer scripts) `fpm`'s main selling point
# — generating a `control` file and directory layout for you from flags —
# buys little: this task writes `debian/control`/`postinst`/`prerm`/
# `postrm` by hand anyway, to follow the debian conffile/maintainer-script
# conventions precisely (upgrade vs remove vs purge, see those files' own
# comments), so there is nothing left for fpm's flag-driven generation to
# save.
#
# Runs the actual `dpkg-deb --build` step inside the same
# `python:3.12-slim-bullseye`/`linux/amd64` image `build-in-docker.sh` uses
# (this macOS dev machine has no `dpkg-deb` on PATH at all — confirmed,
# `which dpkg-deb` finds nothing here; and using the exact same base as the
# PyInstaller build, not just "any Debian image", avoids a second place a
# glibc/tool-version mismatch could sneak in — see that script's own
# comment for the real GLIBC incompatibility bug found and fixed this way)
# — staging the file tree itself (plain `cp`/`mkdir`/`chmod`, all portable)
# still happens on the host, only the final archive-format-specific step
# needs Linux tooling.
#
# Usage (from repo root):
#   packaging/linux/build-deb.sh [version]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LINUX_DIR="${REPO_ROOT}/packaging/linux"
VERSION="${1:-0.1.0}"
PKG_NAME="hranix-shield"
ARCH="amd64"
IMAGE="python:3.12-slim-bullseye"  # matches build-in-docker.sh's IMAGE — see that script's comment
PLATFORM="linux/amd64"  # matches build-in-docker.sh's target — see that script's comment

DIST_BUNDLE="${LINUX_DIR}/dist/hranix-shield"
if [ ! -d "${DIST_BUNDLE}" ]; then
    echo "error: ${DIST_BUNDLE} not found — run packaging/linux/build-in-docker.sh first" >&2
    exit 1
fi

STAGING="${LINUX_DIR}/deb-staging"
rm -rf "${STAGING}"
mkdir -p "${STAGING}/DEBIAN"
mkdir -p "${STAGING}/opt/hranix-shield"
mkdir -p "${STAGING}/lib/systemd/system"

# --- onedir bundle -> /opt/hranix-shield/ ---
cp -R "${DIST_BUNDLE}/." "${STAGING}/opt/hranix-shield/"

# --- systemd unit -> /lib/systemd/system/ (debian convention: packages
# ship units under /lib/systemd/system, NOT /etc/systemd/system — the
# latter is reserved for local admin overrides/enable-symlinks) ---
cp "${LINUX_DIR}/hranix-shield.service" "${STAGING}/lib/systemd/system/hranix-shield.service"

# --- maintainer scripts + control ---
cp "${LINUX_DIR}/debian/postinst" "${STAGING}/DEBIAN/postinst"
cp "${LINUX_DIR}/debian/prerm" "${STAGING}/DEBIAN/prerm"
cp "${LINUX_DIR}/debian/postrm" "${STAGING}/DEBIAN/postrm"
chmod 0755 "${STAGING}/DEBIAN/postinst" "${STAGING}/DEBIAN/prerm" "${STAGING}/DEBIAN/postrm"

# Installed-Size is a required-by-convention (not strictly enforced by
# dpkg-deb, but expected by apt/lintian) control field: 1024-byte blocks,
# computed from the staged tree rather than hand-maintained (this bundle
# includes the full Python runtime + deps, its size is not something to
# keep in sync by hand across rebuilds).
INSTALLED_SIZE_KB="$(du -sk "${STAGING}/opt" "${STAGING}/lib" | awk '{sum+=$1} END {print sum}')"

sed -e "s/^Version:.*/Version: ${VERSION}/" \
    "${LINUX_DIR}/debian/control" > "${STAGING}/DEBIAN/control"
printf 'Installed-Size: %s\n' "${INSTALLED_SIZE_KB}" >> "${STAGING}/DEBIAN/control"

# --- build (inside the Linux container — see header comment) ---
OUT_NAME="${PKG_NAME}_${VERSION}_${ARCH}.deb"
# --root-owner-group: every file inside the .deb is recorded as owned by
# root:root regardless of the staging tree's own (host, non-root) uid/gid —
# the correct, standard way to build a .deb without needing fakeroot or an
# actually-root build process (dpkg-deb >= 1.19.1 — confirmed 1.20.13 in
# python:3.12-slim-bullseye, see header comment; `fakeroot dpkg-deb --build
# ...` is the older equivalent for a dpkg-deb without this flag, not needed
# here).
docker run --rm \
    --platform "${PLATFORM}" \
    -v "${REPO_ROOT}:/repo" \
    -w /repo \
    "${IMAGE}" \
    dpkg-deb --build --root-owner-group \
        "packaging/linux/deb-staging" "packaging/linux/dist/${OUT_NAME}"

# The container ran as root; hand the resulting .deb back to the host user.
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
docker run --rm --platform "${PLATFORM}" -v "${REPO_ROOT}:/repo" "${IMAGE}" \
    chown "${HOST_UID}:${HOST_GID}" "/repo/packaging/linux/dist/${OUT_NAME}"

echo "[build-deb] built ${LINUX_DIR}/dist/${OUT_NAME}"
