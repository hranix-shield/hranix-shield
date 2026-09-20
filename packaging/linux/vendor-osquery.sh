#!/usr/bin/env bash
# A-24: downloads the OFFICIAL osquery Linux (amd64) .deb at BUILD time
# only (never at runtime — an already-running packaged app must never hit
# the network/escalate privileges in the background, see this task's own
# brief) and extracts a standalone `osqueryi` binary into
# packaging/linux/vendor/osquery/, where hranix-shield.spec's
# `datas=[...]` picks it up for the onedir bundle (see that file's own
# comment). Run this ONCE before build-in-docker.sh — same "separate,
# tracked build step, not a hidden one-off" convention that script already
# established for its own step.
#
# --- Vendored binary vs. `apt-get install` in postinst: the real trade-off ---
#
# The A-24 task brief explicitly leaves this choice to the developer, both
# options considered on their actual merits (not a default carried over
# from macOS without re-checking):
#
#   (a) VENDOR the binary at build time (chosen here) — the .deb ships a
#       fully self-contained install: no network access needed at INSTALL
#       time, no third-party apt repository/GPG key to trust on the
#       end-user's machine, works identically offline. Cost: the shipped
#       osquery version is frozen to whatever this script downloaded at
#       build time — updating it means rebuilding the .deb, exactly the
#       same trade-off this project already accepted for PyInstaller/
#       rumps/infi.systray versions (see packaging/*/README.md's own
#       licence tables, each pinned to one version, bumped by hand on
#       rebuild).
#   (b) `apt-get install -y osquery` in `debian/postinst`, after adding
#       osquery's own apt repository (https://pkg.osquery.io/deb) — easier
#       to keep current (`apt upgrade` on the target machine alone updates
#       it), but adds a REAL network dependency at INSTALL time (the whole
#       reason A-19..A-22 exist is a "panель безопасности продукт для
#       локальности/приватности", CLAUDE.md's open/closed boundary; making
#       first install silently depend on reaching a third-party apt
#       mirror, and implicitly trusting one more GPG key, cuts against
#       that) and needs `sudo`/root at install time regardless (already
#       true for this whole .deb via dpkg, so not a NEW privilege
#       requirement, but still a new EXTERNAL package source added to the
#       target system, which `apt` tracks/exposes forever after, not just
#       for the duration of this one install).
#
# (a) is chosen for the same reason macOS's vendor-osquery.sh vendors
# rather than shells out to `brew install --cask` at install time: this
# project's own architecture already treats "no background network/
# privilege escalation for an already-running app" as a hard rule, and
# extending that same "install-time-only, one pinned download, no lasting
# third-party repo added to the host" property to Linux keeps the story
# consistent across all three OSes rather than Linux alone taking on a
# permanent apt-repo dependency the other two never need. Documented here
# instead of silently defaulting to whichever came first.
#
# Pinned version/URL/checksum (2026-07-18, verified against osquery's own
# GitHub Releases API, not recalled from memory — same release macOS's
# vendor-osquery.sh uses, see that script for the exact `curl` command):
OSQUERY_VERSION="5.23.1"
OSQUERY_DEB_URL="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery_${OSQUERY_VERSION}-1.linux_amd64.deb"
# `shasum -a 256` of the downloaded .deb, computed on this machine right
# after downloading it (2026-07-18) — same "verify what you actually got"
# discipline as macOS's vendor-osquery.sh.
OSQUERY_DEB_SHA256="1431a9a6394657eba3cdd3476a462a6fe9721fc3664a70f23efcf7e37816787a"

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LINUX_DIR="${REPO_ROOT}/packaging/linux"
VENDOR_DIR="${LINUX_DIR}/vendor/osquery"
# Same image/platform build-in-docker.sh already pins (see that script's
# own comment for the amd64-vs-arm64 and glibc-version reasoning) — using
# the identical image here, not just "any Debian image", means the
# extracted binary is tested (below) under the exact same glibc this
# project's own PyInstaller bundle already targets, one fewer place a
# glibc-compatibility surprise (A-22's real, previously-hit bug) could
# sneak back in.
IMAGE="python:3.12-slim-bullseye"
PLATFORM="linux/amd64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "[vendor-osquery] downloading osquery ${OSQUERY_VERSION} .deb from ${OSQUERY_DEB_URL}"
curl -sL --fail -o "${WORK_DIR}/osquery.deb" "${OSQUERY_DEB_URL}"

ACTUAL_SHA256="$(shasum -a 256 "${WORK_DIR}/osquery.deb" | awk '{print $1}')"
if [ "${ACTUAL_SHA256}" != "${OSQUERY_DEB_SHA256}" ]; then
    echo "[vendor-osquery] FATAL — downloaded osquery_${OSQUERY_VERSION}-1.linux_amd64.deb's sha256" >&2
    echo "  expected: ${OSQUERY_DEB_SHA256}" >&2
    echo "  actual:   ${ACTUAL_SHA256}" >&2
    echo "  refusing to vendor an unverified binary — re-verify by hand and" >&2
    echo "  update OSQUERY_DEB_SHA256 above deliberately if this is a genuine" >&2
    echo "  re-release, don't just delete this check." >&2
    exit 1
fi
echo "[vendor-osquery] sha256 verified"

rm -rf "${VENDOR_DIR}"
mkdir -p "${VENDOR_DIR}"

echo "[vendor-osquery] extracting .deb (dpkg-deb -x, no system install) and verifying inside ${IMAGE} (${PLATFORM})"
docker run --rm \
    --platform "${PLATFORM}" \
    -v "${WORK_DIR}:/work" \
    -v "${VENDOR_DIR}:/vendor-out" \
    -w /work \
    "${IMAGE}" \
    bash -euxc '
        dpkg-deb -x osquery.deb extracted

        # Same shape as the macOS .pkg (see packaging/macos/vendor-osquery.sh):
        # /usr/bin/osqueryi ships as a SYMLINK to the same osqueryd binary
        # (osquery is one executable that switches "daemon" vs "interactive
        # shell" behaviour based on the basename it was invoked as, confirmed
        # empirically, not assumed) — the real ELF lives at
        # opt/osquery/bin/osqueryd, not behind the usr/bin/ symlink directly.
        REAL_BINARY="extracted/opt/osquery/bin/osqueryd"
        if [ ! -f "$REAL_BINARY" ]; then
            echo "[vendor-osquery] FATAL: expected osqueryd binary not found at $REAL_BINARY" >&2
            echo "  osquery deb layout may have changed since '"${OSQUERY_VERSION}"' — inspect the" >&2
            echo "  extracted tree manually before updating this script." >&2
            exit 1
        fi

        cp "$REAL_BINARY" /vendor-out/osqueryi
        chmod +x /vendor-out/osqueryi

        # Unlike macOS, ELF binaries need no re-signing to run standalone —
        # confirmed here by actually running the copy under its new name,
        # inside the SAME base image the real PyInstaller build/install-test
        # runs under (see build-in-docker.sh/README.md).
        echo "[vendor-osquery] verifying the extracted+renamed binary actually runs and answers a real query"
        /vendor-out/osqueryi --version
        /vendor-out/osqueryi --json "SELECT count(*) AS process_count FROM processes;"
    '

# The container ran as root, so /vendor-out (bind-mounted VENDOR_DIR) landed
# owned by root:root on the host — hand it back, same pattern
# build-in-docker.sh/build-deb.sh already use for their own Docker output.
docker run --rm --platform "${PLATFORM}" -v "${VENDOR_DIR}:/vendor-out" "${IMAGE}" \
    chown -R "${HOST_UID}:${HOST_GID}" /vendor-out

echo "[vendor-osquery] done: ${VENDOR_DIR}/osqueryi ($(du -h "${VENDOR_DIR}/osqueryi" | awk '{print $1}'))"
echo "[vendor-osquery] licence — osquery is dual-licensed Apache-2.0 OR GPL-2.0-only"
echo "  (SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only, verified against"
echo "  https://github.com/osquery/osquery/blob/${OSQUERY_VERSION}/LICENSE, 2026-07-18)"
echo "  — this project elects Apache-2.0 (the OSI-clean, non-copyleft choice"
echo "  CLAUDE.md's licence gate expects); see packaging/linux/README.md's"
echo "  licence table for the full citation."
