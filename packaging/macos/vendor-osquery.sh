#!/bin/sh
# A-24: downloads the OFFICIAL osquery macOS .pkg at BUILD time only (never
# at runtime — see this task's brief: an already-running packaged app must
# never hit the network/escalate privileges in the background) and extracts
# a standalone `osqueryi` binary into packaging/macos/vendor/osquery/, where
# hranix-shield.spec's `datas=[...]` picks it up for the .app bundle (see
# that file's own comment). Run this ONCE before `pyinstaller
# packaging/macos/hranix-shield.spec` — same "separate, tracked build step,
# not a hidden one-off" convention packaging/linux/build-in-docker.sh
# already established for its own build step.
#
# Pinned version/URL/checksum (2026-07-18, verified against osquery's own
# GitHub Releases API, not recalled from memory:
#   curl -s https://api.github.com/repos/osquery/osquery/releases/latest
# returned tag_name "5.23.1", published 2026-06-24, asset
# "osquery-5.23.1.pkg"):
OSQUERY_VERSION="5.23.1"
OSQUERY_PKG_URL="https://github.com/osquery/osquery/releases/download/${OSQUERY_VERSION}/osquery-${OSQUERY_VERSION}.pkg"
# `shasum -a 256` of the downloaded .pkg, computed on THIS machine right
# after downloading it (2026-07-18) — not copied from any osquery-published
# checksum page (osquery's release page does not itself publish per-asset
# sha256sums as of this version; this is this build's own pin, the same
# "verify what you actually got, not what you expect" discipline the rest
# of this project's dependency-license table already applies).
OSQUERY_PKG_SHA256="9f40cea0358759ab2ee871c577055657e3cc2c7cbe5c1247f764245941178aa6"

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor/osquery"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "vendor-osquery.sh: downloading osquery ${OSQUERY_VERSION} .pkg from ${OSQUERY_PKG_URL}"
curl -sL --fail -o "$WORK_DIR/osquery.pkg" "$OSQUERY_PKG_URL"

ACTUAL_SHA256="$(shasum -a 256 "$WORK_DIR/osquery.pkg" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$OSQUERY_PKG_SHA256" ]; then
    echo "vendor-osquery.sh: FATAL — downloaded osquery-${OSQUERY_VERSION}.pkg's sha256" >&2
    echo "  expected: $OSQUERY_PKG_SHA256" >&2
    echo "  actual:   $ACTUAL_SHA256" >&2
    echo "  refusing to vendor an unverified binary — if osquery genuinely" >&2
    echo "  released a new build under the same version tag, re-verify by" >&2
    echo "  hand and update OSQUERY_PKG_SHA256 above deliberately, don't" >&2
    echo "  just delete this check." >&2
    exit 1
fi
echo "vendor-osquery.sh: sha256 verified"

echo "vendor-osquery.sh: expanding .pkg (pkgutil --expand-full, no system install)"
pkgutil --expand-full "$WORK_DIR/osquery.pkg" "$WORK_DIR/expanded"

# The official .pkg lays out `/usr/local/bin/osqueryi` as a SYMLINK to
# `/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd` — osquery is one
# binary that switches between "daemon" and "interactive shell" behaviour
# based on the basename it was invoked as (confirmed empirically while
# building this task, not assumed: copying the real osqueryd binary and
# simply renaming the copy to "osqueryi" is enough — no separate osqueryi
# binary exists in the package at all). The real Mach-O lives inside that
# tiny app-bundle wrapper (`opt/osquery/lib/osquery.app/`), not at the
# usr/local/bin path directly.
REAL_BINARY="$WORK_DIR/expanded/Payload/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd"
if [ ! -f "$REAL_BINARY" ]; then
    echo "vendor-osquery.sh: FATAL — expected osqueryd binary not found at" >&2
    echo "  $REAL_BINARY" >&2
    echo "  osquery's .pkg layout may have changed since ${OSQUERY_VERSION} — inspect" >&2
    echo "  $WORK_DIR/expanded manually before updating this script." >&2
    exit 1
fi

rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"
cp "$REAL_BINARY" "$VENDOR_DIR/osqueryi"
chmod +x "$VENDOR_DIR/osqueryi"

# Apple's own signature on osqueryd is an APP-BUNDLE signature: its
# "Sealed Resources" component hashes sibling files inside
# Contents/Resources + Contents/Info.plist (see `codesign -dv` on the
# original .app) — those siblings do not exist once this binary is copied
# out on its own, so the ORIGINAL signature is no longer valid for this
# flat, renamed copy. Confirmed empirically while building this task:
# invoking the copied-but-still-originally-signed binary directly is
# silently SIGKILLed by the kernel (exit code 137, zero output) on this
# Apple Silicon dev machine — macOS requires every executed Mach-O to
# carry a VALID code signature, and an app-bundle signature whose sealed
# resources are missing is not valid standalone. The fix (same one any
# project vendoring a helper binary out of its original bundle needs):
# strip Apple's bundle signature and re-sign AD HOC (`codesign --sign -`)
# — an ad hoc signature only covers this one file's own bytes, no sealed
# sibling resources required, and runs fine locally without needing to be
# from a trusted authority (this app is unsigned/unnotarized as a whole
# already, see packaging/macos/README.md's Gatekeeper section — vendoring
# an ad hoc-signed helper binary next to an already-unsigned .app adds no
# new trust requirement).
codesign --remove-signature "$VENDOR_DIR/osqueryi"
codesign --sign - --force "$VENDOR_DIR/osqueryi"

echo "vendor-osquery.sh: verifying the re-signed binary actually runs and answers a real query"
VERSION_OUTPUT="$("$VENDOR_DIR/osqueryi" --version 2>&1)"
echo "vendor-osquery.sh: $VERSION_OUTPUT"
case "$VERSION_OUTPUT" in
    *"$OSQUERY_VERSION"*) ;;
    *)
        echo "vendor-osquery.sh: FATAL — vendored binary's --version output" >&2
        echo "  did not mention $OSQUERY_VERSION: $VERSION_OUTPUT" >&2
        exit 1
        ;;
esac

echo "vendor-osquery.sh: done — $VENDOR_DIR/osqueryi ($(du -h "$VENDOR_DIR/osqueryi" | awk '{print $1}'))"
echo "vendor-osquery.sh: licence — osquery is dual-licensed Apache-2.0 OR GPL-2.0-only"
echo "  (SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only, verified against"
echo "  https://github.com/osquery/osquery/blob/${OSQUERY_VERSION}/LICENSE, 2026-07-18)"
echo "  — this project elects Apache-2.0 (the OSI-clean, non-copyleft choice"
echo "  CLAUDE.md's licence gate expects); see packaging/macos/README.md's"
echo "  licence table for the full citation."
