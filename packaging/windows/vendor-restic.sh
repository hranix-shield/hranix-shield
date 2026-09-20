#!/bin/sh
# A-61: downloads the OFFICIAL restic Windows binary at BUILD time only
# (never at runtime — the same rule vendor-osquery.sh established for
# osquery: an already-running packaged app must never hit the network in
# the background) and places a standalone `restic.exe` plus its LICENSE
# into packaging/windows/vendor/restic/, where hranix-shield.spec's
# `datas=[...]` picks them up for the onedir bundle (see that file's own
# A-61 comments). Run this ONCE before `pyinstaller
# packaging/windows/hranix-shield.spec` — same "separate, tracked build
# step, not a hidden one-off" convention the other vendor scripts already
# follow. On this OS-agnostic shell-script shape (vs osquery's inline
# PowerShell CI step): restic ships a plain zip, so there is no
# msiexec/admin-install dance that would need real Windows tooling — the
# same script runs verbatim on the windows-latest CI runner (bash is
# preinstalled there and .github/workflows/windows-build.yml's
# "Vendor restic" step invokes it with shell: bash) and in a developer's
# Git Bash checkout. restic is BSD-2-Clause (licence gate CLAUDE.md:
# MIT/Apache/BSD binaries may be VENDORED, unlike GPL components which may
# only run as separate network services — a restic subprocess is exactly
# the already-established services/backup/restic_client.py shape).
#
# Pinned version/URL/checksum (2026-09-20, verified live, not recalled
# from memory): restic's GitHub Releases API returned tag_name "v0.19.1",
# published 2026-07-05; asset "restic_0.19.1_windows_amd64.zip". The
# sha256 below was computed on the Windows dev machine (Git Bash,
# `sha256sum`) right after downloading the archive AND cross-checked
# against restic's own release-published SHA256SUMS file (both agree).
RESTIC_VERSION="0.19.1"
RESTIC_ZIP_URL="https://github.com/restic/restic/releases/download/v${RESTIC_VERSION}/restic_${RESTIC_VERSION}_windows_amd64.zip"
RESTIC_ZIP_SHA256="da948ad707ed690426473aaba2046cd61f8f90f6f0e7dab6be0d5796531de67d"
# The licence travels WITH the vendored binary (plan-spec: "LICENSE бинаря
# — рядом"), pinned to the same tag so it can never drift from the actual
# code shipped.
RESTIC_LICENSE_URL="https://raw.githubusercontent.com/restic/restic/v${RESTIC_VERSION}/LICENSE"

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor/restic"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "vendor-restic.sh: downloading restic ${RESTIC_VERSION} windows_amd64.zip from ${RESTIC_ZIP_URL}"
curl -sL --fail -o "$WORK_DIR/restic.zip" "$RESTIC_ZIP_URL"

ACTUAL_SHA256="$(sha256sum "$WORK_DIR/restic.zip" | awk '{print $1}')"
if [ "$ACTUAL_SHA256" != "$RESTIC_ZIP_SHA256" ]; then
    echo "vendor-restic.sh: FATAL — downloaded restic_${RESTIC_VERSION}_windows_amd64.zip's sha256" >&2
    echo "  expected: $RESTIC_ZIP_SHA256" >&2
    echo "  actual:   $ACTUAL_SHA256" >&2
    echo "  refusing to vendor an unverified binary — if restic genuinely" >&2
    echo "  released a new build under the same version tag, re-verify by" >&2
    echo "  hand (and against restic's own release SHA256SUMS) and update" >&2
    echo "  RESTIC_ZIP_SHA256 above deliberately, don't just delete this check." >&2
    exit 1
fi
echo "vendor-restic.sh: sha256 verified (matches the release-published SHA256SUMS value pinned above)"

echo "vendor-restic.sh: extracting the restic binary (plain zip, no install)"
# The archive ships ONE file named restic_<version>_windows_amd64.exe
# (verified live against the pinned release, 2026-09-20) — extract it,
# then normalize the name to the bare restic.exe the spec/runtime expect.
unzip -o -j "$WORK_DIR/restic.zip" "restic_*_windows_amd64.exe" -d "$WORK_DIR"
mv "$WORK_DIR"/restic_*_windows_amd64.exe "$WORK_DIR/restic.exe"
if [ ! -f "$WORK_DIR/restic.exe" ]; then
    echo "vendor-restic.sh: FATAL — restic binary not found inside the archive;" >&2
    echo "  restic's zip layout may have changed since ${RESTIC_VERSION} — inspect" >&2
    echo "  $WORK_DIR manually before updating this script." >&2
    exit 1
fi

rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"
cp "$WORK_DIR/restic.exe" "$VENDOR_DIR/restic.exe"
curl -sL --fail -o "$VENDOR_DIR/LICENSE" "$RESTIC_LICENSE_URL"
if ! head -1 "$VENDOR_DIR/LICENSE" | grep -qi "BSD"; then
    echo "vendor-restic.sh: FATAL — downloaded LICENSE does not look like the" >&2
    echo "  expected BSD-2-Clause text (first line: $(head -1 "$VENDOR_DIR/LICENSE"))" >&2
    echo "  refusing to ship a binary without its licence — inspect" >&2
    echo "  ${RESTIC_LICENSE_URL} manually before updating this check." >&2
    exit 1
fi

echo "vendor-restic.sh: verifying the vendored binary actually runs and reports the pinned version"
VERSION_OUTPUT="$("$VENDOR_DIR/restic.exe" version 2>&1)"
echo "vendor-restic.sh: $VERSION_OUTPUT"
case "$VERSION_OUTPUT" in
    *"restic ${RESTIC_VERSION}"*) ;;
    *)
        echo "vendor-restic.sh: FATAL — vendored binary's version output" >&2
        echo "  did not mention restic ${RESTIC_VERSION}: $VERSION_OUTPUT" >&2
        exit 1
        ;;
esac

echo "vendor-restic.sh: done — $VENDOR_DIR/restic.exe ($(du -h "$VENDOR_DIR/restic.exe" | awk '{print $1}')) + LICENSE"
echo "vendor-restic.sh: licence — restic is BSD-2-Clause (verified against"
echo "  https://github.com/restic/restic/blob/v${RESTIC_VERSION}/LICENSE, 2026-09-20);"
echo "  the vendored copy's own LICENSE file sits next to the binary."
