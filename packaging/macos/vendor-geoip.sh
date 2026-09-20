#!/bin/sh
# A-40: downloads the offline IP -> country dataset this build vendors
# (see server/app/services/mcp/security_connectors/geoip.py's module
# docstring for the full licence research behind WHY this project uses
# sapics/ip-location-db's public-domain "user-country" table instead of
# MaxMind GeoLite2 — short version: GeoLite2 requires creating a MaxMind
# account, an "act as a specific real person on an external site" step
# this project's build tooling should never do unattended; the dataset
# below needs no account/registration/API key at all) at BUILD time only
# — never at runtime, same "an already-running packaged app never reaches
# the network or escalates privileges in the background" rule
# vendor-osquery.sh (this same directory) already established for the
# osquery binary. Run this ONCE before `pyinstaller
# packaging/macos/hranix-shield.spec`, same convention as that script.
#
# Licence: Public Domain Dedication and Licence v1.0 (PDDL) —
# https://opendatacommons.org/licenses/pddl/1.0/, verified live 2026-07-23
# against https://github.com/sapics/ip-location-db's own README ("Original
# Databases" section: "user-country... published under the Public Domain
# Dedication and License v1.0 (PDDL) (free use without attribution)").
# No attribution required, no account/registration of any kind.
#
# Unlike vendor-osquery.sh's ONE fixed release (a versioned .pkg, pinned
# by an immutable sha256 forever), this dataset is rebuilt by its
# publisher DAILY off the "latest" GitHub Releases tag — there is no
# single version to pin permanently. This script instead downloads the
# checksum file published in that SAME release alongside the data file
# and verifies the two agree — a FRESHNESS check ("did I get exactly the
# bytes the publish server is offering right now, not a corrupted/
# truncated download"), not a supply-chain pin against a value fixed at
# the time this script was written. A developer who wants a truly
# reproducible build should download and review a copy manually and point
# `GEOIP_DATABASE_DIR` at it instead (see Settings.geoip_database_dir /
# geoip.py's `resolve_geoip_dir`).

GEOIP_BASE_URL="https://github.com/sapics/ip-location-db/releases/download/latest"
GEOIP_CHECKSUM_BASE_URL="https://github.com/sapics/ip-location-db/releases/download/checksum"

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENDOR_DIR="$SCRIPT_DIR/vendor/geoip"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

fetch_and_verify() {
    filename="$1"
    echo "vendor-geoip.sh: downloading ${filename} from ${GEOIP_BASE_URL}"
    curl -sL --fail -o "$WORK_DIR/$filename" "$GEOIP_BASE_URL/$filename"

    echo "vendor-geoip.sh: downloading ${filename}.sha256 from ${GEOIP_CHECKSUM_BASE_URL}"
    curl -sL --fail -o "$WORK_DIR/$filename.sha256" "$GEOIP_CHECKSUM_BASE_URL/$filename.sha256"

    EXPECTED_SHA256="$(awk '{print $1}' "$WORK_DIR/$filename.sha256")"
    ACTUAL_SHA256="$(shasum -a 256 "$WORK_DIR/$filename" | awk '{print $1}')"
    if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
        echo "vendor-geoip.sh: FATAL — ${filename}'s sha256 does not match the" >&2
        echo "  checksum published alongside it in the same release" >&2
        echo "  expected: $EXPECTED_SHA256" >&2
        echo "  actual:   $ACTUAL_SHA256" >&2
        echo "  refusing to vendor a file that failed its own publisher's" >&2
        echo "  integrity check — a truncated/corrupted download, not" >&2
        echo "  something to silently ignore." >&2
        exit 1
    fi
    echo "vendor-geoip.sh: ${filename} sha256 verified"
}

fetch_and_verify "user-country-ipv4.csv"
fetch_and_verify "user-country-ipv6.csv"

rm -rf "$VENDOR_DIR"
mkdir -p "$VENDOR_DIR"
cp "$WORK_DIR/user-country-ipv4.csv" "$VENDOR_DIR/user-country-ipv4.csv"
cp "$WORK_DIR/user-country-ipv6.csv" "$VENDOR_DIR/user-country-ipv6.csv"

echo "vendor-geoip.sh: verifying the vendored files actually look like the expected CSV shape"
FIRST_LINE="$(head -n 1 "$VENDOR_DIR/user-country-ipv4.csv")"
case "$FIRST_LINE" in
    *,*,??) ;;
    *)
        echo "vendor-geoip.sh: FATAL — user-country-ipv4.csv's first line" >&2
        echo "  ('$FIRST_LINE') does not look like 'start,end,XX' — sapics/" >&2
        echo "  ip-location-db's CSV layout may have changed, inspect by hand" >&2
        echo "  before updating this script." >&2
        exit 1
        ;;
esac

echo "vendor-geoip.sh: done — $VENDOR_DIR ($(du -sh "$VENDOR_DIR" | awk '{print $1}'))"
echo "vendor-geoip.sh: licence — Public Domain Dedication and Licence v1.0 (PDDL)"
echo "  (https://opendatacommons.org/licenses/pddl/1.0/, verified against"
echo "  https://github.com/sapics/ip-location-db's own README, 2026-07-23)"
echo "  — free use, no attribution required, no account/registration needed;"
echo "  see server/app/services/mcp/security_connectors/geoip.py's module"
echo "  docstring for the full licence research (incl. why this is used"
echo "  instead of MaxMind GeoLite2)."
