"""A-40: offline IP -> country-code resolution for the `network` console's
connections table (security_console.py._network_payload) — augments each
row with a `country` field (ISO 3166-1 alpha-2, e.g. "US") without ever
making a network request per lookup, matching this project's "приватно,
локально" principle (CLAUDE.md) the same way every other connector in this
stack already does (osquery/CrowdSec/ClamAV/Wazuh are all either a local
subprocess or an already-running service on the SAME machine — never a
per-request call out to a third party).

## Licence research (done FIRST, before any of the code below — required
by CLAUDE.md's licence gate ("проверять лицензию... данные, не код, но
всё равно проверить и зафиксировать") and this task's own brief)

MaxMind's own free GeoLite2-Country database was the working assumption
in this task's brief — checked live against MaxMind's own published terms
on 2026-07-23, not assumed:

  - https://www.maxmind.com/en/geolite2/eula ("GeoLite End User License
    Agreement", last updated Feb 2026 per that page): the GeoLite2 DATA
    itself is licensed CC BY-SA 4.0 — an OSI-adjacent, share-alike
    Creative Commons licence. CLAUDE.md's licence gate ("Ядро платформы —
    только OSI-совместимое... Ядро") is written for CODE linked into this
    process; a vendored read-only data file is a different question, and
    CC BY-SA 4.0 data would likely have been an acceptable answer to it.
  - The blocker is a different, PROCEDURAL one: actually downloading a
    GeoLite2 copy requires first creating a free MaxMind *account*
    (https://www.maxmind.com/en/geolite2/signup — account_id + a
    generated licence key), and the EULA additionally obligates the
    licensee to keep the database up to date and destroy old copies.
    Registering a real account (a real e-mail address, agreeing to
    MaxMind's own ToS as a specific identifiable party) on the user's
    behalf, unprompted, inside a non-interactive automated task is
    exactly the kind of step the A-40 task brief calls out as a reason to
    STOP and report rather than push through — so this module does not
    use GeoLite2 (this decision — not a code bug — is why no
    `MAXMIND_LICENSE_KEY`-shaped setting exists anywhere in this
    codebase).

Rather than stopping the whole task, a genuinely no-registration
alternative was researched and found: **github.com/sapics/ip-location-db**
publishes `user-country` — a daily-rebuilt IP -> country-code table
compiled ONLY from sources with no redistribution restriction (RIR
delegated-stats files, public BGP routing archives — Route Views/RIPE
RIS — and RFC 8805/9632 geofeeds; explicitly NOT RIR whois data, which
most RIRs' own Acceptable Use Policies forbid using for geolocation at
all — see that project's own README, "Compliance & Data Handling
Policy") and published under the **Public Domain Dedication and Licence
v1.0 (PDDL)** — https://opendatacommons.org/licenses/pddl/1.0/, both
checked live 2026-07-23. PDDL is a public-domain-equivalent DATA licence:
no attribution required, no account/registration of any kind to
download (a plain anonymous `curl` against a public GitHub Releases
asset, with sha256 checksums published alongside in the same release),
no periodic-account-key-rotation obligation, no share-alike/copyleft
term at all. Strictly cleaner than GeoLite2's own CC BY-SA 4.0 for this
project's purposes — the real reason this module uses it instead of
GeoLite2 is "not merely licence-compatible, genuinely nicer", not a
grudging fallback.

Accuracy trade-off, stated honestly (from sapics/ip-location-db's own
published comparison, measured 14 June 2026, IPv4 only — see that
project's README "Accuracy of database" section): `user-country` agrees
with GeoLite2's own country_code for 97.49% of GeoLite2's IPv4 range
coverage (2.51% disagree, ~0% missing). Good enough for this console's
"which country is this remote host roughly in" signal — not survey-grade,
and not pretending to be. If a future task needs city-level detail or a
provably tighter match, the same upstream project also publishes
`dbip-country` (CC BY 4.0, attribution required) and `geolite2-country`
(the real MaxMind data, mirrored — still requires accepting MaxMind's own
EULA per that upstream project's README) as documented upgrade paths —
not a re-investigation from scratch.

## Mechanism

`packaging/<os>/vendor-geoip.sh` downloads the plain CSV release assets
(`user-country-ipv4.csv`/`user-country-ipv6.csv`, each row
`ip_range_start,ip_range_end,country_code`) at BUILD time only — never at
runtime, same "an already-running packaged app never reaches the network
or escalates privileges in the background" rule A-24's `vendor-osquery.sh`
already established for the osquery binary — into `packaging/<os>/vendor/
geoip/`, verified against a checksum fetched in that SAME build step (see
that script's own docstring for why this is a freshness check, not an
immutable version pin the way vendor-osquery.sh's fixed sha256 is: this
dataset is rebuilt by its publisher daily, there is no one version to pin
forever).

Deliberately the plain CSV format, not this same upstream project's
`.mmdb` (MaxMind binary format) asset: reading `.mmdb` needs a dedicated
parser library (no such dependency exists anywhere in this project yet,
and adding one would be its own separate CLAUDE.md licence-gate check for
zero benefit here), while the CSV's `start,end,country_code` ranges
(already sorted by `start` in the real downloaded file — confirmed while
building this task, and defensively re-sorted below regardless, see
`_load_range_table`) are a single `bisect` lookup over two arrays parsed
once and cached in memory, using nothing beyond the standard library.

Three states this module can be in, checked live while building this
task (no such database is vendored on this repo's own dev checkout by
default — `is_geoip_configured()` is False until `packaging/<os>/
vendor-geoip.sh` has been run at least once, or `Settings.geoip_database_dir`
points at a manually-downloaded copy):

  - No database directory resolvable at all (`resolve_geoip_dir()` is
    `None`) -> `resolve_country()` always returns `None` — never a
    fabricated country code.
  - A database directory exists, but the specific IP is not covered by
    any range in it (a private/reserved address like `192.168.x.x` is
    never present in a public delegation dataset, or the public dataset
    simply has a gap) -> `resolve_country()` returns `None` too — this is
    a legitimately honest "no country", not a bug.
  - A database directory exists and the IP is covered -> the real ISO
    3166-1 alpha-2 code from the dataset.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
import logging
import sys
from pathlib import Path

from app.config import REPO_ROOT, Settings, get_settings, is_packaged
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry

logger = logging.getLogger(__name__)

GEOIP_CONNECTOR_NAME = "geoip"

# The two release assets `packaging/<os>/vendor-geoip.sh` downloads (see
# that script and this module's docstring) — exact filenames from
# sapics/ip-location-db's own release, kept as constants (not repeated
# literals) so the vendor script and this reader can never drift apart.
IPV4_FILENAME = "user-country-ipv4.csv"
IPV6_FILENAME = "user-country-ipv6.csv"


def _packaging_os_dirname() -> str:
    """Which `packaging/<this>/` directory this platform's vendored data
    would live under — same three-way split
    `packaging/{macos,linux,windows}/` already uses for `vendor-osquery.sh`
    and the `.spec` files, re-derived here (not imported) since no shared
    "current OS's packaging dir name" helper exists yet elsewhere in this
    codebase."""
    if sys.platform == "darwin":
        return "macos"
    if sys.platform == "win32":
        return "windows"
    return "linux"


def _vendored_geoip_dir() -> Path:
    """Where a packaged build's own `.spec` places the vendored CSVs —
    `<PyInstaller bundle root>/vendor/geoip/` — only ever called when
    `is_packaged()` is already True. Deliberately duplicates (does not
    import) the `sys._MEIPASS` detection `osquery.py`'s
    `_vendored_osqueryi_path()` already uses, for the exact same reason
    that module's docstring gives: importing a shared helper from
    `launcher.py` here would be a real circular import (`launcher` ->
    `app.app_factory` -> this module, via `security_console.py` ->
    `security_connectors/__init__.py`), confirmed by tracing the same
    import chain osquery.py already documented."""
    return Path(sys._MEIPASS) / "vendor" / "geoip"  # type: ignore[attr-defined]


def _dev_geoip_dir() -> Path:
    """Where a developer running from a source checkout (not packaged) can
    populate the same data by hand, running `packaging/<os>/vendor-geoip.sh`
    locally — mirrors that script's own output location, so "run the
    vendor script once" works identically whether or not a real packaged
    build is ever produced."""
    return REPO_ROOT / "packaging" / _packaging_os_dirname() / "vendor" / "geoip"


def resolve_geoip_dir(settings: Settings | None = None) -> Path | None:
    """The directory this process should load `user-country-ipv4.csv`/
    `user-country-ipv6.csv` from, or `None` when none is available —
    checked fresh on every call (never cached), same "`is_packaged()` is
    re-checked every access" discipline `app/config.py`'s own
    `resolved_*` properties document, so a test can monkeypatch
    `Settings.geoip_database_dir`/`sys.frozen`/`sys._MEIPASS` per-test with
    no reload required.

    Priority order:
      1. `Settings.geoip_database_dir`, if set AND the directory actually
         exists — the explicit-override escape hatch the A-40 task brief
         allows ("можно и просто указать путь к скачанной вручную базе
         через настройку") for an operator who downloaded a copy by hand
         without running the vendor script at all.
      2. The vendored copy (`_vendored_geoip_dir()` when `is_packaged()`,
         else `_dev_geoip_dir()`) — the "works out of the box once
         packaged/vendored, honestly `None` otherwise" default every other
         connector in this stack already follows (see e.g. osquery.py's
         `_resolve_osqueryi()`).
    """
    settings = settings or get_settings()
    if settings.geoip_database_dir:
        configured = Path(settings.geoip_database_dir)
        if configured.is_dir():
            return configured
        logger.warning(
            "geoip: configured geoip_database_dir %s does not exist", configured
        )
        return None

    candidate = _vendored_geoip_dir() if is_packaged() else _dev_geoip_dir()
    return candidate if candidate.is_dir() else None


def is_geoip_configured(settings: Settings | None = None) -> bool:
    """True iff a usable geoip database directory is resolvable right now
    — mirrors `is_crowdsec_configured`/`is_clamav_configured`'s "no
    connection, just a config-shape check" role in this stack."""
    return resolve_geoip_dir(settings) is not None


class _CountryRangeTable:
    """One IP-family's parsed range table — three parallel arrays (not a
    list of tuples) so `bisect` can search `starts` directly without a key
    function, the standard "structure-of-arrays for a hot bisect lookup"
    shape. `starts` is kept strictly ascending (see `_load_range_table`),
    which is what makes `lookup()`'s binary search correct."""

    __slots__ = ("starts", "ends", "codes")

    def __init__(self, starts: list[int], ends: list[int], codes: list[str]) -> None:
        self.starts = starts
        self.ends = ends
        self.codes = codes

    @classmethod
    def empty(cls) -> "_CountryRangeTable":
        return cls([], [], [])

    def lookup(self, value: int) -> str | None:
        """`value` (an IP address as a plain int, see `resolve_country`)
        -> the country code of the range covering it, or `None` when no
        loaded range covers it (see module docstring's "honest None"
        states)."""
        idx = bisect.bisect_right(self.starts, value) - 1
        if idx < 0:
            return None
        if value > self.ends[idx]:
            # Falls in the gap between range `idx` and range `idx + 1` —
            # real gaps exist in this dataset (see module docstring's
            # accuracy note), an honest miss, not a bug.
            return None
        return self.codes[idx]


def _load_range_table(path: Path, *, family: int) -> _CountryRangeTable:
    """Parses one `ip_range_start,ip_range_end,country_code` CSV (the exact
    shape sapics/ip-location-db's `user-country-ipv{4,6}.csv` publish, see
    module docstring) into a `_CountryRangeTable`. Never raises on a
    malformed row — skips it and keeps going, same "one bad row must not
    take down the whole table" defensiveness every other connector in this
    stack applies to one bad *field* (see e.g. osquery.py's `_to_int`).

    Re-sorts by `start` before building the table even though the real
    downloaded file was confirmed already sorted while building this task
    — a cheap, one-time defensive step (this file is loaded once and
    cached, see `_tables_for_dir`) rather than trusting an external
    publisher's ordering to never change.
    """
    rows: list[tuple[int, int, str]] = []
    with path.open(newline="", encoding="utf-8") as fh:
        for line in csv.reader(fh):
            if len(line) != 3:
                continue
            start_s, end_s, code = line
            try:
                start_addr = ipaddress.ip_address(start_s.strip())
                end_addr = ipaddress.ip_address(end_s.strip())
            except ValueError:
                continue
            if start_addr.version != family or end_addr.version != family:
                continue
            code = code.strip().upper()
            if not code:
                continue
            rows.append((int(start_addr), int(end_addr), code))

    rows.sort(key=lambda row: row[0])
    return _CountryRangeTable(
        starts=[row[0] for row in rows],
        ends=[row[1] for row in rows],
        codes=[row[2] for row in rows],
    )


# Keyed by the resolved geoip directory's own string path — a fresh
# directory (e.g. a test's own `tmp_path`) always gets a fresh parse, the
# same directory is only ever parsed once per process lifetime. Simple
# `dict`, not `functools.lru_cache`: caching on a `Path` object's `__eq__`
# would work too, but keying on the resolved string makes the "which
# directory did this come from" relationship explicit when debugging.
_TABLE_CACHE: dict[str, tuple[_CountryRangeTable, _CountryRangeTable]] = {}


def _tables_for_dir(geoip_dir: Path) -> tuple[_CountryRangeTable, _CountryRangeTable]:
    """(ipv4 table, ipv6 table) for `geoip_dir`, parsed once and cached for
    the rest of this process's lifetime — parsing ~280k/~275k CSV rows
    takes a few hundred milliseconds (measured while building this task),
    fine as a one-time cost, not something a per-request dashboard refresh
    should ever pay twice. A missing individual file (e.g. a build that
    only vendored IPv4) degrades to that family's table being empty
    (`_CountryRangeTable.empty()`) rather than failing the whole
    directory — an IPv6-only gap is honestly "no IPv6 country data", not a
    reason to also lose IPv4 resolution.
    """
    key = str(geoip_dir)
    cached = _TABLE_CACHE.get(key)
    if cached is not None:
        return cached

    ipv4_path = geoip_dir / IPV4_FILENAME
    ipv6_path = geoip_dir / IPV6_FILENAME
    ipv4_table = (
        _load_range_table(ipv4_path, family=4) if ipv4_path.is_file() else _CountryRangeTable.empty()
    )
    ipv6_table = (
        _load_range_table(ipv6_path, family=6) if ipv6_path.is_file() else _CountryRangeTable.empty()
    )
    tables = (ipv4_table, ipv6_table)
    _TABLE_CACHE[key] = tables
    return tables


def resolve_country(ip: str | None, *, settings: Settings | None = None) -> str | None:
    """Resolves `ip` (an IPv4/IPv6 literal, e.g. osquery.py's
    `fetch_network_console_data`'s per-row `remote_address`) to an ISO
    3166-1 alpha-2 country code, or `None` — never a fabricated guess —
    for any of: no database available at all (`is_geoip_configured()`
    False), `ip` itself falsy/unparsable (a listening-socket row has no
    remote side at all, see osquery.py's docstring — `formatNetworkEndpoint`
    on the frontend already treats that as an honest "—"), or `ip` simply
    not covered by any loaded range (see `_CountryRangeTable.lookup`'s
    docstring — includes every private/reserved address, which is the
    correct answer for e.g. `192.168.1.20`, not a bug).
    """
    if not ip:
        return None
    geoip_dir = resolve_geoip_dir(settings)
    if geoip_dir is None:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    ipv4_table, ipv6_table = _tables_for_dir(geoip_dir)
    table = ipv4_table if addr.version == 4 else ipv6_table
    return table.lookup(int(addr))


def register_geoip_connector(registry: MCPRegistry, *, settings: Settings | None = None) -> None:
    """Registers this task's connector *description* (see connector.py's
    own docstring for why that class only holds metadata) — `endpoint` is
    the resolved database directory when one is available, `""` (the
    established "not wired up yet, not an error" convention) otherwise.
    `transport="file"`: unlike every sibling connector in this stack (a
    subprocess/TCP socket/HTTP call), this one is a plain local file read
    with no live process/service on the other end at all — the most
    accurate of the free-form strings `MCPConnector.transport` already
    documents as open-ended.
    """
    settings = settings or get_settings()
    geoip_dir = resolve_geoip_dir(settings)
    registry.register(
        MCPConnector(
            name=GEOIP_CONNECTOR_NAME,
            description=(
                "Offline IP -> country resolution for the network console's "
                "connections table (sapics/ip-location-db 'user-country', "
                "Public Domain Dedication and Licence v1.0 — see this "
                "module's docstring for the full GeoLite2-vs-this licence "
                "research). Local file lookup only, never a network "
                "request per connection."
            ),
            transport="file",
            endpoint=str(geoip_dir) if geoip_dir is not None else "",
        )
    )
