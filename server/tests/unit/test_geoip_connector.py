"""A-40: `geoip.py` — offline IP -> country resolution, fully self-
contained (a small hand-written CSV fixture per test, never the real
~24MB vendored dataset — see `packaging/macos/vendor-geoip.sh`'s own
docstring for why that one is fetched separately, at build time, not
committed). No Docker/network access required for this file.

Packaged-vs-dev directory resolution is tested with the exact same
`sys.frozen`/`sys._MEIPASS` monkeypatch technique
`test_osquery_connector.py`'s `_set_packaged()` already established for
`osquery.py`'s own `_resolve_osqueryi()` — copied here (not imported)
for the same reason that file gives: it needs to patch `geoip_module.sys`
specifically.
"""

from pathlib import Path

import pytest

import app.services.mcp.security_connectors.geoip as geoip_module
from app.config import Settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.geoip import (
    GEOIP_CONNECTOR_NAME,
    is_geoip_configured,
    register_geoip_connector,
    resolve_country,
    resolve_geoip_dir,
)

_IPV4_CSV = (
    "1.0.0.0,1.0.0.255,AU\n"
    "8.8.8.0,8.8.8.255,US\n"
    "93.184.216.0,93.184.216.255,US\n"
)
_IPV6_CSV = (
    "2001:4860:4860::,2001:4860:4860::ffff,US\n"
)


def _write_dataset(directory: Path, *, ipv4: str = _IPV4_CSV, ipv6: str = _IPV6_CSV) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / geoip_module.IPV4_FILENAME).write_text(ipv4, encoding="utf-8")
    (directory / geoip_module.IPV6_FILENAME).write_text(ipv6, encoding="utf-8")
    return directory


def _set_packaged(monkeypatch: pytest.MonkeyPatch, meipass: str) -> None:
    monkeypatch.setattr(geoip_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(geoip_module.sys, "_MEIPASS", meipass, raising=False)


# ---------------------------------------------------------------------------
# resolve_country / the range-table lookup itself
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_resolve_country_finds_an_ip_inside_a_loaded_ipv4_range(tmp_path: Path):
    _write_dataset(tmp_path)
    settings = Settings(geoip_database_dir=str(tmp_path))

    assert resolve_country("8.8.8.8", settings=settings) == "US"
    assert resolve_country("1.0.0.128", settings=settings) == "AU"


@pytest.mark.unit
def test_resolve_country_finds_an_ip_inside_a_loaded_ipv6_range(tmp_path: Path):
    _write_dataset(tmp_path)
    settings = Settings(geoip_database_dir=str(tmp_path))

    assert resolve_country("2001:4860:4860::8888", settings=settings) == "US"


@pytest.mark.unit
def test_resolve_country_is_honestly_none_for_an_address_no_range_covers(tmp_path: Path):
    """A private/reserved address (never present in a public delegation
    dataset) is a legitimately honest miss, not a bug — see
    `_CountryRangeTable.lookup`'s docstring."""
    _write_dataset(tmp_path)
    settings = Settings(geoip_database_dir=str(tmp_path))

    assert resolve_country("192.168.1.20", settings=settings) is None
    assert resolve_country("10.0.0.5", settings=settings) is None
    # Just past the loaded AU range's end (1.0.0.255) — the honest gap
    # case described in `_CountryRangeTable.lookup`.
    assert resolve_country("1.0.1.0", settings=settings) is None


@pytest.mark.unit
def test_resolve_country_returns_none_without_ever_raising_for_bad_input(tmp_path: Path):
    _write_dataset(tmp_path)
    settings = Settings(geoip_database_dir=str(tmp_path))

    assert resolve_country(None, settings=settings) is None
    assert resolve_country("", settings=settings) is None
    assert resolve_country("not-an-ip", settings=settings) is None


@pytest.mark.unit
def test_resolve_country_returns_none_when_no_database_directory_exists(tmp_path: Path):
    """`geoip_database_dir` points at a directory that was never populated
    (e.g. a fresh dev checkout that never ran vendor-geoip.sh) — honest
    `None`, never a crash, never a fabricated country."""
    missing_dir = tmp_path / "does-not-exist"
    settings = Settings(geoip_database_dir=str(missing_dir))

    assert is_geoip_configured(settings) is False
    assert resolve_country("8.8.8.8", settings=settings) is None


@pytest.mark.unit
def test_resolve_country_tolerates_malformed_csv_rows(tmp_path: Path):
    """One bad row must not take down the whole table (module docstring's
    "one bad row must not take down the whole table" rule) — a short row,
    an unparsable address, and an empty country code are all skipped, the
    well-formed rows around them still resolve."""
    directory = tmp_path / "geoip"
    _write_dataset(
        directory,
        ipv4=(
            "not,enough,columns,here\n"
            "1.0.0.0,1.0.0.255,AU\n"
            "garbage-start,1.0.2.255,JP\n"
            "1.0.3.0,1.0.3.255,\n"
            "8.8.8.0,8.8.8.255,US\n"
        ),
    )
    settings = Settings(geoip_database_dir=str(directory))

    assert resolve_country("1.0.0.128", settings=settings) == "AU"
    assert resolve_country("8.8.8.8", settings=settings) == "US"
    # The two malformed rows never made it into the table at all.
    assert resolve_country("1.0.2.128", settings=settings) is None
    assert resolve_country("1.0.3.128", settings=settings) is None


@pytest.mark.unit
def test_resolve_country_is_upper_cased_regardless_of_source_casing(tmp_path: Path):
    directory = _write_dataset(tmp_path, ipv4="1.0.0.0,1.0.0.255,au\n")
    settings = Settings(geoip_database_dir=str(directory))

    assert resolve_country("1.0.0.1", settings=settings) == "AU"


@pytest.mark.unit
def test_ipv4_only_dataset_leaves_ipv6_honestly_unavailable(tmp_path: Path):
    """A build that only vendored one family degrades gracefully — see
    `_tables_for_dir`'s own docstring."""
    directory = tmp_path / "geoip"
    directory.mkdir()
    (directory / geoip_module.IPV4_FILENAME).write_text(_IPV4_CSV, encoding="utf-8")
    # No IPv6 file written at all.
    settings = Settings(geoip_database_dir=str(directory))

    assert resolve_country("8.8.8.8", settings=settings) == "US"
    assert resolve_country("2001:4860:4860::8888", settings=settings) is None


# ---------------------------------------------------------------------------
# resolve_geoip_dir / is_geoip_configured priority order
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_explicit_setting_wins_over_the_vendored_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    explicit_dir = _write_dataset(tmp_path / "explicit")
    # A vendored dev-mode dir also exists, at a totally different path —
    # the explicit setting must win regardless.
    monkeypatch.setattr(geoip_module, "_dev_geoip_dir", lambda: tmp_path / "vendored-should-not-be-used")
    settings = Settings(geoip_database_dir=str(explicit_dir))

    assert resolve_geoip_dir(settings) == explicit_dir


@pytest.mark.unit
def test_dev_mode_falls_back_to_the_repo_vendor_directory_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    dev_dir = _write_dataset(tmp_path / "dev-vendor")
    monkeypatch.setattr(geoip_module, "_dev_geoip_dir", lambda: dev_dir)
    settings = Settings(geoip_database_dir=None)

    assert resolve_geoip_dir(settings) == dev_dir
    assert is_geoip_configured(settings) is True


@pytest.mark.unit
def test_packaged_mode_looks_under_sys_meipass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    vendored = _write_dataset(tmp_path / "vendor" / "geoip")
    _set_packaged(monkeypatch, str(tmp_path))
    settings = Settings(geoip_database_dir=None)

    assert resolve_geoip_dir(settings) == vendored


@pytest.mark.unit
def test_packaged_mode_without_a_vendored_copy_is_honestly_unconfigured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    _set_packaged(monkeypatch, str(tmp_path))  # nothing under tmp_path/vendor/geoip
    settings = Settings(geoip_database_dir=None)

    assert resolve_geoip_dir(settings) is None
    assert is_geoip_configured(settings) is False


@pytest.mark.unit
def test_configured_but_missing_directory_logs_and_returns_none(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
):
    missing = tmp_path / "gone"
    settings = Settings(geoip_database_dir=str(missing))

    with caplog.at_level("WARNING"):
        result = resolve_geoip_dir(settings)

    assert result is None
    assert "does not exist" in caplog.text


# ---------------------------------------------------------------------------
# register_geoip_connector
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_register_geoip_connector_reports_the_resolved_directory_as_endpoint(tmp_path: Path):
    directory = _write_dataset(tmp_path)
    settings = Settings(geoip_database_dir=str(directory))
    registry = MCPRegistry()

    register_geoip_connector(registry, settings=settings)

    connector = registry.get(GEOIP_CONNECTOR_NAME)
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "file"
    assert connector.endpoint == str(directory)


@pytest.mark.unit
def test_register_geoip_connector_reports_an_empty_endpoint_when_unconfigured(tmp_path: Path):
    settings = Settings(geoip_database_dir=str(tmp_path / "nope"))
    registry = MCPRegistry()

    register_geoip_connector(registry, settings=settings)

    connector = registry.get(GEOIP_CONNECTOR_NAME)
    assert connector.endpoint == ""
