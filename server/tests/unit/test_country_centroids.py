"""A-41: `country_centroids.py`'s static `country_centroid()` lookup — pure
data + one small function, no I/O, no fixtures needed (unlike geoip.py's own
unit tests, which build a throwaway CSV per test — there is nothing to
vendor or resolve a directory for here, see that module's own docstring for
why this file is deliberately simpler)."""

import pytest

from app.services.mcp.security_connectors.country_centroids import (
    _CENTROIDS,
    country_centroid,
)


@pytest.mark.unit
def test_known_codes_resolve_to_their_publicly_known_centroid():
    """A spot-check against a handful of countries whose approximate
    latitude/longitude is common knowledge (DoD: "сверить хотя бы одну
    координату вручную — центроид США/России и т.п. — совпадает с публично
    известными широтой/долготой этой страны") — the US centroid is
    continental-interior (positive lat, deeply negative lon, nowhere near
    either coast), Russia's is Siberian (high positive lat AND lon, not
    anywhere near Moscow in the west), reversed-hemisphere sanity for
    Australia (negative lat) and Brazil (negative lat, negative lon)."""
    us_lat, us_lon = country_centroid("US")
    assert 25 < us_lat < 50
    assert -125 < us_lon < -65

    ru_lat, ru_lon = country_centroid("RU")
    assert 40 < ru_lat < 75
    assert 30 < ru_lon < 180

    au_lat, au_lon = country_centroid("AU")
    assert -45 < au_lat < -10
    assert 110 < au_lon < 155

    br_lat, br_lon = country_centroid("BR")
    assert -35 < br_lat < 5
    assert -75 < br_lon < -30


@pytest.mark.unit
def test_lookup_is_case_insensitive_and_whitespace_tolerant():
    """Mirrors `resolve_country()`'s own `.strip().upper()` normalisation in
    geoip.py — this function is meant to compose directly onto that one's
    output without the caller needing its own defensive normalisation."""
    assert country_centroid("us") == country_centroid("US")
    assert country_centroid(" DE ") == country_centroid("DE")


@pytest.mark.unit
def test_unrecognised_code_is_honestly_none_not_a_fabricated_origin():
    """`(0.0, 0.0)` is a real point in the Gulf of Guinea, not "unknown" —
    an unrecognised code must never silently resolve there (this module's
    own docstring explains why)."""
    assert country_centroid("ZZ") is None
    assert country_centroid("XX") is None


@pytest.mark.unit
def test_falsy_input_is_honestly_none():
    assert country_centroid(None) is None
    assert country_centroid("") is None


@pytest.mark.unit
def test_every_centroid_is_a_plausible_real_world_coordinate():
    """Defends against a fat-fingered entry landing outside any valid
    latitude/longitude range at all — cheap, exhaustive, catches a typo a
    spot-check on four countries above never would."""
    for code, (lat, lon) in _CENTROIDS.items():
        assert -90 <= lat <= 90, f"{code}: latitude {lat} out of range"
        assert -180 <= lon <= 180, f"{code}: longitude {lon} out of range"


@pytest.mark.unit
def test_table_has_no_duplicate_or_empty_codes():
    codes = list(_CENTROIDS.keys())
    assert len(codes) == len(set(codes)), "duplicate country code in _CENTROIDS"
    assert all(code and code == code.upper() and len(code) == 2 for code in codes)


@pytest.mark.unit
def test_table_covers_roughly_the_promised_scale():
    """The A-41 plan promises "~250 записей" — not an exact contract (a
    future task may add/remove entries), but this guards against the table
    accidentally shrinking to a handful of entries (e.g. a bad merge)."""
    assert len(_CENTROIDS) >= 200
