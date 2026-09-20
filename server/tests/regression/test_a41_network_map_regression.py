"""A-41 regression anchor: the `network` console's connections map
(`app.js`'s `projectLatLon`/`groupConnectionsByCountry`/`drawConnectionsMap`,
`index.html`'s `#conMapCard`, `security_console.py`'s `_enrich_connections`
`lat`/`lon` fields, `country_centroids.py`).

Three independent guards, same spirit as
test_a34_network_table_regression.py's own two-halves split (a Python-side
backend-shape pin + a real-`app.js`-via-Node pin), plus a THIRD one specific
to this task's central promise:

  1. The pure projection function (`projectLatLon`) is exercised directly,
     via Node's `vm` module against the real, unmodified `app.js` — no
     canvas needed, "чистая математика, без canvas — легко тестируется
     напрямую" (the A-41 plan's own words).
  2. `groupConnectionsByCountry` — the "one dot per DISTINCT country, not
     per connection" dedup/aggregation logic — same Node harness technique.
  3. **A static privacy tripwire**: `app.js` must never contain a literal
     `http://`/`https://` URL at all (true of this file before A-41, see
     this test's own docstring below) — a real Leaflet/Mapbox/OSM tile
     integration would necessarily hardcode a tile-server URL template
     somewhere in the file, so this single grep is a cheap, always-on
     guard against that specific regression, independent of (not a
     replacement for) the task's own live Playwright network-interception
     verification (see the A-41 task report) which is the actual DoD-
     mandated proof for a REAL browser session.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

# tests/regression/test_a41_....py -> tests/regression -> tests -> server -> app/static/assets/app.js
_APP_JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "assets" / "app.js"


@pytest.mark.unit
def test_app_js_never_hardcodes_an_external_url():
    """The whole point of A-41 (see the plan's "Важное архитектурное
    решение"): no tile-server/CDN/mapping-library URL may ever be hardcoded
    into this file. Before A-41, `app.js` already contained zero `http://`/
    `https://` literals at all (confirmed while building this task) — this
    pins that invariant going forward specifically for the map feature, not
    just today's snapshot."""
    assert _APP_JS_PATH.is_file(), f"app.js not found at {_APP_JS_PATH}"
    source = _APP_JS_PATH.read_text(encoding="utf-8")
    assert "http://" not in source
    assert "https://" not in source
    # Belt-and-suspenders: actual DOMAIN-shaped strings (with their TLD) a
    # real map/tile integration would hardcode somewhere, even if someone
    # later rewrote a URL to avoid the scheme literal (e.g. string
    # concatenation) — deliberately domain-shaped (not just the bare product
    # name "Mapbox"/"Leaflet"/...), since this file's own explanatory
    # comments legitimately NAME those libraries in prose (e.g. this
    # module's own map-rendering docstring, explaining exactly why none of
    # them are used) without that being a real integration.
    for forbidden_host in (
        "openstreetmap.org", "mapbox.com", "googleapis.com",
        "google.com/maps", "maps.google.", "unpkg.com/leaflet", "leafletjs.com",
    ):
        assert forbidden_host not in source.lower()


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_project_lat_lon_matches_the_documented_equirectangular_formula():
    """Pins `projectLatLon`'s exact formula (the A-41 plan's own words:
    `x = (lon + 180) / 360 * width`, `y = (90 - lat) / 180 * height`) against
    a handful of landmark coordinates with an obvious expected pixel
    position on a 360x180 canvas (1 canvas pixel per degree, so expected
    values are trivial to hand-verify): (0, 0) (the centre of the map),
    (90, -180) (top-left corner), (-90, 180) (bottom-right corner)."""
    assert _APP_JS_PATH.is_file(), f"app.js not found at {_APP_JS_PATH}"

    harness = r"""
    const vm = require('vm');
    const fs = require('fs');
    const code = fs.readFileSync(process.argv[1], 'utf8');
    var context = { window: {}, document: { getElementById: function(){ return null; }, addEventListener: function(){} }, console: console };
    vm.createContext(context);
    vm.runInContext(code, context, { filename: 'app.js' });

    var cases = [
      [0, 0, 360, 180],
      [90, -180, 360, 180],
      [-90, 180, 360, 180],
      [0, -180, 360, 180],
      [0, 180, 360, 180],
      [90, 0, 360, 180],
      [-90, 0, 360, 180],
    ];
    var results = cases.map(function(c){ return context.projectLatLon(c[0], c[1], c[2], c[3]); });
    console.log(JSON.stringify(results));
    """
    result = subprocess.run(
        ["node", "-e", harness, str(_APP_JS_PATH)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    points = json.loads(result.stdout.strip().splitlines()[-1])

    # (lat=0, lon=0) -> dead centre of the canvas.
    assert points[0] == {"x": 180, "y": 90}
    # (lat=90, lon=-180) -> top-left corner (north pole, antimeridian west).
    assert points[1] == {"x": 0, "y": 0}
    # (lat=-90, lon=180) -> bottom-right corner (south pole, antimeridian east).
    assert points[2] == {"x": 360, "y": 180}
    # Equator at the antimeridian, both sides.
    assert points[3] == {"x": 0, "y": 90}
    assert points[4] == {"x": 360, "y": 90}
    # Poles at the prime meridian.
    assert points[5] == {"x": 180, "y": 0}
    assert points[6] == {"x": 180, "y": 180}


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_group_connections_by_country_dedupes_and_flags_suspicious_correctly():
    """Exercises the real `groupConnectionsByCountry` (not a Python
    reimplementation) against the exact "one dot per DISTINCT country, not
    per connection" + "any real True in the group marks the whole dot
    suspicious, a null never does" rules the A-41 plan calls for."""
    assert _APP_JS_PATH.is_file(), f"app.js not found at {_APP_JS_PATH}"

    connections = [
        {"country": "US", "lat": 37.09, "lon": -95.71, "is_suspicious": False},
        # Second US row — same country, must merge into ONE point with
        # count=2, not a second overlapping dot.
        {"country": "US", "lat": 37.09, "lon": -95.71, "is_suspicious": True},
        {"country": "DE", "lat": 51.16, "lon": 10.45, "is_suspicious": None},
        # No resolved country/coordinates at all — must be silently dropped,
        # not turned into a "?"-labelled point at (0, 0)/crash.
        {"country": None, "lat": None, "lon": None, "is_suspicious": False},
    ]

    harness = r"""
    const vm = require('vm');
    const fs = require('fs');
    const code = fs.readFileSync(process.argv[1], 'utf8');
    var context = { window: {}, document: { getElementById: function(){ return null; }, addEventListener: function(){} }, console: console };
    vm.createContext(context);
    vm.runInContext(code, context, { filename: 'app.js' });

    var connections = JSON.parse(process.argv[2]);
    var groups = context.groupConnectionsByCountry(connections);
    console.log(JSON.stringify(groups));
    """
    result = subprocess.run(
        ["node", "-e", harness, str(_APP_JS_PATH), json.dumps(connections)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    groups = json.loads(result.stdout.strip().splitlines()[-1])

    assert len(groups) == 2
    by_country = {g["country"]: g for g in groups}
    assert by_country["US"]["count"] == 2
    # A real True on EITHER of the two merged US rows marks the whole group.
    assert by_country["US"]["suspicious"] is True
    assert by_country["DE"]["count"] == 1
    # `is_suspicious: null` (CrowdSec not checked) must never flip this to
    # True — same three-state honesty the table itself already applies.
    assert by_country["DE"]["suspicious"] is False
