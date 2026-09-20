"""A-41: a static ISO 3166-1 alpha-2 country-code -> geographic centroid
(latitude, longitude, decimal degrees) lookup table, feeding the `network`
console's new visual connections map (see `security_console.py`'s
`_enrich_connections`, `app.js`'s canvas map renderer).

## Why this file exists at all (and why it is deliberately NOT geoip.py)

`geoip.py` (A-40) answers a completely different question — "which country
is THIS SPECIFIC IP ADDRESS in" — from a real, licensed, periodically
rebuilt third-party dataset (`sapics/ip-location-db`'s `user-country`,
PDDL-licensed, vendored at build time — see that module's own extensive
licence-research docstring). This file answers a much smaller, static
question — "roughly where IS a given country, as one point on a map" — and
the answer never changes at runtime and never needs re-vendoring, so it is
just a plain Python dict, not a connector with its own `is_configured()`/
`resolve_*()`/vendoring story.

## Licence note (CLAUDE.md's gate, applied — briefly, because there is
## genuinely little to research here, unlike geoip.py's case)

A country's approximate centroid coordinate is a bare geographic fact (like
"Paris is at roughly 48.85°N, 2.35°E") — this is the same category of
"objective fact, not a creative work" the A-41 task brief itself already
identifies, and it is NOT the same question geoip.py's licence research
answered (that was about a specific compiled, redistributed IP-RANGE
DATASET with its own publisher and licence terms). There is no single
"the" centroid for a country shaped source-of-truth to license here — every
public atlas, GIS textbook, and country-centroid CSV mirrored across dozens
of open GitHub repos publishes numbers that agree to within a degree or two
of each other for the same reason two independent measurements of a
mountain's height agree: they are measuring the same real thing. The values
below were written directly from general geographic knowledge (not copied
from any single named dataset file), rounded to 1-2 decimal places — plenty
of precision for "which quarter of the world is this dot in" at map-canvas
scale (a few dozen pixels wide), nowhere near the precision this file would
need if it were claiming to pinpoint a specific city or address (it is not
— see `app.js`'s map renderer docstring for the same "honestly approximate,
not survey-grade" framing already used for A-40's own IP->country accuracy
trade-off).

## What "centroid" means for an oddly-shaped or scattered country

For a geographically compact country this is close to its literal
geometric centre. For an elongated, archipelagic, or otherwise scattered
country (Indonesia, Kiribati, French Polynesia, the US Minor Outlying
Islands...) there is no single point that is "in" the country at all in
the way Paris is in France — every choice here is a deliberate compromise
picking a point that reads as "roughly this part of the world" on a
low-resolution world map, exactly the level of honesty this map component
promises (see the A-41 plan's "координатная сетка вместо контуров
континентов" framing: this whole feature is explicitly NOT trying to be
survey-grade).

## Deliberately never (0.0, 0.0) for "unknown"

`country_centroid()` returns `None`, never a fabricated `(0.0, 0.0)`, for
any code not in this table — `(0, 0)` is a real point in the Gulf of Guinea
off the coast of Ghana, and silently mapping an unrecognised code there
would fabricate a specific, wrong location rather than honestly saying "no
centroid known for this code" (same "never fabricate a specific answer out
of an absence of data" rule `resolve_country()`/`_CountryRangeTable.lookup`
already apply in geoip.py, and the same reasoning the A-41 plan itself
calls out explicitly).

## Coverage

Every ISO 3166-1 alpha-2 code currently in normal use (bare countries plus
the inhabited/administered dependent territories that show up as their own
country codes in real IP-allocation data, e.g. `HK`/`TW`/`PR`/`GU` — the
same "real codes `resolve_country()` can actually return" set A-40's own
geoip data draws from), plus `XK` (Kosovo) — not a formally reserved ISO
code, but the ad-hoc code essentially every IP-geolocation dataset in
practice emits for it, including this project's own vendored
`sapics/ip-location-db` data (confirmed by inspecting a real `user-country`
release while building this task) — so leaving it out would silently drop
real Kosovo-resolved connections off the map. A handful of uninhabited/
research-station-only territories (Antarctica, Bouvet Island, Heard Island,
the French Southern Territories...) are included too, for the same
"`resolve_country()` COULD in principle return this code, never crash the
map when it does" completeness reason — not because real user connections
are expected to originate there often, if ever.
"""

from __future__ import annotations

# (latitude, longitude) in decimal degrees, positive = North/East.
_CENTROIDS: dict[str, tuple[float, float]] = {
    # --- Europe ---
    "AD": (42.55, 1.58), "AL": (41.15, 20.17), "AT": (47.59, 14.13),
    "AX": (60.18, 20.0), "BA": (43.92, 17.68), "BE": (50.64, 4.67),
    "BG": (42.73, 25.49), "BY": (53.71, 27.95), "CH": (46.82, 8.23),
    "CY": (35.13, 33.43), "CZ": (49.82, 15.47), "DE": (51.17, 10.45),
    "DK": (56.26, 9.5), "EE": (58.6, 25.01), "ES": (40.46, -3.75),
    "FI": (61.92, 25.75), "FO": (61.89, -6.91), "FR": (46.6, 2.21),
    "GB": (55.38, -3.44), "GG": (49.47, -2.58), "GI": (36.14, -5.35),
    "GR": (39.07, 21.82), "HR": (45.1, 15.2), "HU": (47.16, 19.5),
    "IE": (53.41, -8.24), "IM": (54.24, -4.55), "IS": (64.96, -19.02),
    "IT": (41.87, 12.57), "JE": (49.21, -2.13), "LI": (47.17, 9.56),
    "LT": (55.17, 23.88), "LU": (49.82, 6.13), "LV": (56.88, 24.6),
    "MC": (43.75, 7.41), "MD": (47.41, 28.37), "ME": (42.71, 19.37),
    "MK": (41.61, 21.75), "MT": (35.94, 14.38), "NL": (52.13, 5.29),
    "NO": (60.47, 8.47), "PL": (51.92, 19.15), "PT": (39.4, -8.22),
    "RO": (45.94, 24.97), "RS": (44.02, 21.01), "RU": (61.52, 105.32),
    "SE": (60.13, 18.64), "SI": (46.15, 14.99), "SJ": (77.55, 23.7),
    "SK": (48.67, 19.7), "SM": (43.94, 12.46), "UA": (48.38, 31.17),
    "VA": (41.9, 12.45), "XK": (42.6, 20.9),
    # --- North America ---
    "AG": (17.06, -61.8), "AI": (18.22, -63.07), "AW": (12.52, -69.97),
    "BB": (13.19, -59.54), "BL": (17.9, -62.83), "BM": (32.32, -64.75),
    "BQ": (12.18, -68.25), "BS": (25.03, -77.4), "BZ": (17.19, -88.5),
    "CA": (56.13, -106.35), "CR": (9.75, -83.75), "CU": (21.52, -77.78),
    "CW": (12.17, -68.99), "DM": (15.41, -61.37), "DO": (18.74, -70.16),
    "GD": (12.26, -61.6), "GL": (71.71, -42.6), "GP": (16.27, -61.55),
    "GT": (15.78, -90.23), "HN": (15.2, -86.24), "HT": (18.97, -72.29),
    "JM": (18.11, -77.3), "KN": (17.36, -62.78), "KY": (19.51, -80.57),
    "LC": (13.91, -60.98), "MF": (18.08, -63.05), "MQ": (14.64, -61.02),
    "MS": (16.74, -62.19), "MX": (23.63, -102.55), "NI": (12.87, -85.21),
    "PA": (8.54, -80.78), "PM": (46.94, -56.27), "PR": (18.22, -66.59),
    "SV": (13.79, -88.9), "SX": (18.03, -63.05), "TC": (21.69, -71.8),
    "TT": (10.69, -61.22), "US": (37.09, -95.71), "VC": (12.98, -61.29),
    "VG": (18.42, -64.64), "VI": (18.34, -64.9),
    # --- South America ---
    "AR": (-38.42, -63.62), "BO": (-16.29, -63.59), "BR": (-14.24, -51.93),
    "CL": (-35.68, -71.54), "CO": (4.57, -74.3), "EC": (-1.83, -78.18),
    "FK": (-51.8, -59.5), "GF": (4.0, -53.08), "GY": (4.86, -58.93),
    "PE": (-9.19, -75.02), "PY": (-23.44, -58.44), "SR": (3.92, -56.03),
    "UY": (-32.52, -55.77), "VE": (6.42, -66.59),
    # --- Africa ---
    "AO": (-11.2, 17.87), "BF": (12.24, -1.56), "BI": (-3.37, 29.92),
    "BJ": (9.31, 2.32), "BW": (-22.33, 24.68), "CD": (-4.04, 21.76),
    "CF": (6.61, 20.94), "CG": (-0.23, 15.83), "CI": (7.54, -5.55),
    "CM": (7.37, 12.35), "CV": (16.0, -24.01), "DJ": (11.83, 42.59),
    "DZ": (28.03, 1.66), "EG": (26.82, 30.8), "EH": (24.22, -12.89),
    "ER": (15.18, 39.78), "ET": (9.15, 40.49), "GA": (-0.8, 11.61),
    "GH": (7.95, -1.02), "GM": (13.44, -15.31), "GN": (9.95, -9.7),
    "GQ": (1.65, 10.27), "GW": (11.8, -15.18), "KE": (-0.02, 37.91),
    "KM": (-11.88, 43.87), "LR": (6.43, -9.43), "LS": (-29.61, 28.23),
    "LY": (26.34, 17.23), "MA": (31.79, -7.09), "MG": (-18.77, 46.87),
    "ML": (17.57, -4.0), "MR": (21.0, -10.94), "MU": (-20.35, 57.55),
    "MW": (-13.25, 34.3), "MZ": (-18.67, 35.53), "NA": (-22.96, 18.49),
    "NE": (17.61, 8.08), "NG": (9.08, 8.68), "RW": (-1.94, 29.87),
    "SC": (-4.68, 55.49), "SD": (12.86, 30.22), "SH": (-15.97, -5.7),
    "SL": (8.46, -11.78), "SN": (14.5, -14.45), "SO": (5.15, 46.2),
    "SS": (6.88, 31.31), "ST": (0.19, 6.61), "SZ": (-26.52, 31.47),
    "TD": (15.45, 18.73), "TG": (8.62, 0.82), "TN": (33.89, 9.54),
    "TZ": (-6.37, 34.89), "UG": (1.37, 32.29), "YT": (-12.83, 45.17),
    "ZA": (-30.56, 22.94), "ZM": (-13.13, 27.85), "ZW": (-19.02, 29.15),
    # --- Middle East ---
    "AE": (23.42, 53.85), "BH": (26.07, 50.56), "IL": (31.05, 34.85),
    "IQ": (33.22, 43.68), "IR": (32.43, 53.69), "JO": (30.59, 36.24),
    "KW": (29.31, 47.48), "LB": (33.85, 35.86), "OM": (21.47, 55.98),
    "PS": (31.95, 35.2), "QA": (25.35, 51.18), "SA": (23.89, 45.08),
    "SY": (34.8, 39.0), "TR": (38.96, 35.24), "YE": (15.55, 48.52),
    # --- Central & South Asia ---
    "AF": (33.94, 67.71), "BD": (23.68, 90.36), "BT": (27.51, 90.43),
    "IN": (20.59, 78.96), "KG": (41.2, 74.77), "KZ": (48.02, 66.92),
    "LK": (7.87, 80.77), "MV": (3.2, 73.22), "NP": (28.39, 84.12),
    "PK": (30.38, 69.35), "TJ": (38.86, 71.28), "TM": (38.97, 59.56),
    "UZ": (41.38, 64.59),
    # --- East & Southeast Asia ---
    "BN": (4.54, 114.73), "CN": (35.86, 104.2), "HK": (22.32, 114.17),
    "ID": (-0.79, 113.92), "JP": (36.2, 138.25), "KH": (12.57, 104.99),
    "KP": (40.34, 127.51), "KR": (35.91, 127.77), "LA": (19.86, 102.5),
    "MM": (21.91, 95.96), "MN": (46.86, 103.85), "MO": (22.2, 113.55),
    "MY": (4.21, 101.98), "PH": (12.88, 121.77), "SG": (1.35, 103.82),
    "TH": (15.87, 100.99), "TL": (-8.87, 125.73), "TW": (23.7, 121.0),
    "VN": (14.06, 108.28),
    # --- Oceania & Pacific ---
    "AS": (-14.27, -170.13), "AU": (-25.27, 133.78), "CK": (-21.24, -159.78),
    "FJ": (-17.71, 178.07), "FM": (7.43, 150.55), "GU": (13.44, 144.79),
    "KI": (1.87, -157.36), "MH": (7.13, 171.18), "MP": (17.33, 145.38),
    "NC": (-20.9, 165.62), "NF": (-29.03, 167.95), "NR": (-0.52, 166.93),
    "NU": (-19.05, -169.87), "NZ": (-40.9, 174.89), "PF": (-17.68, -149.41),
    "PG": (-6.31, 143.96), "PN": (-24.7, -127.44), "PW": (7.51, 134.58),
    "SB": (-9.65, 160.16), "TK": (-8.97, -171.86), "TO": (-21.18, -175.2),
    "TV": (-7.11, 177.65), "UM": (19.28, 166.65), "VU": (-15.38, 166.96),
    "WF": (-13.77, -177.16), "WS": (-13.76, -172.1),
    # --- Indian Ocean / Southern Ocean territories ---
    "AQ": (-80.0, 0.0), "BV": (-54.43, 3.38), "CC": (-12.19, 96.87),
    "CX": (-10.45, 105.68), "GS": (-54.43, -36.59), "HM": (-53.08, 73.5),
    "IO": (-6.34, 71.88), "RE": (-21.12, 55.54), "TF": (-49.28, 69.35),
    "AM": (40.07, 45.04), "AZ": (40.14, 47.58), "GE": (42.32, 43.36),
}


def country_centroid(code: str | None) -> tuple[float, float] | None:
    """`code` (an ISO 3166-1 alpha-2 country code, e.g. `resolve_country()`'s
    return value in geoip.py) -> its (latitude, longitude) centroid in
    decimal degrees, or `None` when `code` is falsy or simply not present in
    `_CENTROIDS` — an honest miss (an unrecognised/newly-assigned code this
    table has not been updated for yet), never a fabricated `(0.0, 0.0)`
    (see this module's own docstring for why that specific fallback would be
    a fabrication, not a safe default: it is a real point in the Gulf of
    Guinea).

    Case-insensitive and whitespace-tolerant on purpose, mirroring
    `resolve_country()`'s own `.strip().upper()` normalisation in geoip.py —
    this function is meant to compose directly onto that one's output
    without either caller needing its own defensive normalisation first.
    """
    if not code:
        return None
    return _CENTROIDS.get(code.strip().upper())
