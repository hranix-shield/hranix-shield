"""A-34 regression anchor (A-40 extended it — see that section below).

A-34 is a pure-frontend task (only `server/app/static/assets/app.js`
changes — see docs/инструкция-разработка-фаза-0-понятность-панели-2026-07-19.md's
"A-34" section): `renderConsoleList` grew a dedicated `network` branch that
turns `connections` rows into a readable table (Процесс/PID, local/remote
address:port, human protocol name, state) instead of falling through to the
generic key:value dump.

The backend contract (`osquery.py`'s `fetch_network_console_data`,
`security_console.py`'s `_network_payload`) is untouched and already covered
by test_security_console_network_av.py/test_a15_osquery_regression.py — but
neither of those pins the *exact per-row field names* the new frontend
branch now reads. This anchor closes that gap: if a later task ever
renames/drops one of these fields, the new table silently breaks (wrong/
missing column) without any backend test failing — this file is the
tripwire.

A-40 added two MORE fields on top of the same rows (`country`, geoip.py;
`is_suspicious`, crowdsec.py — see `security_console.py`'s
`_enrich_connections`) and two more table columns reading them — this file
was updated in place (not superseded) to keep pinning the CURRENT full
contract, `_FAKE_RAW_CONNECTIONS` (what `fetch_network_console_data` itself
returns) now kept separate from `_FAKE_ENRICHED_CONNECTIONS` (what the
console's actual HTTP response — and the frontend table — sees after
`_network_payload`'s enrichment, with `fetch_active_decision_values`/
`resolve_country` mocked for determinism, same technique
test_security_console_network_av.py's own A-40 update uses).

The second half exercises the actual shipped `app.js` code (not a Python
reimplementation of its logic) via Node's `vm` module against a minimal fake
DOM, so a regression in the rendering branch itself — not just the backend
shape it consumes — is also caught without a live browser. Skips honestly
when `node` isn't on PATH, the same "self-skip when the tool isn't there"
convention already used by the `*_live` markers in pytest.ini.

A-39 update: two more fields (`bytes_sent`/`bytes_received`, joined in by
`security_console.py._network_payload` from
`services/mcp/security_connectors/traffic_counters.py`) and two more table
columns — both halves below updated to pin the new 10-field row shape/8-cell
rendered row, not just the original 8/5.

A-41 update: two MORE fields (`lat`/`lon`, `country_centroids.py`'s
`country_centroid()` applied to the already-resolved `country` — see
`security_console.py`'s `_enrich_connections`) feeding the new network
console map, not the table (`renderConsoleList` deliberately does not grow
an 11th/12th column for two raw numbers no human reads directly — the map
consumes them instead, see `app.js`'s new map-rendering function). Only the
backend-shape half of this file (`expected_keys`/`_FAKE_ENRICHED_CONNECTIONS`)
changes; the rendered-table assertions below are untouched on purpose.

A-52 update: one MORE field (`is_blocked` — `os_firewall.py`'s persisted
`blocked_ips` table cross-referenced against `remote_address`, see
`security_console.py`'s `_enrich_connections` own A-52 addendum) —
`expected_keys`/`_FAKE_ENRICHED_CONNECTIONS` updated again, same pattern.

A-51 update: the REAL bug this update fixes — 9 separate columns wrapped
onto a second line at typical window widths (see
docs/план-спецификация-фаза-0-сеть-доработка-2026-08-17.md). Local/remote
and sent/received are each now ONE merged, 2-line column apiece (9 → 7),
so the rendered-table assertions below ARE updated this time (unlike every
previous field-only update above) — a cell with a nested `.con-cell-stack`
renders as the CONCATENATION of its two stacked lines with no separator
(no different from how a real browser's own `Element.textContent`
behaves), so assertions on those two merged cells check substring
presence rather than exact equality; the fake DOM's own `textContent`
getter (`makeElement()` below) was also fixed to recurse into `children`
instead of only ever returning whatever was last directly assigned to a
LEAF node — the old naive version silently returned `''` for any cell
with nested children, which used to never happen before this task.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from tests.common.factories import create_user

# tests/regression/test_a34_....py -> tests/regression -> tests -> server -> app/static/assets/app.js
_APP_JS_PATH = Path(__file__).resolve().parents[2] / "app" / "static" / "assets" / "app.js"

_FAKE_RAW_CONNECTIONS = [
    {
        "process": "Notes",
        "pid": 1228,
        "local_address": "192.168.1.20",
        "local_port": 51000,
        "remote_address": "93.184.216.34",
        "remote_port": 443,
        "protocol": "6",
        "state": "ESTABLISHED",
    },
    {
        "process": "mDNSResponder",
        "pid": 210,
        "local_address": "0.0.0.0",
        "local_port": 5353,
        "remote_address": None,
        "remote_port": None,
        "protocol": "17",
        "state": None,
    },
    {
        "process": None,
        "pid": None,
        "local_address": "10.0.0.5",
        "local_port": 22,
        "remote_address": "10.0.0.9",
        "remote_port": 51234,
        "protocol": "132",
        "state": "LISTEN",
    },
]

# A-40: row 1's remote address ("93.184.216.34") resolves to a country and
# matches a mocked active CrowdSec decision (is_suspicious True) — row 2 has
# no remote address at all (country/suspicious both fall out honestly:
# `resolve_country(None)` is None, `ip_matches_any_decision(None, ...)` is
# False, not None — CrowdSec WAS actually checked here, a missing address
# just never matches, see crowdsec.py's own docstring) — row 3's remote
# address is checked and genuinely does not match.
# A-39: `by_pid` is mocked empty in this file's own integration test (see
# below) — every row's bytes_sent/bytes_received must honestly come back
# `None` since none of these pids have an entry.
# A-41: row 1's "US" gets its real centroid (country_centroids.py); rows 2/3
# have no resolved country, so `lat`/`lon` stay honestly `None`/`None` too.
_US_CENTROID = (37.09, -95.71)
# A-52: none of these three rows' remote addresses have a `blocked_ips` row
# in this test (no DB seeding here) — honestly `False` on all three, same
# "always locally known, never a three-state 'not checked'" reasoning
# `_enrich_connections`'s own A-52 addendum documents.
_FAKE_ENRICHED_CONNECTIONS = [
    {
        **_FAKE_RAW_CONNECTIONS[0], "bytes_sent": None, "bytes_received": None, "country": "US",
        "lat": _US_CENTROID[0], "lon": _US_CENTROID[1], "is_suspicious": True, "is_blocked": False,
    },
    {
        **_FAKE_RAW_CONNECTIONS[1], "bytes_sent": None, "bytes_received": None, "country": None,
        "lat": None, "lon": None, "is_suspicious": False, "is_blocked": False,
    },
    {
        **_FAKE_RAW_CONNECTIONS[2], "bytes_sent": None, "bytes_received": None, "country": None,
        "lat": None, "lon": None, "is_suspicious": False, "is_blocked": False,
    },
]
_FAKE_COUNTRY_BY_IP = {"93.184.216.34": "US"}
_FAKE_SUSPICIOUS_DECISION_VALUES = ["93.184.216.34"]


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
async def test_network_connections_carry_every_field_the_new_table_reads(
    client: TestClient,
    migrated_session_maker: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
):
    """Pins the exact per-row shape (see module docstring) — including the
    edge cases the new renderer must not crash on: a `None` `process`/`pid`
    (row 3), a `None` `remote_address`/`remote_port` (row 2, a
    listening-socket-shaped row), and a `protocol` value that is neither
    "6" nor "17" (row 3, "132") which the renderer must show as-is rather
    than fail on."""

    async def _fake_network_data():
        return {
            "connector": {"status": "ok"},
            "connections": _FAKE_RAW_CONNECTIONS,
            "listening_ports": [],
            "active_connections": len(_FAKE_RAW_CONNECTIONS),
        }

    # A-39: pinned to an empty `by_pid` (deterministic, no real nettop/ss
    # subprocess call in what is meant to be a fast, OS-independent shape
    # regression) — every row's new bytes_sent/bytes_received must honestly
    # come back `None` since none of _FAKE_RAW_CONNECTIONS' pids have an
    # entry.
    async def _fake_traffic_counters(registry):
        return {"connector": {"status": "ok"}, "by_pid": {}}

    async def _fake_decision_values():
        return {"connector": {"status": "ok"}, "values": _FAKE_SUSPICIOUS_DECISION_VALUES}

    def _fake_resolve_country(ip, **kwargs):
        return _FAKE_COUNTRY_BY_IP.get(ip)

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network_data)
    monkeypatch.setattr(security_console_module, "fetch_traffic_counters", _fake_traffic_counters)
    monkeypatch.setattr(security_console_module, "fetch_active_decision_values", _fake_decision_values)
    monkeypatch.setattr(security_console_module, "resolve_country", _fake_resolve_country)
    headers = await _admin_headers(client, migrated_session_maker, "a34_network_regress")

    response = client.get("/security/consoles/network", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["connections"] == _FAKE_ENRICHED_CONNECTIONS
    expected_keys = {
        "process", "pid", "local_address", "local_port",
        "remote_address", "remote_port", "protocol", "state",
        # A-39 (11б): joined in by security_console.py._network_payload, see
        # that function's own docstring.
        "bytes_sent", "bytes_received",
        # A-40: geoip.py/crowdsec.py reputation cross-reference.
        "country", "is_suspicious",
        # A-41: country_centroids.py, feeding the map (not the table).
        "lat", "lon",
        # A-52: os_firewall.py's persisted blocked_ips table cross-reference.
        "is_blocked",
    }
    for row in body["connections"]:
        assert set(row.keys()) == expected_keys


@pytest.mark.skipif(shutil.which("node") is None, reason="Node.js not installed on this machine")
def test_render_console_list_network_branch_produces_a_readable_table():
    """Runs the real `app.js` (unmodified, loaded from disk) in a Node `vm`
    context against a minimal fake DOM, and calls the actual
    `renderConsoleList` function with the same three edge-case rows the
    integration test above pins from the backend side (the fully-enriched
    shape — `_FAKE_ENRICHED_CONNECTIONS` — since that is exactly what the
    real endpoint hands the frontend). Asserts the rendered rows are the
    A-51 7-column table (local/remote and sent/received each merged into
    one 2-line column — see this file's own module docstring, "A-51
    update") — not the old generic key:value dump (which would render
    literal "process: ", "pid: ", ... label text inside each cell; the new
    branch never does that)."""
    assert _APP_JS_PATH.is_file(), f"app.js not found at {_APP_JS_PATH}"

    harness = r"""
    const vm = require('vm');
    const fs = require('fs');
    const code = fs.readFileSync(process.argv[1], 'utf8');

    function makeElement(){
      var el = {
        className: '',
        style: {},
        disabled: false,
        onclick: null,
        onkeydown: null,
        tabIndex: -1,
        type: '',
        children: [],
        appendChild: function(child){ el.children.push(child); return child; },
        // A-53: the network branch's rows are now clickable
        // (`.con-row-clickable` + `role="button"`, same pattern
        // `perimeter`'s ports rows already use) — needs a real
        // `setAttribute`, unlike the plain-property fields above.
        setAttribute: function(name, value){ el['_attr_' + name] = value; },
      };
      // A-51: a real DOM's textContent recurses into children (concatenating
      // every descendant text node, no separator) — the merged 2-line cells
      // this task introduced (app.js's `.con-cell-stack` nesting) rely on
      // exactly that. The old version of this fake only ever returned
      // whatever was last directly assigned via the setter, silently ''
      // for any element with nested children instead of leaves — never
      // exercised before this task added the first nested-element cells.
      Object.defineProperty(el, 'textContent', {
        get: function(){
          if(el.children.length === 0) return el._text || '';
          return el.children.map(function(c){ return c.textContent; }).join('');
        },
        set: function(v){ el._text = v; el.children = []; },
      });
      Object.defineProperty(el, 'innerHTML', {
        get: function(){ return ''; },
        set: function(){ el.children = []; },
      });
      return el;
    }

    var conList = makeElement();
    var context = {
      document: {
        createElement: function(){ return makeElement(); },
        createTextNode: function(text){ var n = makeElement(); n.textContent = String(text); return n; },
        getElementById: function(id){ return id === 'conList' ? conList : makeElement(); },
        addEventListener: function(){},
      },
      window: {},
      localStorage: { getItem: function(){ return null; }, setItem: function(){} },
      fetch: function(){},
      console: console,
    };
    vm.createContext(context);
    vm.runInContext(code, context, { filename: 'app.js' });

    context.lastConsoleId = 'network';
    var items = JSON.parse(process.argv[2]);
    context.renderConsoleList(items);

    function cellTexts(row){ return row.children.map(function(c){ return c.textContent; }); }
    var rendered = conList.children.map(cellTexts);
    console.log(JSON.stringify(rendered));
    """

    result = subprocess.run(
        ["node", "-e", harness, str(_APP_JS_PATH), json.dumps(_FAKE_ENRICHED_CONNECTIONS)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, f"node harness failed: {result.stderr}"
    rendered_rows = json.loads(result.stdout.strip().splitlines()[-1])

    # Row 0: header row (RU labels by default — currentLang() falls back to
    # 'ru' when localStorage has nothing, which the fake localStorage above
    # always reports). A-51: 7 cells now (was 9) — index 1 and index 5 are
    # the two merged 2-line headers; their rendered text is the
    # CONCATENATION of both lines (see this file's own module docstring,
    # "A-51 update", for why no separator — real `textContent` behaviour).
    assert len(rendered_rows[0]) == 7
    assert rendered_rows[0][0] == "Процесс"
    assert rendered_rows[0][1] == "Локальный/Удалённыйадрес:порт"
    assert rendered_rows[0][2] == "Страна"
    assert rendered_rows[0][3] == "Протокол"
    assert rendered_rows[0][4] == "Состояние"
    assert rendered_rows[0][5] == "Отправлено/ПолученоКбайт"
    assert rendered_rows[0][6] == "Репутация"
    assert len(rendered_rows) == 1 + len(_FAKE_ENRICHED_CONNECTIONS)

    # Row 1: "Notes" + pid, both endpoints (merged local/remote cell — «Л:»/
    # «У:» prefixes, see app.js's renderConsoleList network branch), a real
    # 🇺🇸 US flag (the standard "regional indicator" flag-emoji encoding of
    # "US" — see app.js's countryFlagEmoji), TCP mapped from "6", real
    # state, no bytes_sent/bytes_received (by_pid mocked empty —
    # formatBytesKb(null) degrades to the same honest dash on both merged
    # lines), and the red "Подозрительный узел" reputation badge
    # (is_suspicious True).
    row1 = rendered_rows[1]
    assert row1[0] == "Notes (1228)"
    assert "Л: 192.168.1.20:51000" in row1[1] and "У: 93.184.216.34:443" in row1[1]
    assert row1[2] == "\U0001F1FA\U0001F1F8 US"
    assert row1[3] == "TCP"
    assert row1[4] == "ESTABLISHED"
    assert "↑ —" in row1[5] and "↓ —" in row1[5]
    assert row1[6] == "⚠ Подозрительный узел"

    # Row 2: no remote side -> the merged cell's remote line is the honest
    # dash; no country resolved (honest —); UDP mapped from "17"; missing
    # state falls back to the dash; checked-but-not-matching reputation
    # (also —, not a badge).
    row2 = rendered_rows[2]
    assert row2[0] == "mDNSResponder (210)"
    assert "Л: 0.0.0.0:5353" in row2[1] and "У: —" in row2[1]
    assert row2[2] == "—"
    assert row2[3] == "UDP"
    assert row2[4] == "—"
    assert row2[6] == "—"

    # Row 3: missing process name -> the honest RU placeholder, no PID
    # suffix; no country; an unmapped protocol ("132") is shown as-is, not
    # swallowed; same honest "—" reputation as row 2.
    row3 = rendered_rows[3]
    assert row3[0] == "неизвестный процесс"
    assert "Л: 10.0.0.5:22" in row3[1] and "У: 10.0.0.9:51234" in row3[1]
    assert row3[2] == "—"
    assert row3[3] == "132"
    assert row3[4] == "LISTEN"
    assert row3[6] == "—"

    # None of the rows contain the old generic dump's "key: " label text —
    # confirms the network branch actually fired instead of falling through
    # to the generic fallback below it.
    flattened = " ".join(cell for row in rendered_rows for cell in row)
    for stale_label in ("process: ", "pid: ", "local_address: ", "protocol: "):
        assert stale_label not in flattened
