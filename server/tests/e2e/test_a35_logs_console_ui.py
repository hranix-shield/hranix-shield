"""A-35: real-browser regression coverage for the «Журналы ОС» console's new
UI (see docs/инструкция-разработка-фаза-0-понятность-панели-2026-07-19.md's
"A-35" section). This task is deliberately frontend-only (no backend
change — the `entries` shape it consumes was already pinned by A-16's own
unit tests, see tests/unit/test_wazuh_logs_console_data.py), so the most
meaningful automated check is exercising the REAL shipped
`app/static/{index.html,assets/app.js,assets/styles.css}` in an actual
browser, not a hand-rolled reimplementation of the rendering logic.

Loads `index.html` directly off disk via a `file://` URL — no server, no
login, no network needed: this test only cares about pure client-side
rendering (`renderConsole`/`renderConsoleList`), so it injects a fixture
`lastConsoleData` the same shape `GET /security/consoles/logs` returns
(see routers/security_console.py's `_logs_payload`) via `page.evaluate()`
and calls `renderConsole()` directly, then reads the resulting DOM back.
`page.evaluate()` is fine here for feeding in fixture data — the project's
"real `page.click()`, not `page.evaluate()`" rule (see the instruction
doc's opening rules) is about the separate MANDATORY manual live-server
Playwright verification with a real login and a real click on a real
button, done once by hand for the task's report, not about every
automated test's setup step.

Self-skips (like the `*_live` markers in pytest.ini) when Playwright's
Chromium isn't installed on this machine, so a plain `pytest -q` run on a
box that never ran `playwright install` still passes — same "no Docker/
no optional live dependency needed for the base suite" convention already
used for wazuh_live/clamav_live/osquery_live/crowdsec_live.
"""

from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[2]
INDEX_HTML = SERVER_DIR / "app" / "static" / "index.html"

_LONG_PATH = "/Users/tester/Library/Application Support/Hranix Shield/data/assistant.db"
_SHORT_PATH = "/usr/sbin/zic"

_FIXTURE_LOGS_DATA = {
    "id": "logs",
    "status": "ok",
    "enabled": True,
    "engine": ["wazuh_agent", "windows_event_log", "macos_unified_log"],
    "connector": {"status": "ok"},
    "metrics": {
        "events_24h": 3,
        "warnings_24h": None,
        "security_errors_24h": None,
        "sources": 1,
    },
    "chart": {"metric": "events_24h_7d", "unit": "count", "values": []},
    "entries": [
        {
            "timestamp": "2026-07-18T10:00:00+00:00",
            "level": "notice",
            "source": "wazuh_fim",
            "file": _SHORT_PATH,
            "description": f"Изменение файла под контролем целостности: {_SHORT_PATH}",
        },
        {
            "timestamp": "2026-07-18T11:00:00+00:00",
            "level": "warning",
            "source": "wazuh_fim",
            "file": _LONG_PATH,
            "description": f"Изменение файла под контролем целостности: {_LONG_PATH}",
        },
        {
            "timestamp": "2026-07-18T12:00:00+00:00",
            "level": "critical",
            "source": "wazuh_fim",
            "file": "/etc/passwd",
            "description": "Изменение файла под контролем целостности: /etc/passwd",
        },
        {
            # A future/unseen FIM level this project has never emitted live
            # (today only "notice" occurs in practice, see wazuh.py's
            # `_finding_to_entry`) — pins that the mapping degrades to the
            # neutral tone instead of crashing/rendering blank, per the
            # task brief's "сделай маппинг расширяемым" requirement.
            "timestamp": "2026-07-18T13:00:00+00:00",
            "level": "some_future_level",
            "source": "wazuh_fim",
            "file": "/tmp/whatever",
            "description": "Изменение файла под контролем целостности: /tmp/whatever",
        },
    ],
    "settings": {
        "os_event_log": True,
        "audit_logins_privilege": True,
        "wazuh_crowdsec_events": True,
        "sysmon": False,
        "retention_days": 90,
    },
}

_RENDER_LOGS_JS = """(fixture) => {
    window.lastConsoleId = 'logs';
    window.lastConsoleData = fixture;
    renderConsole();
}"""

_READ_LOGS_UI_JS = """() => {
    var hint = document.getElementById('conListHint');
    var rows = Array.from(document.querySelectorAll('#conList .con-row')).map(function(row){
        var lvl = row.querySelector('.log-lvl');
        var dot = row.querySelector('.log-lvl-dot');
        var file = row.querySelector('.log-file');
        var desc = row.querySelector('.log-desc');
        return {
            levelClassName: lvl ? lvl.className : null,
            levelTitle: lvl ? lvl.title : null,
            levelText: lvl ? lvl.textContent : null,
            dotPresent: !!dot,
            fileText: file ? file.textContent : null,
            fileTitle: file ? file.title : null,
            desc: desc ? desc.textContent : null,
        };
    });
    return {
        hintHidden: hint.hidden,
        hintText: hint.textContent,
        rows: rows,
    };
}"""


def _launch_chromium(playwright_module):
    try:
        return playwright_module.chromium.launch()
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Playwright Chromium not available on this machine: {exc}")


@pytest.mark.e2e
def test_logs_console_shows_hint_colored_levels_and_truncated_paths():
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(_RENDER_LOGS_JS, _FIXTURE_LOGS_DATA)
            ui = page.evaluate(_READ_LOGS_UI_JS)
        finally:
            browser.close()

    # 1) A-35 item 1: the static explainer text is visible above the list —
    # not the empty/hidden state every other console without a `listHint`
    # gets (see the second test below).
    assert ui["hintHidden"] is False
    assert "отслеживает изменения важных файлов" in ui["hintText"]

    assert len(ui["rows"]) == 4
    notice_row, warning_row, critical_row, unknown_row = ui["rows"]

    # 2) A-35 item 2: a colored dot indicator per row, never the bare
    # backend keyword ("notice"/"warning"/"critical"/whatever unseen value)
    # printed as-is — each row's level text is a translated label, and the
    # tone class maps the way the task brief specifies.
    assert notice_row["dotPresent"] is True
    assert "log-lvl-neutral" in notice_row["levelClassName"]
    assert notice_row["levelText"] != "notice"  # localized, not the raw keyword

    assert warning_row["dotPresent"] is True
    assert "log-lvl-warn" in warning_row["levelClassName"]
    assert warning_row["levelText"] != "warning"

    assert critical_row["dotPresent"] is True
    assert "log-lvl-crit" in critical_row["levelClassName"]

    # Extensibility: a level this project has never actually emitted still
    # renders (neutral tone, its own text shown verbatim as the honest
    # fallback) instead of throwing or leaving the cell blank.
    assert unknown_row["dotPresent"] is True
    assert "log-lvl-neutral" in unknown_row["levelClassName"]
    assert unknown_row["levelText"] == "some_future_level"

    # 3) A-35 item 3: long paths are truncated for display, with the full
    # untouched path preserved in `title` (same pattern as A-26's
    # `canvas.title`) — short paths pass through unshortened.
    assert notice_row["fileText"] == _SHORT_PATH  # short enough, unchanged
    assert notice_row["fileTitle"] == _SHORT_PATH

    assert warning_row["fileText"] != _LONG_PATH
    assert len(warning_row["fileText"]) < len(_LONG_PATH)
    assert warning_row["fileTitle"] == _LONG_PATH  # full path preserved on hover
    assert warning_row["fileText"].endswith("assistant.db")


@pytest.mark.e2e
def test_hint_box_stays_hidden_for_a_console_without_a_listhint():
    """Guards against the hint bleeding into consoles that never asked for
    one (see CONSOLE_META in app.js — today only `logs` sets `listHint`)."""
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    fixture = {
        "id": "ids",
        "status": "ok",
        "enabled": True,
        "engine": ["crowdsec"],
        "connector": {"status": "ok"},
        "metrics": {
            "banned_24h": 0,
            "active_bans_community": 0,
            "active_bans_local": 0,
            "scenarios": 0,
            "last_event_at": None,
        },
        "chart": {"metric": "active_bans_7d", "unit": "count", "values": []},
        "recent_attempts": [],
        "allowlist": {"connector": {"status": "not_configured"}, "items": []},
        "settings": {
            "ban_policy": "per_scenario",
            "rule_source": "community",
        },
    }

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(
                """(fixture) => {
                    window.lastConsoleId = 'ids';
                    window.lastConsoleData = fixture;
                    renderConsole();
                }""",
                fixture,
            )
            hint_hidden = page.evaluate("() => document.getElementById('conListHint').hidden")
        finally:
            browser.close()

    assert hint_hidden is True
