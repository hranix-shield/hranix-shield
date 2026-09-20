"""A-44: real-browser regression coverage for the «Обнаружение вторжений»
console's new «Белый список» write UI (inline add-form + per-row
«Удалить» button) — same "load the REAL shipped index.html/app.js off
disk via file://, inject a fixture, call renderConsole(), read the DOM
back" technique test_a35_logs_console_ui.py already established for A-35.
No server, no login, no network, no elevated docker exec/Touch ID prompt
needed — this test only cares about pure client-side rendering
(renderConsole/renderIdsAllowlist), which is exactly what a hand-rolled
reimplementation of the rendering logic could not actually prove.

Self-skips (like test_a35's own) when Playwright's Chromium isn't
installed, so a plain `pytest -q` run needs no extra setup.
"""

from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[2]
INDEX_HTML = SERVER_DIR / "app" / "static" / "index.html"

# Same overall shape routers/security_console.py's `_ids_payload` actually
# returns (see that function's own docstring) — two real allowlist items,
# one permanent ("бессрочно"/no expiry — A-42's Go-zero-time normalisation
# already turned that into a real `None`) and one with a real expiration,
# so the delete button's own wiring is exercised on more than one row.
_FIXTURE_IDS_DATA = {
    "id": "ids",
    "status": "ok",
    "enabled": True,
    "engine": ["crowdsec"],
    "connector": {"status": "ok"},
    "metrics": {
        "active_bans": 0,
        "active_bans_local": 0,
        "active_bans_community": 0,
        "banned_24h": None,
        "scenarios": 0,
        "last_event_at": None,
    },
    "chart": {"metric": "active_bans_local_7d", "unit": "count", "values": []},
    "recent_attempts": [],
    "allowlist": {
        "connector": {"status": "ok"},
        "items": [
            {
                "allowlist_name": "hranix_manual",
                "value": "203.0.113.5",
                "comment": "A-44 e2e fixture — permanent entry",
                "expiration": None,
                "created_at": "2026-07-25T08:00:00Z",
            },
            {
                "allowlist_name": "hranix_manual",
                "value": "203.0.113.0/24",
                "comment": "A-44 e2e fixture — with expiration",
                "expiration": "2027-01-01T00:00:00Z",
                "created_at": "2026-07-25T08:00:00Z",
            },
        ],
    },
    "settings": {
        "ban_policy": "per_scenario",
        "rule_source": "crowdsec_hub",
    },
}

_RENDER_IDS_JS = """(fixture) => {
    window.lastConsoleId = 'ids';
    window.lastConsoleData = fixture;
    renderConsole();
}"""

_READ_ALLOWLIST_UI_JS = """() => {
    var section = document.getElementById('idsAllowlistSection');
    var valueInput = document.getElementById('idsAllowlistValueInput');
    var commentInput = document.getElementById('idsAllowlistCommentInput');
    var addBtn = document.getElementById('idsAllowlistAddBtn');
    var rows = Array.from(document.querySelectorAll('#idsAllowlistList .con-row')).map(function(row){
        var removeBtn = row.querySelector('button');
        return {
            text: row.textContent,
            removeBtnText: removeBtn ? removeBtn.textContent : null,
            removeBtnDisabled: removeBtn ? removeBtn.disabled : null,
        };
    });
    return {
        sectionHidden: section ? section.hidden : null,
        valuePlaceholder: valueInput ? valueInput.placeholder : null,
        commentPlaceholder: commentInput ? commentInput.placeholder : null,
        addBtnText: addBtn ? addBtn.textContent : null,
        addBtnOnclickPresent: addBtn ? typeof addBtn.onclick === 'function' || addBtn.hasAttribute('onclick') : null,
        rowCount: rows.length,
        rows: rows,
    };
}"""


def _launch_chromium(playwright_module):
    try:
        return playwright_module.chromium.launch()
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Playwright Chromium not available on this machine: {exc}")


@pytest.mark.e2e
def test_ids_allowlist_section_shows_inline_add_form_and_per_row_delete_buttons():
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(_RENDER_IDS_JS, _FIXTURE_IDS_DATA)
            ui = page.evaluate(_READ_ALLOWLIST_UI_JS)
        finally:
            browser.close()

    assert ui["sectionHidden"] is False
    # Real, non-empty RU placeholders (applyLang() already ran on page
    # load) — proves the inline add-form is genuinely wired to
    # data-ru-ph/data-en-ph, not just present in the markup unstyled.
    assert ui["valuePlaceholder"]
    assert "IP" in ui["valuePlaceholder"] or "CIDR" in ui["valuePlaceholder"]
    assert ui["commentPlaceholder"]
    assert ui["addBtnText"].strip() == "Добавить в белый список"

    assert ui["rowCount"] == 2
    for row in ui["rows"]:
        assert row["removeBtnText"] == "Удалить"
        assert row["removeBtnDisabled"] is False
    assert "203.0.113.5" in ui["rows"][0]["text"]
    assert "A-44 e2e fixture — permanent entry" in ui["rows"][0]["text"]
    assert "203.0.113.0/24" in ui["rows"][1]["text"]


@pytest.mark.e2e
def test_ids_allowlist_add_form_hidden_field_state_survives_lang_switch():
    """A-44's own inline form must keep working after the existing RU<->EN
    toggle (app.js's applyLang, e.g. the header's own language-switch
    button calling `applyLang(currentLang() === 'ru' ? 'en' : 'ru')`) —
    same defensive check test_a35's own file could have added; guards
    against a future edit to applyLang() accidentally clobbering
    `[data-ru-ph]` handling for the two new inputs."""
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(_RENDER_IDS_JS, _FIXTURE_IDS_DATA)
            page.evaluate("() => { applyLang('en'); renderConsole(); }")
            ui = page.evaluate(_READ_ALLOWLIST_UI_JS)
        finally:
            browser.close()

    assert ui["addBtnText"].strip() == "Add to allowlist"
    assert "IP" in ui["valuePlaceholder"] or "CIDR" in ui["valuePlaceholder"]
    for row in ui["rows"]:
        assert row["removeBtnText"] == "Remove"
