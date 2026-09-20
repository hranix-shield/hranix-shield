"""A-45: real-browser regression coverage for the «Обнаружение вторжений»
console's new «Обновления сценариев» section («Проверить обновления» →
«Применить обновления») — same "load the REAL shipped index.html/app.js off
disk via file://, inject fixture globals, call renderConsole(), read the DOM
back" technique test_a44_ids_allowlist_write_ui.py already established for
A-44. No server, no login, no network, no elevated docker exec/Touch ID
prompt needed — this test only cares about pure client-side rendering
(renderConsole/renderScenarioUpdatesSection), which is exactly what a
hand-rolled reimplementation of the rendering logic could not actually
prove.

Self-skips (like test_a44's own) when Playwright's Chromium isn't installed,
so a plain `pytest -q` run needs no extra setup.
"""

from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[2]
INDEX_HTML = SERVER_DIR / "app" / "static" / "index.html"

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
    "allowlist": {"connector": {"status": "ok"}, "items": []},
    "settings": {"ban_policy": "per_scenario", "rule_source": "crowdsec_hub"},
}

# Real live-container plan text (see crowdsec.py's "A-45 addendum" docstring
# section) — with a genuine version-bump queued.
_REAL_PLAN_WITH_UPGRADES = (
    "Action plan:\n"
    "📥 download\n"
    " scenarios: crowdsecurity/ssh-time-based-bf (0.2 -> 0.3)\n"
    " postoverflows: crowdsecurity/rdns (0.3 -> 0.4)\n"
    "🔄 check & update data files\n"
    "\n"
    "Dry run, no action taken.\n"
)

_REAL_PLAN_ALREADY_CURRENT = (
    "Action plan:\n"
    "🔄 check & update data files\n"
    "\n"
    "Dry run, no action taken.\n"
)

_RENDER_IDS_JS = """(args) => {
    window.lastConsoleId = 'ids';
    window.lastConsoleData = args.fixture;
    window.idsScenarioUpdatesVisible = true;
    window.lastScenarioUpdatePlan = { plan: args.plan, has_upgrades: args.hasUpgrades };
    renderConsole();
}"""

_READ_SCENARIO_UPDATES_UI_JS = """() => {
    var section = document.getElementById('idsScenarioUpdatesSection');
    var note = document.getElementById('idsScenarioUpdatesNote');
    var applyBtn = document.getElementById('idsScenarioUpdatesApplyBtn');
    var rows = Array.from(document.querySelectorAll('#idsScenarioUpdatesList .con-row'))
        .map(function(row){ return row.textContent; });
    return {
        sectionHidden: section ? section.hidden : null,
        noteHidden: note ? note.hidden : null,
        noteText: note ? note.textContent : null,
        applyBtnHidden: applyBtn ? applyBtn.hidden : null,
        applyBtnText: applyBtn ? applyBtn.textContent : null,
        rows: rows,
    };
}"""


def _launch_chromium(playwright_module):
    try:
        return playwright_module.chromium.launch()
    except Exception as exc:  # pragma: no cover - environment-dependent
        pytest.skip(f"Playwright Chromium not available on this machine: {exc}")


@pytest.mark.e2e
def test_scenario_updates_section_shows_real_plan_and_apply_button_when_upgrades_exist():
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(
                _RENDER_IDS_JS,
                {"fixture": _FIXTURE_IDS_DATA, "plan": _REAL_PLAN_WITH_UPGRADES, "hasUpgrades": True},
            )
            ui = page.evaluate(_READ_SCENARIO_UPDATES_UI_JS)
        finally:
            browser.close()

    assert ui["sectionHidden"] is False
    # The raw plan text is shown line-by-line, verbatim (A-36's own "show
    # the real tool output" discipline) — never re-parsed/reformatted.
    assert any("ssh-time-based-bf (0.2 -> 0.3)" in row for row in ui["rows"])
    assert any("📥 download" in row for row in ui["rows"])
    # The apply button is visible AND real RU text — proves the honest
    # degradation is keyed off `has_upgrades`, not just section visibility.
    assert ui["applyBtnHidden"] is False
    assert ui["applyBtnText"].strip() == "Применить обновления"
    assert ui["noteHidden"] is False
    assert "актуальны" not in ui["noteText"]  # NOT the "already current" phrasing


@pytest.mark.e2e
def test_scenario_updates_section_hides_apply_button_when_plan_is_empty():
    """The DoD's own honest-degradation requirement: an empty/"already
    current" plan must NOT show the apply button at all — never a fake
    "nothing to update" button that does nothing when clicked."""
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(
                _RENDER_IDS_JS,
                {"fixture": _FIXTURE_IDS_DATA, "plan": _REAL_PLAN_ALREADY_CURRENT, "hasUpgrades": False},
            )
            ui = page.evaluate(_READ_SCENARIO_UPDATES_UI_JS)
        finally:
            browser.close()

    assert ui["sectionHidden"] is False
    assert ui["applyBtnHidden"] is True
    assert ui["noteHidden"] is False
    assert "актуальны" in ui["noteText"]


@pytest.mark.e2e
def test_scenario_updates_section_survives_lang_switch():
    """Same defensive check test_a44's own file added for its own new
    section — guards against a future edit to applyLang() accidentally
    clobbering this JS-built section (it is rebuilt via renderConsole(),
    not data-ru/data-en static markup, same as renderFirewallRulesList)."""
    sync_playwright = pytest.importorskip("playwright.sync_api").sync_playwright

    with sync_playwright() as p:
        browser = _launch_chromium(p)
        try:
            page = browser.new_page()
            page.goto(INDEX_HTML.as_uri())
            page.evaluate(
                _RENDER_IDS_JS,
                {"fixture": _FIXTURE_IDS_DATA, "plan": _REAL_PLAN_WITH_UPGRADES, "hasUpgrades": True},
            )
            page.evaluate("() => { applyLang('en'); }")
            ui = page.evaluate(_READ_SCENARIO_UPDATES_UI_JS)
        finally:
            browser.close()

    assert ui["applyBtnText"].strip() == "Apply updates"
    assert "up to date" not in ui["noteText"]
    assert any("ssh-time-based-bf (0.2 -> 0.3)" in row for row in ui["rows"])
