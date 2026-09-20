"""A-35 regression anchor.

Per docs/методология-поэтапной-разработки.md, every task adds at least one
regression test that must stay green through the rest of Phase 0. A-35 is
frontend-only (see docs/инструкция-разработка-фаза-0-понятность-панели-2026-07-19.md's
"A-35" section) — the `entries` backend contract it renders was already
pinned by A-16's own unit tests (tests/unit/test_wazuh_logs_console_data.py)
and is untouched here.

The real behavioural coverage for this task is
tests/e2e/test_a35_logs_console_ui.py (a real headless-browser render of the
actual shipped files) — but that test self-skips on a machine without
Playwright's Chromium installed (same convention as the `*_live` markers).
This anchor is the fallback that still catches an accidental revert/removal
of the three A-35 UI pieces even on a box where the e2e test can't run: a
plain static-text check needs no browser, no server, nothing to install.
"""

from pathlib import Path

import pytest

SERVER_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = SERVER_DIR / "app" / "static"
APP_JS = (STATIC_DIR / "assets" / "app.js").read_text(encoding="utf-8")
STYLES_CSS = (STATIC_DIR / "assets" / "styles.css").read_text(encoding="utf-8")
INDEX_HTML = (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@pytest.mark.unit
def test_logs_hint_element_and_meta_text_are_wired():
    """Item 1: a short static explainer above the FIM event list, RU/EN,
    same `{ru, en}` convention as every other console-text field."""
    assert 'id="conListHint"' in INDEX_HTML
    assert "listHint" in APP_JS
    assert "отслеживает изменения важных файлов" in APP_JS
    assert "watches for changes to important files" in APP_JS


@pytest.mark.unit
def test_log_level_indicator_mapping_is_extensible_not_a_raw_word():
    """Item 2: a lookup table (not a hardcoded 3-way if/else) mapping
    level -> {ru, en, tone}, covering notice/warning/error/critical plus an
    honest fallback for anything else — see describeLogLevel/LOG_LEVEL_META
    in app.js."""
    assert "LOG_LEVEL_META" in APP_JS
    assert "describeLogLevel" in APP_JS
    for level in ("notice", "warning", "error", "critical"):
        assert f"{level}:" in APP_JS or f'"{level}"' in APP_JS or f"'{level}'" in APP_JS
    # CSS: a colored dot, not just colored text — three distinct tones.
    assert ".log-lvl-dot" in STYLES_CSS
    assert ".log-lvl-neutral" in STYLES_CSS
    assert ".log-lvl-warn" in STYLES_CSS
    assert ".log-lvl-crit" in STYLES_CSS


@pytest.mark.unit
def test_long_file_paths_are_truncated_with_a_title_tooltip():
    """Item 3: same 'truncate + full value in `title`' pattern already
    established by drawBarChart's canvas.title (A-26), reused for FIM file
    paths via truncateFimPath()."""
    assert "function truncateFimPath" in APP_JS
    assert ".log-file" in STYLES_CSS
    # The row-building code must actually assign the untouched original
    # path to `.title`, not just truncate for display and drop the rest.
    assert "fileEl.title = item.file" in APP_JS
