"""A-32 regression anchor.

Per docs/инструкция-разработка-фаза-0-понятность-панели-2026-07-19.md's A-32
section, this task is scoped to `server/app/static/assets/app.js` ONLY (no
`index.html`/`styles.css` changes) — the banner element (`#conIdsStatus`) is
therefore created dynamically at runtime by `renderConsole()`, styled with
inline styles that reference the same CSS custom properties (`--good-soft`/
`--good-t`/`--warn-soft`/`--warn-t`) every other status pill in the app
already reads, rather than added as static markup + new CSS classes. The
backend contract for `GET /security/consoles/ids` (`metrics.active_bans_local`,
`recent_attempts`) was already real and correct before this task (A-23) and
is not touched here.

There is no existing frontend/Playwright test suite in this repo (checked:
`server/tests/e2e/` only has `__init__.py`), so per the task brief this file
is the Python-side proof that the served JS this fix lives in is still
served correctly and actually contains the new honest-status-banner wiring —
NOT a substitute for the mandatory live Playwright screenshot (see the task
report), just the regression anchor that keeps this from silently regressing
in the plain `pytest` run every other task's anchor already lives in.

Pins:
  - `/panel/assets/app.js` still serves the script, and it now contains:
      * the `conIdsStatus` element creation + wiring in `renderConsole()`,
        keyed off `active_bans_local` (both the "0" and ">0" branches),
        gated to the `ids` console only;
      * `renderConsoleList`'s dedicated non-generic empty-state text for
        `ids`'s `recent_attempts`.
  - `active_bans_community`'s own label/tooltip (A-23) is untouched by this
    task, exactly as instructed.
  - `index.html`/`styles.css` are unmodified by this task (still contain no
    `conIdsStatus`/`con-ids-status` reference at all — that DOM node/style is
    entirely JS-created, never static markup).
  - The backend `/security/consoles/ids` payload still honestly reports a
    numeric `active_bans_local` (or `None` when CrowdSec isn't configured/
    reachable) — the precondition the new frontend banner relies on to
    decide what to show; this is the same shape A-11/A-23's own regression
    anchors already pin, re-asserted here narrowly as a sanity check that
    this frontend-only task didn't accidentally touch the router.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user


@pytest.mark.integration
def test_panel_html_and_css_are_untouched_by_this_task(client: TestClient):
    """A-32's own brief restricts it to app.js alone — the banner element is
    JS-created, so neither the static HTML nor styles.css should carry any
    trace of it."""
    html_response = client.get("/panel/")
    css_response = client.get("/panel/assets/styles.css")

    assert html_response.status_code == 200
    assert css_response.status_code == 200
    assert "conIdsStatus" not in html_response.text
    assert "con-ids-status" not in css_response.text


@pytest.mark.integration
def test_panel_app_js_wires_the_ids_status_banner_and_empty_list_text(client: TestClient):
    response = client.get("/panel/assets/app.js")

    assert response.status_code == 200
    js = response.text

    # The banner element is created + read/written in renderConsole(), keyed
    # off the real active_bans_local metric — never a fabricated/hardcoded
    # value — and inserted right before the metrics grid ("above the
    # metrics" per the DoD).
    assert "conIdsStatus" in js
    assert "active_bans_local" in js
    assert "metricsBox.parentNode.insertBefore(idsStatusBox, metricsBox)" in js
    # Colours reuse the app's existing CSS custom properties, not a new
    # hardcoded/invented palette.
    assert "var(--good-soft)" in js
    assert "var(--good-t)" in js
    assert "var(--warn-soft)" in js
    assert "var(--warn-t)" in js
    # Positive-state copy (RU/EN) — asserting the literal honest-verdict
    # phrasing survives, not just "some text exists".
    assert "Реальных атак на эту машину не обнаружено" in js
    assert "No real attacks detected on this machine" in js
    # Warning-state copy (RU/EN) — a plain factual count, no invented alarm.
    assert "Зафиксировано реальных попыток на этой машине: " in js
    assert "Real attempts detected on this machine: " in js

    # The dedicated non-generic empty `recent_attempts` text for `ids`
    # (task step 2) — distinct from the generic "Нет данных"/"No data yet"
    # every other console's empty list still uses.
    assert "Реальных попыток вторжения не зафиксировано" in js
    assert "No real intrusion attempts recorded" in js

    # Task step 3: `active_bans_community`'s existing A-23 label/tooltip
    # must be untouched by this task.
    assert "Заблокировано глобально (community-лист CrowdSec)" in js
    assert (
        "IP-адреса, заблокированные по данным всего сообщества CrowdSec по всему миру"
        in js
    )


@pytest.mark.integration
async def test_ids_console_still_reports_a_numeric_or_none_active_bans_local(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """Sanity check that this frontend-only task did not accidentally change
    the backend shape the new banner depends on: `active_bans_local` stays
    either a real `int` (CrowdSec reachable) or honestly `None` (not
    configured/unreachable) — never a string, never fabricated."""
    await create_user(
        migrated_session_maker, username="a32_regress", password="pw", role="admin"
    )
    token = client.post(
        "/auth/login", json={"username": "a32_regress", "password": "pw"}
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    metrics = response.json()["metrics"]
    assert "active_bans_local" in metrics
    assert metrics["active_bans_local"] is None or isinstance(
        metrics["active_bans_local"], int
    )
