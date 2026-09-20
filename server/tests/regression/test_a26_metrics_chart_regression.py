"""A-26 regression anchor.

Per docs/инструкция-разработка-фаза-0-реальные-функции-панели-2026-07-19.md,
this task adds at least one regression test that must stay green through the
rest of Phase 0 (and beyond, alongside the A-10/A-11/A-15/A-16/A-17/A-18
anchors). Pins the core A-26 contract later tasks (A-27..A-30's own console
wiring) must not break:

  - GET /security/consoles/{ids,av,network,logs} always carry a
    `chart` dict shaped `{"metric": str, "unit": str, "values": list}` —
    the SAME uniform shape on every one of those 4 consoles now (before
    A-26, `network`'s was a different `{"inbound": [], "outbound": []}`
    shape entirely) — regardless of whether any real history has
    accumulated yet.
  - `chart.values` is always either `[]` (insufficient history — a fresh
    install, or a tool only just configured) or a list of exactly 7
    numbers (real last-7-days history) — never anything in between, never
    missing.
  - The old "chart rendering not implemented" placeholder text is gone
    from the backend response entirely (that concept doesn't exist in the
    API anymore, only in app.js's own rendering of an empty `values`).
  - `backup`'s own chart mechanism (backup_jobs-derived, A-12) is
    untouched — still always exactly 7 values, real or honestly zero.
  - `perimeter` deliberately LEFT this uniform single-`values` shape on
    2026-07-31 (post-merge user question: a single local+community-summed
    bar reads as "this many things happened on my machine" when almost all
    of it is CrowdSec's shared worldwide blocklist) — its `chart` is now
    `{"metric": str, "unit": str, "values_community": list, "values_local":
    list}`, each independently either `[]` or length-7, see
    test_security_console_charts.py's own two-series tests for the
    dedicated coverage. Kept as its own separate anchor test below rather
    than folded into the uniform-shape parametrize, so this file still
    documents which consoles share the uniform shape and which one
    deliberately does not.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.common.factories import create_user

_CHART_CONSOLES = ["ids", "av", "network", "logs"]


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.integration
@pytest.mark.parametrize("console_id", _CHART_CONSOLES)
async def test_every_console_reports_the_uniform_chart_shape_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], console_id: str
):
    """No monkeypatching: runs the real connectors, whatever this machine's
    actual state is — the point of this anchor is the *shape* of the
    contract (uniform chart dict, values either empty or length-7), not
    any one machine's specific values, same "shape not values" philosophy
    every other regression anchor in this suite uses."""
    headers = await _admin_headers(client, migrated_session_maker, f"a26_regress_{console_id}")

    response = client.get(f"/security/consoles/{console_id}", headers=headers)

    assert response.status_code == 200
    body = response.json()
    chart = body["chart"]
    assert set(chart.keys()) == {"metric", "unit", "values"}
    assert isinstance(chart["metric"], str)
    assert isinstance(chart["unit"], str)
    assert isinstance(chart["values"], list)
    assert len(chart["values"]) in (0, 7)
    # The pre-A-26 dead placeholder shape must never resurface.
    assert "inbound" not in chart
    assert "outbound" not in chart


@pytest.mark.integration
async def test_perimeter_chart_reports_its_own_two_series_shape_honestly(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """`perimeter` deliberately does NOT share the other 4 consoles' single-
    `values` shape (see this module's own docstring) — pinned separately so
    a future change can't silently collapse it back into one summed series
    without this anchor failing."""
    headers = await _admin_headers(client, migrated_session_maker, "a26_regress_perimeter")

    response = client.get("/security/consoles/perimeter", headers=headers)

    assert response.status_code == 200
    chart = response.json()["chart"]
    assert set(chart.keys()) == {"metric", "unit", "values_community", "values_local"}
    assert isinstance(chart["metric"], str)
    assert isinstance(chart["unit"], str)
    assert len(chart["values_community"]) in (0, 7)
    assert len(chart["values_local"]) in (0, 7)


@pytest.mark.integration
async def test_backup_console_chart_is_unaffected_by_a26(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """`backup` already had a real chart mechanism before A-26
    (backup_jobs, see services/backup/wiring.py._size_chart_7d) — this
    task must not touch it. Always exactly 7 values, real or honest zero,
    never an empty "insufficient history" list (unlike the 5 consoles
    above): backup_jobs zero-fills every day unconditionally."""
    headers = await _admin_headers(client, migrated_session_maker, "a26_regress_backup")

    response = client.get("/security/consoles/backup", headers=headers)

    assert response.status_code == 200
    chart = response.json()["chart"]
    assert chart["metric"] == "backup_size_7d"
    assert len(chart["values"]) == 7
