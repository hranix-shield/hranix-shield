"""A-26: GET /security/consoles/{perimeter,ids,av,network,logs} against the
real app wiring (client fixture — real migrated tmp SQLite DB, real HTTP
layer via TestClient) — exercising each console's real `chart.values`,
newly backed by `metric_samples` (services/metrics/). `backup` is
deliberately excluded here: it already has its own real chart mechanism
(backup_jobs, see tests/integration/test_backup_console_router.py),
untouched by this task.

Each console's own connector(s) are monkeypatched the same way each
console's existing test file already does (test_security_console_ids_crowdsec.py
etc.) — this file only adds coverage for the NEW `chart` field, not a
second copy of each console's pre-existing connector-wiring tests.
"""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

import app.routers.security_console as security_console_module
from app.db.models import MetricSample
from tests.common.factories import create_user


async def _admin_headers(
    client: TestClient, session_maker: async_sessionmaker[AsyncSession], username: str
) -> dict[str, str]:
    await create_user(session_maker, username=username, password="pw", role="admin")
    token = client.post(
        "/auth/login", json={"username": username, "password": "pw"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def _insert_samples(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    console_id: str,
    metric: str,
    today_value: float,
    yesterday_value: float,
    now: datetime,
) -> None:
    async with session_maker() as session:
        session.add(
            MetricSample(console_id=console_id, metric=metric, value=today_value, sampled_at=now)
        )
        session.add(
            MetricSample(
                console_id=console_id,
                metric=metric,
                value=yesterday_value,
                sampled_at=now - timedelta(days=1),
            )
        )
        await session.commit()


def _ok_ids():
    async def _fake(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {
                "active_bans": 4,
                "active_bans_local": 2,
                "active_bans_community": 2,
                "banned_24h": None,
                "scenarios": 1,
                "last_event_at": None,
            },
            "recent_attempts": [],
        }

    return _fake


@pytest.mark.integration
async def test_ids_chart_is_insufficient_history_on_a_fresh_install(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    """DoD: an empty `metric_samples` table (fresh install) reports the new
    honest "insufficient history" signal (empty `values`), never the old
    "chart not implemented" placeholder — that placeholder no longer
    exists in the backend response at all."""
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _ok_ids())
    headers = await _admin_headers(client, migrated_session_maker, "chart_ids_empty")

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["chart"] == {"metric": "active_bans_local_7d", "unit": "count", "values": []}


@pytest.mark.integration
async def test_ids_chart_renders_real_history_once_two_days_accumulate(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _ok_ids())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        today_value=2,
        yesterday_value=5,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_ids_real")

    response = client.get("/security/consoles/ids", headers=headers)

    body = response.json()
    assert body["chart"]["metric"] == "active_bans_local_7d"
    assert len(body["chart"]["values"]) == 7
    assert body["chart"]["values"][-1] == 2.0
    assert body["chart"]["values"][-2] == 5.0


@pytest.mark.integration
async def test_perimeter_chart_reflects_two_independent_series(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    """Post-merge user question (2026-07-31): the chart used to be ONE
    series (local+community summed), which reads as "this many things
    happened on my machine" when almost all of it is CrowdSec's shared
    worldwide blocklist. Now two independent series: `values_community`
    (sampled under `perimeter` itself) and `values_local` (READ from
    `ids`'s own already-sampled `active_bans_local` history, not a second,
    duplicate sample of the same fact)."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": True}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _ok_ids())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="perimeter",
        metric="active_bans_community",
        today_value=4,
        yesterday_value=6,
        now=now,
    )
    # Deliberately under `console_id="ids"` — this is the series the
    # perimeter chart's `values_local` reads cross-console, never its own
    # separate sample.
    await _insert_samples(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        today_value=1,
        yesterday_value=3,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_perimeter")

    response = client.get("/security/consoles/perimeter", headers=headers)

    body = response.json()
    assert body["chart"]["metric"] == "crowdsec_active_bans_7d"
    assert body["chart"]["unit"] == "count"
    assert "values" not in body["chart"]  # old single-series shape is gone for this console
    assert len(body["chart"]["values_community"]) == 7
    assert body["chart"]["values_community"][-1] == 4.0
    assert body["chart"]["values_community"][-2] == 6.0
    assert len(body["chart"]["values_local"]) == 7
    assert body["chart"]["values_local"][-1] == 1.0
    assert body["chart"]["values_local"][-2] == 3.0


@pytest.mark.integration
async def test_perimeter_chart_shows_local_series_even_while_community_still_accumulates(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    """`active_bans_community` is a newly-introduced perimeter-scoped
    sample (2026-07-31) — a fresh install (or a machine upgrading from the
    old combined metric) has zero history for it on day one, while `ids`'s
    own `active_bans_local` may already have real history. The chart must
    not honestly-empty itself for up to 2 days just because ONE of the two
    series is still accumulating — see renderConsoleChart's own comment for
    the frontend half of this."""

    async def _fake_firewall():
        return {"connector": {"status": "ok"}, "active": True}

    async def _fake_disk_encryption():
        return {"connector": {"status": "ok"}, "active": True}

    monkeypatch.setattr(security_console_module, "fetch_firewall_status", _fake_firewall)
    monkeypatch.setattr(security_console_module, "fetch_disk_encryption_status", _fake_disk_encryption)
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _ok_ids())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="ids",
        metric="active_bans_local",
        today_value=0,
        yesterday_value=2,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_perimeter_partial")

    response = client.get("/security/consoles/perimeter", headers=headers)

    body = response.json()
    assert body["chart"]["values_community"] == []  # honest: genuinely no history yet
    assert len(body["chart"]["values_local"]) == 7
    assert body["chart"]["values_local"][-2] == 2.0


@pytest.mark.integration
async def test_av_chart_reflects_quarantine_count_history(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    async def _fake_osquery():
        return {
            "connector": {"status": "ok"},
            "process_count": 10,
            "file_events": {"status": "not_configured", "count": None, "recent": []},
        }

    async def _fake_clamav(settings=None, *, job_registry=None):
        return {
            "connector": {"status": "ok"},
            "engine_version": "1.0",
            "database_version": "1",
            "databases_updated_at": None,
            "quarantine_count": 3,
            "last_scan_at": None,
            "clean": True,
        }

    monkeypatch.setattr(security_console_module, "fetch_av_osquery_data", _fake_osquery)
    monkeypatch.setattr(security_console_module, "fetch_av_clamav_data", _fake_clamav)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="av",
        metric="quarantine_count",
        today_value=3,
        yesterday_value=1,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_av")

    response = client.get("/security/consoles/av", headers=headers)

    body = response.json()
    assert body["chart"]["metric"] == "quarantine_count_7d"
    assert body["chart"]["values"][-1] == 3.0
    assert body["chart"]["values"][-2] == 1.0


@pytest.mark.integration
async def test_network_chart_replaces_the_old_inbound_outbound_shape_with_real_values(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    async def _fake_network():
        return {
            "connector": {"status": "ok"},
            "connections": [],
            "listening_ports": [],
            "active_connections": 9,
        }

    monkeypatch.setattr(security_console_module, "fetch_network_console_data", _fake_network)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="network",
        metric="active_connections",
        today_value=9,
        yesterday_value=2,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_network")

    response = client.get("/security/consoles/network", headers=headers)

    body = response.json()
    # A-26: the old dead `{"inbound": [], "outbound": []}` shape is gone —
    # this console now uses the same uniform {metric, unit, values} shape
    # as every other console.
    assert "inbound" not in body["chart"]
    assert "outbound" not in body["chart"]
    assert body["chart"]["metric"] == "active_connections_7d"
    assert body["chart"]["values"][-1] == 9.0
    assert body["chart"]["values"][-2] == 2.0


@pytest.mark.integration
async def test_logs_chart_reflects_events_24h_history(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    async def _fake_logs(settings=None):
        return {
            "connector": {"status": "ok"},
            "metrics": {"events_24h": 6, "warnings_24h": None, "security_errors_24h": None, "sources": 1},
            "entries": [],
        }

    monkeypatch.setattr(security_console_module, "fetch_logs_console_data", _fake_logs)
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="logs",
        metric="events_24h",
        today_value=6,
        yesterday_value=3,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_logs")

    response = client.get("/security/consoles/logs", headers=headers)

    body = response.json()
    assert body["chart"]["metric"] == "events_24h_7d"
    assert body["chart"]["values"][-1] == 6.0
    assert body["chart"]["values"][-2] == 3.0


@pytest.mark.integration
async def test_a_consoles_chart_never_leaks_another_consoles_history(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession], monkeypatch
):
    """DoD-adjacent regression guard: perimeter and ids each get their own
    `crowdsec`-flavoured metric, but from DIFFERENT console_ids
    (`active_bans_community` vs `active_bans_local`) — inserting a lot of
    history for `perimeter`'s own metric must not make `ids`'s chart
    non-empty. (The reverse is NOT isolated by design — `perimeter`'s
    `values_local` deliberately cross-reads `ids`'s own history, see
    the two tests above — this guard only checks the direction that must
    stay isolated.)"""
    monkeypatch.setattr(security_console_module, "fetch_ids_console_data", _ok_ids())
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await _insert_samples(
        migrated_session_maker,
        console_id="perimeter",
        metric="active_bans_community",
        today_value=10,
        yesterday_value=10,
        now=now,
    )
    headers = await _admin_headers(client, migrated_session_maker, "chart_isolation")

    response = client.get("/security/consoles/ids", headers=headers)

    assert response.json()["chart"]["values"] == []
