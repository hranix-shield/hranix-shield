"""A-56: /security/overview's KPI tiles read REAL sources — the latest
`MetricSample` per series (the same (console_id, metric) pairs the sampler
writes: ("ids", "active_bans_local"), ("network", "active_connections")) —
and honestly report `None` when no sample exists yet, instead of the former
fabricated zeros that read as "checked, all quiet" while the Network
console showed 200 live connections (GUI-прогон 2026-09-19, находка F2).

The empty-DB → all-None test is the regression anchor against ever
reintroducing the factory zero. Seeding inserts `MetricSample` rows
directly (the sampler's own write shape, sampler.py::run_metrics_sample_sweep)
— the background sampler itself is deliberately NOT running under the
`client` fixture, so a test that saw non-None KPIs without seeding would
mean real fabricated values leaked back in.
"""

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import MetricSample
from tests.common.factories import create_user


async def _admin_token(
    client: TestClient, maker: async_sessionmaker[AsyncSession]
) -> str:
    await create_user(maker, username="overview-kpi-admin", password="pw", role="admin")
    response = client.post(
        "/auth/login", json={"username": "overview-kpi-admin", "password": "pw"}
    )
    return response.json()["access_token"]


async def _seed_sample(
    maker: async_sessionmaker[AsyncSession],
    *,
    console_id: str,
    metric: str,
    value: float,
    sampled_at: datetime,
) -> None:
    async with maker() as session:
        session.add(
            MetricSample(
                console_id=console_id, metric=metric, value=value, sampled_at=sampled_at
            )
        )
        await session.commit()


@pytest.mark.integration
async def test_overview_kpis_are_none_on_an_empty_database(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """Regression anchor: no samples → every KPI is None (UI «—»), never the
    old fabricated 0s."""
    token = await _admin_token(client, migrated_session_maker)

    response = client.get("/security/overview", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    assert response.json()["kpis"] == {
        "blocked_24h": None,
        "active_connections": None,
        "system_load_pct": None,
        "uptime_pct": None,
    }


@pytest.mark.integration
async def test_overview_kpis_read_the_latest_samples(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    token = await _admin_token(client, migrated_session_maker)
    base = datetime(2026, 9, 20, 12, 0, 0)

    # Two samples per series: the LATEST one must win, whatever its value.
    await _seed_sample(
        migrated_session_maker,
        console_id="ids", metric="active_bans_local", value=2.0, sampled_at=base
    )
    await _seed_sample(
        migrated_session_maker,
        console_id="ids", metric="active_bans_local", value=5.0,
        sampled_at=base + timedelta(minutes=10)
    )
    await _seed_sample(
        migrated_session_maker,
        console_id="network", metric="active_connections", value=200.0, sampled_at=base
    )
    # A different series entirely (perimeter's community bans) must NOT leak
    # into the ids/network KPIs.
    await _seed_sample(
        migrated_session_maker,
        console_id="perimeter", metric="active_bans_community", value=999.0,
        sampled_at=base + timedelta(minutes=11)
    )

    response = client.get("/security/overview", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    kpis = response.json()["kpis"]
    assert kpis["blocked_24h"] == 5
    assert kpis["active_connections"] == 200
    assert kpis["system_load_pct"] is None  # genuinely no Phase-0 source
    assert kpis["uptime_pct"] is None


@pytest.mark.integration
async def test_overview_kpis_are_per_series_independent(
    client: TestClient, migrated_session_maker: async_sessionmaker[AsyncSession]
):
    """One series sampled, the other not: the sampled tile shows the value,
    the unsampled one stays None — never a cross-fed or defaulted number."""
    token = await _admin_token(client, migrated_session_maker)
    base = datetime(2026, 9, 20, 12, 0, 0)

    await _seed_sample(
        migrated_session_maker,
        console_id="network", metric="active_connections", value=42.0, sampled_at=base
    )

    response = client.get("/security/overview", headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200
    kpis = response.json()["kpis"]
    assert kpis["blocked_24h"] is None
    assert kpis["active_connections"] == 42
