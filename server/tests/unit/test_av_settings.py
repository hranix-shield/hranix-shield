"""Post-merge user request (2026-08-02): `services/av/settings.py` — the
DB-persisted, genuinely editable replacement for `av`'s old hardcoded
`scan_schedule` string. Real migrated tmp SQLite DB (`migrated_session_maker`
fixture), no monkeypatching needed — this is a pure DB read/write layer.
"""

from datetime import datetime

import pytest

from app.services.av.settings import get_av_settings, update_av_settings

_NOW = datetime(2026, 8, 2, 12, 0)


@pytest.mark.unit
async def test_get_av_settings_returns_honest_disabled_default_when_no_row_exists(
    migrated_session_maker,
):
    """A fresh install must never silently start running full scans on its
    own — same "safe default, explicit opt-in" principle
    Settings.backup_enabled/clamav_enabled already follow."""
    async with migrated_session_maker() as session:
        settings = await get_av_settings(session)

    assert settings.full_scan_schedule_enabled is False
    assert settings.full_scan_hour == 6
    assert settings.full_scan_minute == 0
    assert settings.full_scan_days == (0, 1, 2, 3, 4, 5, 6)
    assert settings.updated_at is None


@pytest.mark.unit
async def test_update_av_settings_persists_and_is_read_back(migrated_session_maker):
    async with migrated_session_maker() as session:
        written = await update_av_settings(
            session, enabled=True, hour=3, minute=30, days=[0, 2, 4], now=_NOW
        )

    assert written.full_scan_schedule_enabled is True
    assert written.full_scan_hour == 3
    assert written.full_scan_minute == 30
    assert written.full_scan_days == (0, 2, 4)
    assert written.updated_at == _NOW

    async with migrated_session_maker() as session:
        read_back = await get_av_settings(session)

    assert read_back.full_scan_schedule_enabled is True
    assert read_back.full_scan_hour == 3
    assert read_back.full_scan_minute == 30
    assert read_back.full_scan_days == (0, 2, 4)
    assert read_back.updated_at == _NOW


@pytest.mark.unit
async def test_update_av_settings_overwrites_the_same_single_row_not_a_new_one(
    migrated_session_maker,
):
    async with migrated_session_maker() as session:
        await update_av_settings(session, enabled=True, hour=6, minute=0, days=[0, 1, 2, 3, 4, 5, 6], now=_NOW)
        second = await update_av_settings(session, enabled=False, hour=9, minute=15, days=[5, 6], now=_NOW)

    assert second.full_scan_schedule_enabled is False
    assert second.full_scan_hour == 9
    assert second.full_scan_minute == 15
    assert second.full_scan_days == (5, 6)

    async with migrated_session_maker() as session:
        from sqlalchemy import func, select

        from app.db.models import AvSettings

        count = (await session.execute(select(func.count()).select_from(AvSettings))).scalar_one()
    assert count == 1
