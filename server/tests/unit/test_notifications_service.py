"""NotificationService.handle_event against a real (tmp, migrated) SQLite
DB via a monkeypatched module-level `async_session_maker` — same pattern as
tests/unit/test_health_checks.py, not a mock of the DB layer itself.
"""

from datetime import datetime

import pytest
from sqlalchemy import select

import app.services.notifications.service as service_module
from app.config import Settings
from app.db.models import Notification
from app.services.notifications.channels import Channel
from app.services.notifications.registry import NotificationRegistry
from app.services.notifications.service import NotificationService
from app.services.notifications.trusted_contacts import TrustedContactRegistry


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


@pytest.mark.unit
async def test_handle_event_persists_a_notification_row_with_registered_channels(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.PANEL_ICON}, critical=False)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(),
        settings=_settings(quiet_hours_enabled=False),
    )

    await service.handle_event("demo.topic", {"foo": "bar"})

    async with migrated_session_maker() as session:
        row = await session.scalar(select(Notification).where(Notification.topic == "demo.topic"))

    assert row is not None
    assert row.payload == {"foo": "bar"}
    assert row.critical is False
    assert row.channels == ["panel_icon"]
    assert row.suppressed_quiet_hours is False


@pytest.mark.unit
async def test_unregistered_topic_is_persisted_as_non_critical_with_no_channels(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    service = NotificationService(
        registry=NotificationRegistry(),
        trusted_contacts=TrustedContactRegistry(),
        settings=_settings(quiet_hours_enabled=False),
    )

    await service.handle_event("never.registered", {})

    async with migrated_session_maker() as session:
        row = await session.scalar(
            select(Notification).where(Notification.topic == "never.registered")
        )

    assert row is not None
    assert row.critical is False
    assert row.channels == []


@pytest.mark.unit
async def test_quiet_hours_suppress_a_non_critical_topic(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.PANEL_ICON, Channel.EMAIL}, critical=False)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(),
        settings=_settings(
            quiet_hours_enabled=True, quiet_hours_start="22:00", quiet_hours_end="08:00"
        ),
        quiet_hours_clock=lambda: datetime(2026, 7, 14, 23, 0),  # inside the window
    )

    await service.handle_event("demo.topic", {})

    async with migrated_session_maker() as session:
        row = await session.scalar(select(Notification).where(Notification.topic == "demo.topic"))

    assert row.suppressed_quiet_hours is True
    assert row.channels == []


@pytest.mark.unit
async def test_quiet_hours_never_suppress_a_critical_topic(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    registry = NotificationRegistry()
    registry.register("critical.topic", channels={Channel.PANEL_ICON}, critical=True)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(),
        settings=_settings(
            quiet_hours_enabled=True, quiet_hours_start="22:00", quiet_hours_end="08:00"
        ),
        quiet_hours_clock=lambda: datetime(2026, 7, 14, 23, 0),  # inside the window
    )

    await service.handle_event("critical.topic", {})

    async with migrated_session_maker() as session:
        row = await session.scalar(
            select(Notification).where(Notification.topic == "critical.topic")
        )

    assert row.suppressed_quiet_hours is False
    assert row.channels == ["panel_icon"]


@pytest.mark.unit
async def test_email_channel_sends_when_smtp_configured_and_contacts_exist(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    sent: list[dict] = []

    async def fake_send_email(**kwargs):
        sent.append(kwargs)

    monkeypatch.setattr(service_module, "send_email", fake_send_email)

    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.EMAIL}, critical=False)
    contacts = TrustedContactRegistry(seed_emails=["ops@example.com"])
    service = NotificationService(
        registry=registry,
        trusted_contacts=contacts,
        settings=_settings(
            quiet_hours_enabled=False,
            smtp_host="localhost",
            smtp_from="hranix@example.com",
        ),
    )

    await service.handle_event("demo.topic", {"reason": "test"})

    assert len(sent) == 1
    assert sent[0]["to_addrs"] == ["ops@example.com"]
    assert sent[0]["from_addr"] == "hranix@example.com"

    async with migrated_session_maker() as session:
        row = await session.scalar(select(Notification).where(Notification.topic == "demo.topic"))
    assert row.email_sent is True


@pytest.mark.unit
async def test_email_channel_skips_and_logs_when_smtp_not_configured(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)
    called = False

    async def fake_send_email(**kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr(service_module, "send_email", fake_send_email)

    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.EMAIL}, critical=False)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(seed_emails=["ops@example.com"]),
        settings=_settings(quiet_hours_enabled=False),  # smtp_host/smtp_from unset
    )

    with caplog.at_level("INFO"):
        await service.handle_event("demo.topic", {})

    assert called is False
    assert any("SMTP is not configured" in record.message for record in caplog.records)

    async with migrated_session_maker() as session:
        row = await session.scalar(select(Notification).where(Notification.topic == "demo.topic"))
    assert row.email_sent is False


@pytest.mark.unit
async def test_email_channel_skips_and_logs_when_no_trusted_contacts(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)

    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.EMAIL}, critical=False)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(),  # empty
        settings=_settings(
            quiet_hours_enabled=False, smtp_host="localhost", smtp_from="hranix@example.com"
        ),
    )

    with caplog.at_level("INFO"):
        await service.handle_event("demo.topic", {})

    assert any("no trusted contacts are configured" in record.message for record in caplog.records)


@pytest.mark.unit
async def test_unimplemented_channel_logs_a_clear_no_delivery_message_not_silence(
    migrated_session_maker, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
):
    monkeypatch.setattr(service_module, "async_session_maker", migrated_session_maker)

    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.SOUND, Channel.VOICE}, critical=False)
    service = NotificationService(
        registry=registry,
        trusted_contacts=TrustedContactRegistry(),
        settings=_settings(quiet_hours_enabled=False),
    )

    with caplog.at_level("INFO"):
        await service.handle_event("demo.topic", {})

    messages = [record.message for record in caplog.records]
    assert any("sound" in m and "no real delivery wired" in m for m in messages)
    assert any("voice" in m and "no real delivery wired" in m for m in messages)
