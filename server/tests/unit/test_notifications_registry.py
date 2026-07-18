import pytest

from app.services.event_bus import Topic
from app.services.notifications.channels import Channel
from app.services.notifications.registry import NotificationRegistry, register_default_topics


@pytest.mark.unit
def test_unregistered_topic_has_no_channels_and_is_not_critical():
    registry = NotificationRegistry()

    assert registry.channels_for("nothing.registered") == set()
    assert registry.is_critical("nothing.registered") is False


@pytest.mark.unit
def test_register_then_channels_for_and_is_critical():
    registry = NotificationRegistry()

    registry.register("demo.topic", channels={Channel.EMAIL, Channel.PANEL_ICON}, critical=True)

    assert registry.channels_for("demo.topic") == {Channel.EMAIL, Channel.PANEL_ICON}
    assert registry.is_critical("demo.topic") is True
    assert registry.known_topics() == ["demo.topic"]


@pytest.mark.unit
def test_set_channels_preserves_the_existing_critical_flag():
    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.EMAIL}, critical=True)

    registry.set_channels("demo.topic", {Channel.SOUND})

    assert registry.channels_for("demo.topic") == {Channel.SOUND}
    assert registry.is_critical("demo.topic") is True  # unchanged


@pytest.mark.unit
def test_set_channels_on_a_never_registered_topic_defaults_critical_to_false():
    registry = NotificationRegistry()

    registry.set_channels("brand.new.topic", {Channel.EMAIL})

    assert registry.channels_for("brand.new.topic") == {Channel.EMAIL}
    assert registry.is_critical("brand.new.topic") is False


@pytest.mark.unit
def test_snapshot_reports_sorted_channels_and_critical_flag():
    registry = NotificationRegistry()
    registry.register("demo.topic", channels={Channel.EMAIL, Channel.SOUND}, critical=False)

    snapshot = registry.snapshot()

    assert snapshot == {"demo.topic": {"channels": ["email", "sound"], "critical": False}}


@pytest.mark.unit
def test_register_default_topics_wires_all_three_phase_0_topics():
    registry = NotificationRegistry()

    register_default_topics(registry)

    assert set(registry.known_topics()) == {
        Topic.SECURITY_ALERT.value,
        Topic.HEALTH_CHANGED.value,
        Topic.BACKUP_STATUS.value,
    }


@pytest.mark.unit
def test_register_default_topics_marks_only_security_alert_critical():
    registry = NotificationRegistry()

    register_default_topics(registry)

    assert registry.is_critical(Topic.SECURITY_ALERT) is True
    assert registry.is_critical(Topic.HEALTH_CHANGED) is False
    assert registry.is_critical(Topic.BACKUP_STATUS) is False


@pytest.mark.unit
def test_register_default_topics_enables_panel_icon_for_every_known_topic():
    """Channel 4 (panel indicator) is the one channel Phase 0 can honestly
    claim works for every topic — assert it is never left out of the
    default matrix."""
    registry = NotificationRegistry()

    register_default_topics(registry)

    for topic in registry.known_topics():
        assert Channel.PANEL_ICON in registry.channels_for(topic)
