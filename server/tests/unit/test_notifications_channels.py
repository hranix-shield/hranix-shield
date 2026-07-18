import pytest

from app.services.notifications.channels import CHANNEL_DELIVERY_IMPLEMENTED, CHANNEL_IDS, Channel


@pytest.mark.unit
def test_channel_ids_cover_all_6_channels_from_the_plan():
    assert CHANNEL_IDS == ("sound", "voice", "text_window", "panel_icon", "email", "sms_call")
    assert set(CHANNEL_IDS) == {channel.value for channel in Channel}


@pytest.mark.unit
def test_every_channel_has_an_honesty_flag():
    assert set(CHANNEL_DELIVERY_IMPLEMENTED.keys()) == set(Channel)


@pytest.mark.unit
def test_only_panel_icon_and_email_are_actually_implemented_in_phase_0():
    implemented = {channel for channel, ok in CHANNEL_DELIVERY_IMPLEMENTED.items() if ok}
    assert implemented == {Channel.PANEL_ICON, Channel.EMAIL}
