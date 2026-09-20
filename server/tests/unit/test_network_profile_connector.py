"""A-38: `network_profile.py` — platform dispatch (detection) + persistence
(`touch_network_profile`/`set_network_category`/`network_profile_payload`)
+ the background sweep (`run_network_profile_sweep`), fully offline (the
shared `run_local_command` helper is monkeypatched here, same "inject a
fake transport" technique test_os_firewall_connector.py already uses) — no
real `networksetup`/`nmcli`/`powershell.exe` invocation, and no dependency
on which OS the test suite itself happens to run on.

The macOS "SSID unreadable despite an active Wi-Fi interface" fallback
tested below is not a hypothetical edge case — it is the exact, live-
confirmed behaviour on this task's own dev machine (see
network_profile.py's module docstring for the full transcript-backed
finding), reproduced here deterministically via the fake transport.
"""

from datetime import datetime

import pytest
from sqlalchemy import select

import app.services.mcp.security_connectors.network_profile as network_profile_module
from app.db.models import NetworkProfile
from app.services.event_bus import EventBus, Topic
from app.services.mcp.security_connectors._local_command import LocalCommandNotFound
from app.services.mcp.security_connectors.network_profile import (
    NETWORK_PROFILE_CONNECTOR_NAME,
    detect_current_network,
    list_known_networks,
    network_profile_payload,
    register_network_profile_connector,
    run_network_profile_sweep,
    set_network_category,
    touch_network_profile,
)
from app.services.mcp.registry import MCPRegistry

_NOW = datetime(2026, 7, 23, 12, 0)


def _fake_run(handlers: dict[tuple, tuple[int, str, str]]):
    """`handlers` maps a FULL argv tuple to a fixed `(returncode, stdout,
    stderr)` reply — an argv not in the map raises `LocalCommandNotFound`,
    matching a real "unexpected command" case loudly rather than silently
    returning nothing."""

    async def _run(*args: str, timeout: float = 5.0):
        if args not in handlers:
            raise LocalCommandNotFound(f"unexpected command: {args!r}")
        return handlers[args]

    return _run


_MACOS_TWO_PORTS = (
    "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa:bb\n\n"
    "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: cc:dd\n"
)


# ---------------------------------------------------------------------------
# macOS detection
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_macos_returns_the_real_ssid_when_readable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )

    result = await detect_current_network()

    assert result == {
        "connector": {"status": "ok"},
        "kind": "wifi",
        "network_key": "wifi:HomeWifi",
        "display_name": "HomeWifi",
        "id_kind": "ssid",
        "default_category": "public",
    }


@pytest.mark.unit
async def test_macos_falls_back_to_gateway_ip_when_ssid_is_unreadable_despite_active_wifi(
    monkeypatch: pytest.MonkeyPatch,
):
    """The live-confirmed finding this task's own report documents: Wi-Fi
    genuinely connected (a real `inet` address) yet `networksetup
    -getairportnetwork` answers the SAME "not associated" text it also uses
    for a genuine disconnection. Must NOT be reported as `not_connected` —
    the interface plainly has a real address — and must NOT silently guess
    an SSID either; the fallback identity is honestly tagged
    `id_kind="gateway_ip"`."""
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (
                    1,
                    "You are not associated with an AirPort network.",
                    "",
                ),
                ("networksetup", "-getinfo", "Wi-Fi"): (
                    0,
                    "DHCP Configuration\nIP address: 192.168.1.90\nRouter: 192.168.1.1\n",
                    "",
                ),
            }
        ),
    )

    result = await detect_current_network()

    assert result["connector"] == {"status": "ok"}
    assert result["kind"] == "wifi"
    assert result["id_kind"] == "gateway_ip"
    assert result["network_key"] == "wifi:gw:192.168.1.1"


@pytest.mark.unit
async def test_macos_falls_back_to_ethernet_when_wifi_has_no_address(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "status: inactive\n", ""),
                ("ifconfig", "bridge0"): (0, "inet 10.0.0.5 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getinfo", "Thunderbolt Bridge"): (
                    0,
                    "IP address: 10.0.0.5\nRouter: 10.0.0.1\n",
                    "",
                ),
            }
        ),
    )

    result = await detect_current_network()

    assert result["connector"] == {"status": "ok"}
    assert result["kind"] == "wired"
    assert result["id_kind"] == "gateway_ip"
    assert result["network_key"] == "wired:gw:10.0.0.1"


@pytest.mark.unit
async def test_macos_reports_not_connected_when_nothing_has_an_address(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "status: inactive\n", ""),
                ("ifconfig", "bridge0"): (0, "status: inactive\n", ""),
            }
        ),
    )

    result = await detect_current_network()

    assert result == {
        "connector": {"status": "not_connected"},
        "kind": None,
        "network_key": None,
        "display_name": None,
        "id_kind": None,
        "default_category": None,
    }


# ---------------------------------------------------------------------------
# Linux (nmcli) — NOT live-verified (see module docstring), tested via the
# same fake transport so at least the documented output shape is exercised.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_linux_parses_the_active_nmcli_connection(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("nmcli", "-t", "-f", "NAME,UUID,DEVICE", "connection", "show", "--active"): (
                    0,
                    "HomeWifi:1234-uuid:wlan0\n",
                    "",
                ),
            }
        ),
    )

    result = await detect_current_network()

    assert result["connector"] == {"status": "ok"}
    assert result["kind"] == "wifi"
    assert result["id_kind"] == "connection_uuid"
    assert result["network_key"] == "linux:1234-uuid"
    assert result["display_name"] == "HomeWifi"


@pytest.mark.unit
async def test_linux_reports_not_connected_when_nmcli_lists_nothing(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("nmcli", "-t", "-f", "NAME,UUID,DEVICE", "connection", "show", "--active"): (0, "", ""),
            }
        ),
    )

    result = await detect_current_network()

    assert result["connector"] == {"status": "not_connected"}
    assert result["network_key"] is None


# ---------------------------------------------------------------------------
# Windows (Get-NetConnectionProfile) — NOT live-verified (see module
# docstring). Confirms NLA's own Public/Private categorisation is reused as
# the DEFAULT category, per this task's own brief.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_windows_defaults_a_public_profile_to_public_category(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Windows")
    csv_out = '"Name","NetworkCategory"\n"Coffee Shop Wifi","Public"\n'
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                (
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Csv -NoTypeInformation",
                ): (0, csv_out, ""),
            }
        ),
    )

    result = await detect_current_network()

    assert result["connector"] == {"status": "ok"}
    assert result["kind"] == "os_profile"
    assert result["network_key"] == "windows:Coffee Shop Wifi"
    assert result["default_category"] == "public"


@pytest.mark.unit
async def test_windows_defaults_a_private_profile_to_trusted_category(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Windows")
    csv_out = '"Name","NetworkCategory"\n"Home Network","Private"\n'
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                (
                    "powershell.exe",
                    "-NoProfile",
                    "-Command",
                    "Get-NetConnectionProfile | Select-Object Name,NetworkCategory | ConvertTo-Csv -NoTypeInformation",
                ): (0, csv_out, ""),
            }
        ),
    )

    result = await detect_current_network()

    assert result["default_category"] == "trusted"


# ---------------------------------------------------------------------------
# Unsupported platform
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_unsupported_platform_reports_not_configured(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "PlanNine")

    result = await detect_current_network()

    assert result == {
        "connector": {"status": "not_configured"},
        "kind": None,
        "network_key": None,
        "display_name": None,
        "id_kind": None,
        "default_category": None,
    }


# ---------------------------------------------------------------------------
# Persistence: touch_network_profile / set_network_category /
# network_profile_payload / list_known_networks
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_touch_creates_a_new_row_with_the_default_category(migrated_session_maker):
    async with migrated_session_maker() as session:
        row = await touch_network_profile(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            default_category="public",
            now=_NOW,
        )

    assert row.category == "public"
    assert row.first_seen_at == _NOW
    assert row.last_seen_at == _NOW


@pytest.mark.unit
async def test_touch_never_overwrites_an_already_persisted_category(migrated_session_maker):
    later = datetime(2026, 7, 23, 13, 0)
    async with migrated_session_maker() as session:
        await set_network_category(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            category="trusted",
            now=_NOW,
        )

    async with migrated_session_maker() as session:
        row = await touch_network_profile(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            default_category="public",  # a scheduler tick's own default — must NOT win
            now=later,
        )

    assert row.category == "trusted"  # the operator's prior choice survives
    assert row.last_seen_at == later  # but the sighting timestamp DOES advance


@pytest.mark.unit
async def test_set_network_category_upserts_a_never_before_seen_network(migrated_session_maker):
    async with migrated_session_maker() as session:
        row = await set_network_category(
            session,
            network_key="wifi:CoffeeShop",
            display_name="CoffeeShop",
            id_kind="ssid",
            category="public",
            now=_NOW,
        )

    assert row.category == "public"
    assert row.first_seen_at == _NOW


@pytest.mark.unit
async def test_set_network_category_changes_an_existing_row(migrated_session_maker):
    async with migrated_session_maker() as session:
        await touch_network_profile(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            default_category="public",
            now=_NOW,
        )

    later = datetime(2026, 7, 23, 13, 0)
    async with migrated_session_maker() as session:
        row = await set_network_category(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            category="trusted",
            now=later,
        )

    assert row.category == "trusted"

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert len(rows) == 1  # upsert, not a second row


@pytest.mark.unit
async def test_set_network_category_rejects_an_invalid_category(migrated_session_maker):
    async with migrated_session_maker() as session:
        with pytest.raises(ValueError):
            await set_network_category(
                session,
                network_key="wifi:HomeWifi",
                display_name="HomeWifi",
                id_kind="ssid",
                category="super-secure",
                now=_NOW,
            )


@pytest.mark.unit
async def test_network_profile_payload_reflects_a_never_before_seen_network_as_its_default(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    """A fresh install: the current network has never been touched/set in
    the DB yet — `current.category` must still honestly reflect what a
    FIRST sighting would default to, not `None`/missing."""
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )

    async with migrated_session_maker() as session:
        payload = await network_profile_payload(session)

    assert payload["connector"] == {"status": "ok"}
    assert payload["current"]["network_key"] == "wifi:HomeWifi"
    assert payload["current"]["category"] == "public"  # the safe default, never a fabricated "trusted"
    assert payload["known"] == []


@pytest.mark.unit
async def test_network_profile_payload_reflects_a_persisted_category(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )
    async with migrated_session_maker() as session:
        await set_network_category(
            session,
            network_key="wifi:HomeWifi",
            display_name="HomeWifi",
            id_kind="ssid",
            category="trusted",
            now=_NOW,
        )

    async with migrated_session_maker() as session:
        payload = await network_profile_payload(session)

    assert payload["current"]["category"] == "trusted"
    assert len(payload["known"]) == 1
    assert payload["known"][0]["network_key"] == "wifi:HomeWifi"
    assert payload["known"][0]["category"] == "trusted"


@pytest.mark.unit
async def test_network_profile_payload_never_writes_on_a_passive_read(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    """A pure read: calling this twice for a genuinely-new network must
    NOT create a row — only `touch_network_profile`/`set_network_category`
    (the scheduler tick / the operator's own click) ever persist."""
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )

    async with migrated_session_maker() as session:
        await network_profile_payload(session)
        await network_profile_payload(session)

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert rows == []


@pytest.mark.unit
async def test_list_known_networks_orders_most_recently_seen_first(migrated_session_maker):
    async with migrated_session_maker() as session:
        await touch_network_profile(
            session, network_key="a", display_name="a", id_kind="ssid",
            default_category="public", now=datetime(2026, 7, 20, 0, 0),
        )
        await touch_network_profile(
            session, network_key="b", display_name="b", id_kind="ssid",
            default_category="public", now=datetime(2026, 7, 22, 0, 0),
        )

    async with migrated_session_maker() as session:
        rows = await list_known_networks(session)

    assert [row.network_key for row in rows] == ["b", "a"]


# ---------------------------------------------------------------------------
# run_network_profile_sweep — the background monitor's own testable core.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_sweep_writes_nothing_and_returns_none_when_no_network_is_detected(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "status: inactive\n", ""),
                ("ifconfig", "bridge0"): (0, "status: inactive\n", ""),
            }
        ),
    )

    key = await run_network_profile_sweep(
        migrated_session_maker, previous_key=None, now=_NOW
    )

    assert key is None
    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert rows == []


@pytest.mark.unit
async def test_sweep_publishes_a_nudge_when_the_network_changes_into_a_public_one(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: CafeWifi", ""),
            }
        ),
    )
    bus = EventBus()
    received: list[dict] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append(payload)

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    key = await run_network_profile_sweep(
        migrated_session_maker, previous_key="wifi:SomeOtherNetwork", event_bus=bus, now=_NOW
    )

    assert key == "wifi:CafeWifi"
    assert len(received) == 1
    assert received[0]["reason"] == "public_network_detected"
    assert received[0]["network_key"] == "wifi:CafeWifi"


@pytest.mark.unit
async def test_sweep_does_not_publish_when_the_network_key_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: CafeWifi", ""),
            }
        ),
    )
    bus = EventBus()
    received: list[dict] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append(payload)

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    key = await run_network_profile_sweep(
        migrated_session_maker, previous_key="wifi:CafeWifi", event_bus=bus, now=_NOW
    )

    assert key == "wifi:CafeWifi"
    assert received == []


@pytest.mark.unit
async def test_sweep_does_not_publish_when_the_network_is_trusted(
    monkeypatch: pytest.MonkeyPatch, migrated_session_maker
):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )
    async with migrated_session_maker() as session:
        await set_network_category(
            session, network_key="wifi:HomeWifi", display_name="HomeWifi", id_kind="ssid",
            category="trusted", now=_NOW,
        )
    bus = EventBus()
    received: list[dict] = []

    async def handler(topic: str, payload: dict) -> None:
        received.append(payload)

    bus.subscribe(Topic.SECURITY_ALERT, handler)

    key = await run_network_profile_sweep(
        migrated_session_maker, previous_key="wifi:SomeOtherNetwork", event_bus=bus, now=_NOW
    )

    assert key == "wifi:HomeWifi"
    assert received == []  # trusted — no nudge needed


@pytest.mark.unit
async def test_sweep_persists_the_sighting(monkeypatch: pytest.MonkeyPatch, migrated_session_maker):
    monkeypatch.setattr(network_profile_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(
        network_profile_module,
        "run_local_command",
        _fake_run(
            {
                ("networksetup", "-listallhardwareports"): (0, _MACOS_TWO_PORTS, ""),
                ("ifconfig", "en0"): (0, "inet 192.168.1.90 netmask 0xffffff00\nstatus: active\n", ""),
                ("networksetup", "-getairportnetwork", "en0"): (0, "Current Wi-Fi Network: HomeWifi", ""),
            }
        ),
    )

    await run_network_profile_sweep(migrated_session_maker, previous_key=None, now=_NOW)

    async with migrated_session_maker() as session:
        rows = (await session.scalars(select(NetworkProfile))).all()
    assert len(rows) == 1
    assert rows[0].network_key == "wifi:HomeWifi"
    assert rows[0].last_seen_at == _NOW


# ---------------------------------------------------------------------------
# Connector registration
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_register_network_profile_connector_adds_a_named_entry():
    registry = MCPRegistry()

    register_network_profile_connector(registry)

    connector = registry.get(NETWORK_PROFILE_CONNECTOR_NAME)
    assert connector is not None
    assert connector.transport == "subprocess"
    assert connector.endpoint == ""
