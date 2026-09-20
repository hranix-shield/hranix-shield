"""A-17: ClamdClient + Settings-driven wiring, fully offline against a
small in-process fake `clamd` TCP server (tests/common/fake_clamd.py) — same
"no Docker required for unit coverage" reasoning as A-11's
test_crowdsec_client.py, adapted to clamd's own line protocol (not HTTP, so
`httpx.MockTransport` does not apply here — a real `asyncio.start_server`
loopback listener is the equivalent test seam for a raw-socket client). The
live-container scenarios (real `clamd`, real EICAR detection) are covered
separately in tests/integration/test_clamav_live.py, marked `clamav_live`
and self-skipping when no real clamd is reachable.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.clamav import (
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    _parse_scan_response,
    _parse_version,
    create_clamav_client,
    fetch_av_clamav_data,
    is_clamav_configured,
    register_clamav_connector,
)
from tests.common.fake_clamd import FakeClamd, free_but_closed_port

_CONFIGURED_SETTINGS = Settings(clamav_enabled=True, clamav_host="127.0.0.1", clamav_port=3310)
_UNCONFIGURED_SETTINGS = Settings(clamav_enabled=False)


# ---------------------------------------------------------------------------
# ClamdClient protocol-level behavior
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_ping_succeeds_against_a_real_socket_server():
    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)
        await client.ping()  # must not raise


@pytest.mark.unit
async def test_ping_raises_unreachable_when_nothing_listens():
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError) as excinfo:
        await client.ping()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_version_returns_the_raw_line():
    async with FakeClamd(version="ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026") as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        version = await client.version()

        assert version == "ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026"


@pytest.mark.unit
async def test_reload_succeeds_against_a_real_socket_server():
    """A-27: `RELOAD` -> `"RELOADING"` — live-confirmed shape against the
    real `hranix-clamav` container (see `ClamdClient.reload`'s docstring),
    reproduced here by the shared fake server."""
    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)
        await client.reload()  # must not raise


@pytest.mark.unit
async def test_reload_raises_unreachable_when_nothing_listens():
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError) as excinfo:
        await client.reload()

    assert excinfo.value.reason == "unreachable"


@pytest.mark.unit
async def test_scan_bytes_streams_the_exact_payload_via_instream_framing():
    """Confirms this connector's own chunking/zero-length-terminator framing
    round-trips correctly — the fake server reassembles whatever it
    receives and this test checks it matches the original payload
    byte-for-byte, independent of `_INSTREAM_CHUNK_SIZE`."""
    payload = b"x" * 20000  # multiple chunks at the connector's 8192 chunk size

    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)
        result = await client.scan_bytes(payload)

        assert fake.received_stream_bytes == payload
        assert result.status == "clean"


@pytest.mark.unit
async def test_scan_bytes_reports_infected_with_signature_name():
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def responder(data: bytes) -> bytes:
        if data == eicar:
            return b"stream: Eicar-Test-Signature FOUND\0"
        return b"stream: OK\0"

    async with FakeClamd(scan_responder=responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await client.scan_bytes(eicar)

        assert result.status == "infected"
        assert result.signature == "Eicar-Test-Signature"


@pytest.mark.unit
async def test_scan_bytes_raises_unreachable_when_nothing_listens():
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError) as excinfo:
        await client.scan_bytes(b"irrelevant")

    assert excinfo.value.reason == "unreachable"


# ---------------------------------------------------------------------------
# Pure parsers
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.parametrize(
    "text,expected_status,expected_signature",
    [
        ("stream: OK", "clean", None),
        ("stream: Eicar-Test-Signature FOUND", "infected", "Eicar-Test-Signature"),
        ("INSTREAM size limit exceeded. ERROR", "error", None),
    ],
)
def test_parse_scan_response(text, expected_status, expected_signature):
    result = _parse_scan_response(text)
    assert result.status == expected_status
    assert result.signature == expected_signature


@pytest.mark.unit
def test_parse_version_splits_engine_db_version_and_build_date():
    engine, db_version, build_date = _parse_version(
        "ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026"
    )
    assert engine == "1.5.3"
    assert db_version == "28059"
    assert build_date == "2026-07-13T06:25:07+00:00"


@pytest.mark.unit
def test_parse_version_falls_back_honestly_on_an_unparseable_date():
    engine, db_version, build_date = _parse_version("ClamAV 1.5.3/28059/not-a-real-date")
    assert engine == "1.5.3"
    assert db_version == "28059"
    assert build_date == "not-a-real-date"  # real (from clamd), just unparsed — not None


@pytest.mark.unit
def test_parse_version_is_honestly_none_on_total_garbage():
    engine, db_version, build_date = _parse_version("")
    assert engine is None
    assert db_version is None
    assert build_date is None


# ---------------------------------------------------------------------------
# Settings-driven wiring
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_is_clamav_configured_follows_the_explicit_opt_in_flag():
    assert is_clamav_configured(Settings(clamav_enabled=False)) is False
    assert is_clamav_configured(Settings(clamav_enabled=True)) is True


@pytest.mark.unit
def test_create_clamav_client_returns_none_when_not_configured():
    assert create_clamav_client(_UNCONFIGURED_SETTINGS) is None


@pytest.mark.unit
def test_create_clamav_client_builds_a_real_client_when_configured():
    client = create_clamav_client(_CONFIGURED_SETTINGS)
    assert isinstance(client, ClamdClient)


@pytest.mark.unit
def test_register_clamav_connector_registers_the_expected_metadata():
    registry = MCPRegistry()

    register_clamav_connector(registry, settings=_CONFIGURED_SETTINGS)

    connector = registry.get("clamav")
    assert isinstance(connector, MCPConnector)
    assert connector.transport == "tcp"
    assert connector.endpoint == "tcp://127.0.0.1:3310"


@pytest.mark.unit
def test_register_clamav_connector_endpoint_is_empty_string_when_unconfigured():
    registry = MCPRegistry()

    register_clamav_connector(registry, settings=_UNCONFIGURED_SETTINGS)

    assert registry.get("clamav").endpoint == ""


# ---------------------------------------------------------------------------
# fetch_av_clamav_data
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_fetch_av_clamav_data_not_configured_reports_honest_placeholder():
    result = await fetch_av_clamav_data(_UNCONFIGURED_SETTINGS)

    assert result["connector"] == {"status": "not_configured"}
    assert result["engine_version"] is None
    assert result["database_version"] is None
    assert result["databases_updated_at"] is None
    assert result["quarantine_count"] is None


@pytest.mark.unit
async def test_fetch_av_clamav_data_unreachable_reports_that_status_and_never_raises():
    settings = Settings(clamav_enabled=True, clamav_host="127.0.0.1", clamav_port=free_but_closed_port())

    result = await fetch_av_clamav_data(settings)

    assert result["connector"] == {"status": "unreachable"}
    assert result["engine_version"] is None


@pytest.mark.unit
async def test_fetch_av_clamav_data_ok_reports_real_version_and_quarantine_count(tmp_path):
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    (quarantine_dir / "a_suspicious.exe").write_bytes(b"x")
    (quarantine_dir / "b_suspicious.exe").write_bytes(b"y")

    async with FakeClamd(version="ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026") as fake:
        settings = Settings(
            clamav_enabled=True,
            clamav_host="127.0.0.1",
            clamav_port=fake.port,
            clamav_quarantine_dir=str(quarantine_dir),
        )

        result = await fetch_av_clamav_data(settings)

        assert result["connector"] == {"status": "ok"}
        assert result["engine_version"] == "1.5.3"
        assert result["database_version"] == "28059"
        assert result["databases_updated_at"] == "2026-07-13T06:25:07+00:00"
        assert result["quarantine_count"] == 2
        # No job registry passed: scan-history fields honestly stay None,
        # not a guessed "just scanned, all clean".
        assert result["last_scan_at"] is None
        assert result["clean"] is None


@pytest.mark.unit
async def test_fetch_av_clamav_data_derives_last_scan_from_the_most_recent_full_job(tmp_path):
    """Post-merge user request (2026-08-02): deliberately a `"full"` job —
    see `test_fetch_av_clamav_data_ignores_quick_and_custom_jobs_for_these_two_fields`
    below for the complementary "quick/custom must NOT count" case."""
    registry = ClamAvScanJobRegistry()
    job = registry.create("full")
    registry.mark_completed(job, scanned_count=5, infected=[])

    async with FakeClamd() as fake:
        settings = Settings(
            clamav_enabled=True,
            clamav_host="127.0.0.1",
            clamav_port=fake.port,
            clamav_quarantine_dir=str(tmp_path / "quarantine"),
        )

        result = await fetch_av_clamav_data(settings, job_registry=registry)

        assert result["last_scan_at"] == job.finished_at
        assert result["clean"] is True


@pytest.mark.unit
async def test_fetch_av_clamav_data_clean_is_false_when_last_full_job_found_something(tmp_path):
    registry = ClamAvScanJobRegistry()
    job = registry.create("full")
    registry.mark_completed(
        job, scanned_count=1, infected=[{"path": "/tmp/x", "signature": "Eicar-Test-Signature"}]
    )

    async with FakeClamd() as fake:
        settings = Settings(
            clamav_enabled=True,
            clamav_host="127.0.0.1",
            clamav_port=fake.port,
            clamav_quarantine_dir=str(tmp_path / "quarantine"),
        )

        result = await fetch_av_clamav_data(settings, job_registry=registry)

        assert result["clean"] is False


@pytest.mark.unit
async def test_fetch_av_clamav_data_ignores_quick_and_custom_jobs_for_these_two_fields(tmp_path):
    """Regression test for a real user complaint (2026-08-02): a quick scan
    was silently making "Последняя проверка"/"Угроз не найдено" look
    freshly re-checked. Only a completed FULL job may ever set
    `last_scan_at`/`clean` — a quick (or custom) job, even one completed
    AFTER the last full job, must be ignored for these two fields."""
    registry = ClamAvScanJobRegistry()
    full_job = registry.create("full")
    registry.mark_completed(full_job, scanned_count=500, infected=[])
    quick_job = registry.create("quick")  # completes AFTER full_job, must still be ignored
    registry.mark_completed(
        quick_job, scanned_count=5, infected=[{"path": "/tmp/x", "signature": "Eicar-Test-Signature"}]
    )

    async with FakeClamd() as fake:
        settings = Settings(
            clamav_enabled=True,
            clamav_host="127.0.0.1",
            clamav_port=fake.port,
            clamav_quarantine_dir=str(tmp_path / "quarantine"),
        )

        result = await fetch_av_clamav_data(settings, job_registry=registry)

        # Reflects full_job (clean, no infections) — NOT the more recent,
        # infected quick_job.
        assert result["last_scan_at"] == full_job.finished_at
        assert result["clean"] is True


@pytest.mark.unit
async def test_fetch_av_clamav_data_last_scan_is_none_when_only_quick_jobs_exist(tmp_path):
    """No full scan has ever completed yet — honestly `None`/`None`, never
    fabricated from a quick scan's own result."""
    registry = ClamAvScanJobRegistry()
    job = registry.create("quick")
    registry.mark_completed(job, scanned_count=5, infected=[])

    async with FakeClamd() as fake:
        settings = Settings(
            clamav_enabled=True,
            clamav_host="127.0.0.1",
            clamav_port=fake.port,
            clamav_quarantine_dir=str(tmp_path / "quarantine"),
        )

        result = await fetch_av_clamav_data(settings, job_registry=registry)

        assert result["last_scan_at"] is None
        assert result["clean"] is None
