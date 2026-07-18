"""A-17: quick/full scan orchestration, quarantine, and the in-memory scan-
job registry — exercised against real tmp_path files and the shared fake
`clamd` TCP server (tests/common/fake_clamd.py), no Docker required. Live
EICAR detection against a real `clamd` container is covered separately in
tests/integration/test_clamav_live.py.
"""

from __future__ import annotations

import asyncio

import pytest

from app.config import Settings
from app.services.mcp.security_connectors.clamav import (
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    ScanResult,
    _iter_scan_candidates,
    quarantine_file,
    run_quick_scan,
    start_full_scan,
)
from tests.common.fake_clamd import FakeClamd, free_but_closed_port

_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _eicar_aware_responder(data: bytes) -> bytes:
    if data == _EICAR:
        return b"stream: Eicar-Test-Signature FOUND\0"
    return b"stream: OK\0"


# ---------------------------------------------------------------------------
# _iter_scan_candidates
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_iter_scan_candidates_finds_regular_files_recursively(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"clean")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "b.txt").write_bytes(b"clean too")

    found = sorted(p.name for p in _iter_scan_candidates([tmp_path], max_files=50))

    assert found == ["a.txt", "b.txt"]


@pytest.mark.unit
def test_iter_scan_candidates_respects_max_files(tmp_path):
    for i in range(10):
        (tmp_path / f"f{i}.txt").write_bytes(b"x")

    found = list(_iter_scan_candidates([tmp_path], max_files=3))

    assert len(found) == 3


@pytest.mark.unit
def test_iter_scan_candidates_skips_files_over_the_stream_size_limit(tmp_path, monkeypatch):
    (tmp_path / "small.txt").write_bytes(b"x")

    import app.services.mcp.security_connectors.clamav as clamav_module

    monkeypatch.setattr(clamav_module, "_MAX_STREAM_BYTES", 0)  # every real file is now "too big"

    found = list(_iter_scan_candidates([tmp_path], max_files=50))

    assert found == []


# ---------------------------------------------------------------------------
# run_quick_scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_run_quick_scan_raises_when_not_configured_and_no_client_given():
    with pytest.raises(ClamAvNotConfiguredError):
        await run_quick_scan(settings=Settings(clamav_enabled=False), target_dirs=[])


@pytest.mark.unit
async def test_run_quick_scan_raises_clamd_error_when_unreachable(tmp_path):
    (tmp_path / "f.txt").write_bytes(b"x")
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError):
        await run_quick_scan(client=client, target_dirs=[tmp_path])


@pytest.mark.unit
async def test_run_quick_scan_detects_an_eicar_file_among_clean_ones(tmp_path):
    (tmp_path / "clean1.txt").write_bytes(b"hello world")
    (tmp_path / "clean2.txt").write_bytes(b"another clean file")
    (tmp_path / "eicar.txt").write_bytes(_EICAR)

    async with FakeClamd(scan_responder=_eicar_aware_responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_quick_scan(client=client, target_dirs=[tmp_path])

        assert result["scanned_count"] == 3
        assert len(result["infected"]) == 1
        assert result["infected"][0]["signature"] == "Eicar-Test-Signature"
        assert result["infected"][0]["path"].endswith("eicar.txt")


@pytest.mark.unit
async def test_run_quick_scan_with_no_matching_files_scans_zero_cleanly(tmp_path):
    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_quick_scan(client=client, target_dirs=[tmp_path])

        assert result["scanned_count"] == 0
        assert result["infected"] == []


# ---------------------------------------------------------------------------
# start_full_scan (background job)
# ---------------------------------------------------------------------------


async def _wait_until_finished(registry: ClamAvScanJobRegistry, job_id: str, *, timeout: float = 5.0):
    async def _poll():
        while True:
            job = registry.get(job_id)
            assert job is not None
            if job.status != "running":
                return job
            await asyncio.sleep(0.01)

    return await asyncio.wait_for(_poll(), timeout=timeout)


@pytest.mark.unit
async def test_start_full_scan_completes_in_the_background_and_detects_eicar(tmp_path):
    (tmp_path / "clean.txt").write_bytes(b"clean")
    (tmp_path / "eicar.txt").write_bytes(_EICAR)
    registry = ClamAvScanJobRegistry()

    async with FakeClamd(scan_responder=_eicar_aware_responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        job = await start_full_scan(registry, client=client, target_dirs=[tmp_path], max_files=50)
        assert job.status == "running"

        finished = await _wait_until_finished(registry, job.id)

        assert finished.status == "completed"
        assert finished.scanned_count == 2
        assert len(finished.infected) == 1
        assert finished.finished_at is not None


@pytest.mark.unit
async def test_start_full_scan_raises_when_not_configured():
    registry = ClamAvScanJobRegistry()

    with pytest.raises(ClamAvNotConfiguredError):
        await start_full_scan(registry, settings=Settings(clamav_enabled=False), target_dirs=[])


@pytest.mark.unit
async def test_start_full_scan_fails_fast_when_clamd_unreachable(tmp_path):
    registry = ClamAvScanJobRegistry()
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError):
        await start_full_scan(registry, client=client, target_dirs=[tmp_path])

    # No orphaned "running" job left behind by a scan that never started.
    assert registry._jobs == {}


class _FlakyClient:
    """Duck-typed stand-in for `ClamdClient`: answers `ping()` fine but
    `scan_bytes()` starts raising `ClamdError` after `fail_after` successful
    calls — deterministically simulates "clamd disappeared mid-scan" without
    depending on real socket-close timing."""

    def __init__(self, *, fail_after: int) -> None:
        self._calls = 0
        self._fail_after = fail_after

    async def ping(self) -> None:
        return None

    async def scan_bytes(self, data: bytes) -> ScanResult:
        self._calls += 1
        if self._calls > self._fail_after:
            raise ClamdError("connection lost mid-scan", reason="unreachable")
        return ScanResult(status="clean", signature=None, raw="stream: OK")


@pytest.mark.unit
async def test_full_scan_job_marks_failed_if_clamd_disappears_mid_scan(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"x")
    (tmp_path / "b.txt").write_bytes(b"y")
    (tmp_path / "c.txt").write_bytes(b"z")
    registry = ClamAvScanJobRegistry()
    client = _FlakyClient(fail_after=1)

    job = await start_full_scan(registry, client=client, target_dirs=[tmp_path], max_files=50)
    finished = await _wait_until_finished(registry, job.id)

    assert finished.status == "failed"
    assert finished.scanned_count == 1
    assert finished.error is not None


# ---------------------------------------------------------------------------
# quarantine_file
#
# `allowed_roots` is passed explicitly in every test below (rather than
# relying on the real default `_default_quick_scan_targets()`, i.e. the
# real Downloads/OS temp dir) so these tests are deterministic regardless
# of where pytest's own `tmp_path` happens to live on a given machine —
# see the "outside allowed roots" tests further down for the actual
# security-relevant behavior this restricts.
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_quarantine_file_moves_never_deletes(tmp_path):
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    destination = await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])

    assert not source.exists()
    assert destination.exists()
    assert destination.read_bytes() == b"payload"
    assert destination.parent == tmp_path / "quarantine"
    assert destination.name.endswith("_suspicious.exe")


@pytest.mark.unit
async def test_quarantine_file_raises_file_not_found_for_a_missing_path(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    with pytest.raises(FileNotFoundError):
        await quarantine_file(
            tmp_path / "does-not-exist.exe", settings=settings, allowed_roots=[tmp_path]
        )


@pytest.mark.unit
async def test_quarantine_file_two_same_named_files_do_not_collide(tmp_path):
    (tmp_path / "d1").mkdir()
    (tmp_path / "d2").mkdir()
    file_1 = tmp_path / "d1" / "invoice.pdf"
    file_2 = tmp_path / "d2" / "invoice.pdf"
    file_1.write_bytes(b"one")
    file_2.write_bytes(b"two")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    dest_1 = await quarantine_file(file_1, settings=settings, allowed_roots=[tmp_path])
    dest_2 = await quarantine_file(file_2, settings=settings, allowed_roots=[tmp_path])

    assert dest_1 != dest_2
    assert dest_1.read_bytes() == b"one"
    assert dest_2.read_bytes() == b"two"


@pytest.mark.unit
async def test_quarantine_file_rejects_a_path_outside_the_allowed_roots(tmp_path):
    """Security finding (architect review, 2026-07-16): `quarantine_file`
    must never accept an arbitrary path — only something that actually
    falls inside a known scan root. `outside_root`/`inside_root` are two
    unrelated tmp_path subtrees standing in for e.g. "/etc" vs. "the real
    Downloads folder"."""
    outside_root = tmp_path / "outside"
    inside_root = tmp_path / "inside"
    outside_root.mkdir()
    inside_root.mkdir()
    secret = outside_root / "not-a-scan-result.txt"
    secret.write_bytes(b"do not move me")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    with pytest.raises(ClamAvPathNotAllowedError):
        await quarantine_file(secret, settings=settings, allowed_roots=[inside_root])

    # Never moved: rejection happens before any filesystem mutation.
    assert secret.exists()
    assert secret.read_bytes() == b"do not move me"


@pytest.mark.unit
async def test_quarantine_file_rejects_a_path_outside_roots_even_when_it_does_not_exist(tmp_path):
    """The scope check must reject before the existence check — otherwise a
    caller could distinguish "outside scope, exists" from "outside scope,
    doesn't exist" via the error type, an existence oracle for paths it has
    no business asking about."""
    inside_root = tmp_path / "inside"
    inside_root.mkdir()
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    with pytest.raises(ClamAvPathNotAllowedError):
        await quarantine_file(
            tmp_path / "outside" / "does-not-exist.exe",
            settings=settings,
            allowed_roots=[inside_root],
        )


@pytest.mark.unit
async def test_quarantine_file_rejects_a_sibling_directory_with_a_similar_prefix(tmp_path):
    """Guards against naive string-prefix matching: a root named
    "Downloads" must not also match "Downloads-evil" just because the
    string starts the same way."""
    root = tmp_path / "Downloads"
    root.mkdir()
    lookalike = tmp_path / "Downloads-evil"
    lookalike.mkdir()
    decoy = lookalike / "file.txt"
    decoy.write_bytes(b"x")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    with pytest.raises(ClamAvPathNotAllowedError):
        await quarantine_file(decoy, settings=settings, allowed_roots=[root])


@pytest.mark.unit
async def test_quarantine_file_accepts_a_path_inside_a_nested_subdirectory_of_an_allowed_root(
    tmp_path,
):
    root = tmp_path / "Downloads"
    nested = root / "archive" / "extracted"
    nested.mkdir(parents=True)
    source = nested / "payload.exe"
    source.write_bytes(b"nested payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    destination = await quarantine_file(source, settings=settings, allowed_roots=[root])

    assert destination.read_bytes() == b"nested payload"


@pytest.mark.unit
async def test_quarantine_file_uses_default_quick_scan_targets_when_no_allowed_roots_given(
    tmp_path, monkeypatch
):
    """No `allowed_roots` override: falls back to the real
    `_default_quick_scan_targets()` — same single source of truth
    `run_quick_scan` itself is bounded to, not a duplicated constant list.
    Confirmed here by monkeypatching that function directly rather than the
    real Downloads/OS temp dir."""
    import app.services.mcp.security_connectors.clamav as clamav_module

    allowed_root = tmp_path / "Downloads"
    allowed_root.mkdir()
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [allowed_root])

    inside = allowed_root / "found-by-scan.exe"
    inside.write_bytes(b"x")
    outside = tmp_path / "elsewhere.exe"
    outside.write_bytes(b"y")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    # Inside the (mocked) default root: works.
    destination = await quarantine_file(inside, settings=settings)
    assert destination.read_bytes() == b"x"

    # Outside it: rejected.
    with pytest.raises(ClamAvPathNotAllowedError):
        await quarantine_file(outside, settings=settings)


# ---------------------------------------------------------------------------
# ClamAvScanJobRegistry
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_scan_job_registry_most_recent_completed_is_none_when_empty():
    registry = ClamAvScanJobRegistry()
    assert registry.most_recent_completed() is None


@pytest.mark.unit
def test_scan_job_registry_most_recent_completed_ignores_running_and_failed_jobs():
    registry = ClamAvScanJobRegistry()
    running = registry.create("quick")  # noqa: F841 - left running on purpose
    failed = registry.create("quick")
    registry.mark_failed(failed, error="unreachable")

    assert registry.most_recent_completed() is None


@pytest.mark.unit
def test_scan_job_registry_most_recent_completed_picks_the_latest_by_finished_at():
    registry = ClamAvScanJobRegistry()
    older = registry.create("quick")
    registry.mark_completed(older, scanned_count=1, infected=[])
    newer = registry.create("full")
    registry.mark_completed(newer, scanned_count=2, infected=[])

    # finished_at is an ISO-formatted UTC timestamp; `newer` was created (and
    # so finishes) strictly after `older` in wall-clock order.
    assert registry.most_recent_completed().id == newer.id


@pytest.mark.unit
def test_scan_job_to_payload_shape():
    registry = ClamAvScanJobRegistry()
    job = registry.create("quick")
    registry.mark_completed(job, scanned_count=3, infected=[{"path": "/x", "signature": "Sig"}])

    payload = job.to_payload()

    assert payload == {
        "id": job.id,
        "kind": "quick",
        "status": "completed",
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "scanned_count": 3,
        "infected": [{"path": "/x", "signature": "Sig"}],
        "error": None,
    }
