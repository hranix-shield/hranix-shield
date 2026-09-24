"""A-17: quick/full scan orchestration, quarantine, and the in-memory scan-
job registry — exercised against real tmp_path files and the shared fake
`clamd` TCP server (tests/common/fake_clamd.py), no Docker required. Live
EICAR detection against a real `clamd` container is covered separately in
tests/integration/test_clamav_live.py.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import sys
from pathlib import Path

import pytest

from app.config import Settings
from app.services.event_bus import EventBus, Topic
from app.services.mcp.security_connectors.clamav import (
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvQuarantineNotFoundError,
    ClamAvRestoreConflictError,
    ClamAvScanJobRegistry,
    ClamdClient,
    ClamdError,
    ScanResult,
    _iter_scan_candidates,
    _known_scan_roots,
    _scan_paths,
    _SCAN_PATHS_MAX_CONSECUTIVE_FAILURES,
    list_quarantine_entries,
    quarantine_file,
    restore_quarantine_file,
    run_custom_scan,
    run_quick_scan,
    start_full_scan,
)
from tests.common.fake_clamd import FakeClamd, free_but_closed_port

_EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# A-65-0 (из промпта A-64): EICAR-тесты пишут настоящий EICAR-тестфайл,
# который реальный Windows Defender удаляет до скана — артефакт среды, не
# кода (см. CONTRIBUTING.md §1). Семантика тестов не меняется.
_EICAR_WIN_SKIP = pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows Defender перехватывает EICAR-тестфайл до скана (артефакт среды)",
)
# Тесты, сравнивающие монотонность finished_at у заданий, созданных подряд:
# разрешение системных часов Windows (~15 мс) даёт им одинаковые метки.
_CLOCK_WIN_SKIP = pytest.mark.skipif(
    sys.platform == "win32",
    reason="разрешение часов Windows (~15 мс) делает finished_at одинаковым у заданий, созданных подряд",
)


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


@_EICAR_WIN_SKIP
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


@_EICAR_WIN_SKIP
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
# Real bug found live (2026-08-03): a custom scan of a root-level folder
# (many files, one `ClamdClient` connection per file via `_scan_paths`)
# surfaced a whole-scan `clamav_unreachable` 503 from a single file's
# transient `ClamdError`, even though `clamd` itself was healthy and every
# other file would have scanned fine. `_scan_paths` must now tolerate a
# one-off blip (same "one bad item must not abort the whole run" reasoning
# already applied to `OSError` two lines above it), while still honestly
# giving up if `clamd` has genuinely gone away for good.
# ---------------------------------------------------------------------------


class _OnceFlakyClient:
    """Fails `scan_bytes` on exactly one call (a one-off blip), then
    recovers — unlike `_FlakyClient` above (a permanent breakdown from
    `fail_after` onward), this simulates the real bug's actual trigger: a
    single transient failure among many otherwise-healthy files."""

    def __init__(self, *, fail_on_call: int) -> None:
        self._calls = 0
        self._fail_on_call = fail_on_call

    async def ping(self) -> None:
        return None

    async def scan_bytes(self, data: bytes) -> ScanResult:
        self._calls += 1
        if self._calls == self._fail_on_call:
            raise ClamdError("transient blip", reason="unreachable")
        return ScanResult(status="clean", signature=None, raw="stream: OK")


class _PatternFlakyClient:
    """`scan_bytes` fails/succeeds per an explicit call-by-call `pattern`
    (`True` = fail) — lets a test assert the consecutive-failure counter
    really resets on any success, not just counts total failures across the
    whole run."""

    def __init__(self, pattern: list[bool]) -> None:
        self._pattern = pattern
        self._calls = 0

    async def ping(self) -> None:
        return None

    async def scan_bytes(self, data: bytes) -> ScanResult:
        should_fail = self._pattern[self._calls]
        self._calls += 1
        if should_fail:
            raise ClamdError("blip", reason="unreachable")
        return ScanResult(status="clean", signature=None, raw="stream: OK")


@pytest.mark.unit
async def test_scan_paths_skips_a_single_transient_failure_and_keeps_going(tmp_path):
    paths = []
    for i in range(3):
        p = tmp_path / f"f{i}.txt"
        p.write_bytes(b"x")
        paths.append(p)
    client = _OnceFlakyClient(fail_on_call=2)

    scanned, infected = await _scan_paths(client, paths)

    # Only the 2 genuinely-scanned files count — the failed one is skipped,
    # not dishonestly counted as scanned.
    assert scanned == 2
    assert infected == []


@pytest.mark.unit
async def test_run_quick_scan_tolerates_a_single_transient_scan_error(tmp_path):
    (tmp_path / "a.txt").write_bytes(b"1")
    (tmp_path / "b.txt").write_bytes(b"2")
    (tmp_path / "c.txt").write_bytes(b"3")
    client = _OnceFlakyClient(fail_on_call=2)

    result = await run_quick_scan(client=client, target_dirs=[tmp_path])

    assert result["scanned_count"] == 2
    assert result["infected"] == []


@pytest.mark.unit
async def test_scan_paths_resets_the_consecutive_failure_count_on_any_success(tmp_path):
    """Failures alternating with successes (never 2 in a row) must never
    trip the circuit breaker, no matter how many total failures accumulate
    across the whole run."""
    paths = []
    for i in range(7):
        p = tmp_path / f"f{i}.txt"
        p.write_bytes(b"x")
        paths.append(p)
    client = _PatternFlakyClient([True, False, True, False, True, False, True])

    scanned, infected = await _scan_paths(client, paths)

    assert scanned == 3  # the 3 `False` (successful) calls
    assert infected == []


@pytest.mark.unit
async def test_scan_paths_gives_up_after_enough_consecutive_failures_without_scanning_the_rest(
    tmp_path,
):
    """A genuinely-down `clamd` (every call fails, not just one) must not
    be masked behind an endless silent-skip loop across every remaining
    file — `_scan_paths` re-raises once `_SCAN_PATHS_MAX_CONSECUTIVE_FAILURES`
    failures happen in a row, and must not even attempt the files after
    that point."""
    paths = []
    for i in range(10):
        p = tmp_path / f"f{i}.txt"
        p.write_bytes(b"x")
        paths.append(p)
    client = _FlakyClient(fail_after=0)  # fails from the very first call onward

    with pytest.raises(ClamdError):
        await _scan_paths(client, paths)

    # Gave up exactly at the threshold — never attempted the remaining files.
    assert client._calls == _SCAN_PATHS_MAX_CONSECUTIVE_FAILURES


@pytest.mark.unit
async def test_run_quick_scan_reraises_clamd_error_once_clamd_is_genuinely_down(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_bytes(b"x")
    client = _FlakyClient(fail_after=0)

    with pytest.raises(ClamdError):
        await run_quick_scan(client=client, target_dirs=[tmp_path])


# ---------------------------------------------------------------------------
# A-33: _known_scan_roots
# ---------------------------------------------------------------------------


@pytest.mark.unit
def test_known_scan_roots_is_the_union_of_quick_and_full_targets(tmp_path, monkeypatch):
    import app.services.mcp.security_connectors.clamav as clamav_module

    home = tmp_path / "home"
    temp_dir = tmp_path / "temp"
    downloads = home / "Downloads"
    home.mkdir()
    temp_dir.mkdir()
    downloads.mkdir()
    # Downloads (quick) is a subdirectory of home (full) here on purpose —
    # the real-world shape this function's own docstring describes — but
    # `_known_scan_roots` only de-duplicates EXACT path matches, not "is
    # this root already covered by a broader one in the list" (see that
    # function's own docstring for why): the union genuinely contains all
    # 3 distinct roots, even though Downloads is already inside home.
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [downloads, temp_dir])
    monkeypatch.setattr(clamav_module, "_default_full_scan_targets", lambda: [home])

    roots = _known_scan_roots()

    assert set(roots) == {home.resolve(), temp_dir.resolve(), downloads.resolve()}


@pytest.mark.unit
def test_known_scan_roots_deduplicates_an_identical_root_listed_by_both(tmp_path, monkeypatch):
    import app.services.mcp.security_connectors.clamav as clamav_module

    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setattr(clamav_module, "_default_quick_scan_targets", lambda: [shared])
    monkeypatch.setattr(clamav_module, "_default_full_scan_targets", lambda: [shared])

    roots = _known_scan_roots()

    assert roots == [shared.resolve()]


# ---------------------------------------------------------------------------
# A-33: run_custom_scan
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_run_custom_scan_rejects_a_path_outside_the_allowed_roots(tmp_path):
    allowed_root = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed_root.mkdir()
    outside.mkdir()
    secret = outside / "secret.txt"
    secret.write_bytes(b"do not scan me")

    with pytest.raises(ClamAvPathNotAllowedError):
        await run_custom_scan(secret, allowed_roots=[allowed_root])


@pytest.mark.unit
async def test_run_custom_scan_rejects_a_traversal_attempt_outside_allowed_roots(tmp_path):
    """DoD-named case: a `"../../etc"`-style traversal attempt must be
    rejected exactly like any other out-of-scope path — `.resolve()`
    normalizes `..` before the scope check runs (see `run_custom_scan`'s
    docstring), so this is not a distinct code path from the plain
    "outside root" case above, but is still worth its own named regression
    anchor since the task brief calls it out explicitly."""
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "passwd").write_bytes(b"root:x:0:0")

    traversal_path = allowed_root / ".." / ".." / "etc" / "passwd"

    with pytest.raises(ClamAvPathNotAllowedError):
        await run_custom_scan(traversal_path, allowed_roots=[allowed_root])

    # Never touched: the file is still exactly where it was.
    assert (tmp_path / "etc" / "passwd").read_bytes() == b"root:x:0:0"


@pytest.mark.unit
async def test_run_custom_scan_rejects_outside_roots_even_when_the_path_does_not_exist(tmp_path):
    """Same "no existence oracle for out-of-scope paths" reasoning as
    `quarantine_file`'s equivalent test — the scope check must win over the
    existence check regardless of ordering convenience."""
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    with pytest.raises(ClamAvPathNotAllowedError):
        await run_custom_scan(tmp_path / "outside" / "does-not-exist", allowed_roots=[allowed_root])


@pytest.mark.unit
async def test_run_custom_scan_raises_file_not_found_for_a_missing_path_inside_allowed_roots(tmp_path):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    with pytest.raises(FileNotFoundError):
        await run_custom_scan(allowed_root / "does-not-exist.txt", allowed_roots=[allowed_root])


@pytest.mark.unit
async def test_run_custom_scan_raises_when_not_configured_and_no_client_given(tmp_path):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()

    with pytest.raises(ClamAvNotConfiguredError):
        await run_custom_scan(
            allowed_root, settings=Settings(clamav_enabled=False), allowed_roots=[allowed_root]
        )


@pytest.mark.unit
async def test_run_custom_scan_raises_clamd_error_when_unreachable(tmp_path):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    client = ClamdClient(host="127.0.0.1", port=free_but_closed_port(), timeout=1.0)

    with pytest.raises(ClamdError):
        await run_custom_scan(allowed_root, allowed_roots=[allowed_root], client=client)


@_EICAR_WIN_SKIP
@pytest.mark.unit
async def test_run_custom_scan_detects_an_eicar_file_in_an_allowed_nested_subdirectory(tmp_path):
    allowed_root = tmp_path / "allowed"
    nested = allowed_root / "project" / "sub"
    nested.mkdir(parents=True)
    (nested / "clean.txt").write_bytes(b"hello world")
    (nested / "eicar.txt").write_bytes(_EICAR)

    async with FakeClamd(scan_responder=_eicar_aware_responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_custom_scan(allowed_root, allowed_roots=[allowed_root], client=client)

        assert result["scanned_count"] == 2
        assert len(result["infected"]) == 1
        assert result["infected"][0]["signature"] == "Eicar-Test-Signature"
        assert result["path"] == str(allowed_root.resolve())


@_EICAR_WIN_SKIP
@pytest.mark.unit
async def test_run_custom_scan_can_target_a_single_file_directly(tmp_path):
    allowed_root = tmp_path / "allowed"
    allowed_root.mkdir()
    eicar_path = allowed_root / "eicar.txt"
    eicar_path.write_bytes(_EICAR)

    async with FakeClamd(scan_responder=_eicar_aware_responder) as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_custom_scan(eicar_path, allowed_roots=[allowed_root], client=client)

        assert result["scanned_count"] == 1
        assert len(result["infected"]) == 1
        assert result["path"] == str(eicar_path.resolve())


# A-65-0: тест моделирует POSIX-механику expanduser (подмена $HOME); на
# Windows os.path.expanduser читает USERPROFILE, поэтому подмена $HOME
# не действует — ограничение среды, не бага кода.
@pytest.mark.skipif(
    sys.platform == "win32",
    reason="expanduser на Windows читает USERPROFILE, а не подменяемый $HOME (POSIX-механика)",
)
@pytest.mark.unit
async def test_run_custom_scan_expands_a_leading_tilde_to_the_real_home_directory(tmp_path, monkeypatch):
    """The panel's own input placeholder (app.js's `avCustomScanPath`)
    suggests typing `~/Downloads/...` — a bare `Path.resolve()` does NOT
    expand `~`, it treats it as a literal directory name, which would
    wrongly reject exactly the input the UI invites (confirmed live while
    building this task). `expanduser()` must run first."""
    import app.services.mcp.security_connectors.clamav as clamav_module

    fake_home = tmp_path / "fake-home"
    downloads = fake_home / "Downloads"
    downloads.mkdir(parents=True)
    (downloads / "found.txt").write_bytes(b"x")
    # `Path.expanduser()` resolves `~` via `os.path.expanduser`'s own
    # `$HOME`-based lookup, NOT via `Path.home()` (confirmed by reading
    # pathlib's own source while building this test) — monkeypatching
    # `Path.home` alone (the technique test_clamav_live.py's live tests
    # already use for `_default_full_scan_targets()`) would not be enough
    # here, `$HOME` itself must point at the fake home too.
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.setattr(clamav_module.Path, "home", classmethod(lambda cls: fake_home))

    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_custom_scan(
            Path("~/Downloads"), allowed_roots=[fake_home], client=client
        )

    assert result["scanned_count"] == 1
    assert result["path"] == str(downloads.resolve())


@pytest.mark.unit
async def test_run_custom_scan_has_no_root_restriction_by_default(tmp_path):
    """Post-merge user finding (2026-08-02): the old default (fall back to
    `_known_scan_roots()`) is GONE — `allowed_roots=None` now means no
    restriction at all, only "the path must exist" is checked. Any path
    (here standing in for e.g. `/Applications`, an external drive — outside
    home/Downloads/temp, which `_known_scan_roots()` would have rejected)
    is scannable without passing `allowed_roots` explicitly."""
    outside_dir = tmp_path / "elsewhere"
    outside_dir.mkdir()
    outside_file = outside_dir / "found.txt"
    outside_file.write_bytes(b"x")

    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        result = await run_custom_scan(outside_file, client=client)

        assert result["scanned_count"] == 1


@pytest.mark.unit
async def test_run_custom_scan_still_honours_an_explicitly_passed_allowed_roots(tmp_path):
    """`allowed_roots` stays usable for a caller/test that DOES want a
    restriction — only the production default changed."""
    allowed_root = tmp_path / "home"
    allowed_root.mkdir()
    outside = tmp_path / "elsewhere.txt"
    outside.write_bytes(b"y")

    async with FakeClamd() as fake:
        client = ClamdClient(host="127.0.0.1", port=fake.port, timeout=2.0)

        with pytest.raises(ClamAvPathNotAllowedError):
            await run_custom_scan(outside, allowed_roots=[allowed_root], client=client)


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
async def test_quarantine_file_publishes_a_real_notification_when_event_bus_given(tmp_path):
    """Post-merge user request (2026-08-02): "везде уведомления" — a real
    quarantine must publish a real `Topic.SECURITY_ALERT` event (panel
    icon/text/sound/email per the notification matrix), not just update the
    in-console banner/tile."""
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    bus = EventBus()
    received: list[tuple[str, dict]] = []

    async def _capture(topic, payload):
        received.append((topic, payload))

    bus.subscribe(Topic.SECURITY_ALERT, _capture)

    await quarantine_file(
        source, settings=settings, allowed_roots=[tmp_path], reason="Eicar-Test-Signature", event_bus=bus
    )

    assert len(received) == 1
    topic, payload = received[0]
    assert topic == Topic.SECURITY_ALERT
    assert payload["reason"] == "file_quarantined"
    assert payload["original_path"] == str(source.resolve())
    assert payload["signature"] == "Eicar-Test-Signature"


@pytest.mark.unit
async def test_quarantine_file_never_publishes_when_no_event_bus_given(tmp_path):
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    # No event_bus kwarg at all — must not raise, must not implicitly touch
    # any global event bus.
    destination = await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])

    assert destination.exists()


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
# A-27: quarantine metadata + list_quarantine_entries + restore_quarantine_file
# ---------------------------------------------------------------------------


@pytest.mark.unit
async def test_quarantine_file_writes_a_metadata_sidecar_with_the_original_path_and_reason(tmp_path):
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    destination = await quarantine_file(
        source, settings=settings, allowed_roots=[tmp_path], reason="Eicar-Test-Signature"
    )

    entries = list_quarantine_entries(settings)
    assert len(entries) == 1
    entry = entries[0]
    assert entry.quarantined_path == str(destination)
    assert entry.original_path == str(source.resolve())
    assert entry.reason == "Eicar-Test-Signature"
    assert entry.quarantined_at  # real timestamp, not empty


@pytest.mark.unit
async def test_quarantine_file_reason_is_honestly_none_when_not_given(tmp_path):
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])

    entries = list_quarantine_entries(settings)
    assert entries[0].reason is None


@pytest.mark.unit
def test_list_quarantine_entries_is_empty_when_the_directory_does_not_exist_yet(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "never-created"))
    assert list_quarantine_entries(settings) == []


@pytest.mark.unit
async def test_list_quarantine_entries_newest_first(tmp_path, monkeypatch):
    import app.services.mcp.security_connectors.clamav as clamav_module

    real_datetime = clamav_module.datetime

    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    older = tmp_path / "older.exe"
    older.write_bytes(b"a")
    newer = tmp_path / "newer.exe"
    newer.write_bytes(b"b")

    await quarantine_file(older, settings=settings, allowed_roots=[tmp_path])

    # Force a distinguishable, strictly-later timestamp regardless of clock
    # resolution on a fast machine — this test cares about sort order, not
    # real wall-clock timing.
    class _LaterDatetime:
        @staticmethod
        def now(tz=None):
            return real_datetime(2099, 1, 1, tzinfo=tz)

    monkeypatch.setattr(clamav_module, "datetime", _LaterDatetime)
    await quarantine_file(newer, settings=settings, allowed_roots=[tmp_path])

    entries = list_quarantine_entries(settings)
    assert [Path(e.original_path).name for e in entries] == ["newer.exe", "older.exe"]


@pytest.mark.unit
async def test_list_quarantine_entries_skips_a_record_whose_payload_file_is_gone(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")

    destination = await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])
    destination.unlink()  # simulate the payload being removed by hand, outside this API

    assert list_quarantine_entries(settings) == []


@pytest.mark.unit
async def test_list_quarantine_entries_skips_an_unparseable_sidecar_without_crashing(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    (quarantine_dir / "garbage.meta.json").write_text("not json at all", encoding="utf-8")

    assert list_quarantine_entries(settings) == []


@pytest.mark.unit
async def test_restore_quarantine_file_moves_the_file_back_to_its_original_path(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    destination = await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])
    entry_id = list_quarantine_entries(settings)[0].id

    restored_path = await restore_quarantine_file(entry_id, settings=settings)

    assert restored_path == source.resolve()
    assert source.exists()
    assert source.read_bytes() == b"payload"
    assert not destination.exists()
    # The metadata sidecar is cleaned up too — a restored file no longer
    # appears in the list.
    assert list_quarantine_entries(settings) == []


@pytest.mark.unit
async def test_restore_quarantine_file_recreates_a_deleted_parent_directory(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    original_dir = tmp_path / "Downloads" / "sub"
    original_dir.mkdir(parents=True)
    source = original_dir / "suspicious.exe"
    source.write_bytes(b"payload")
    await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])
    entry_id = list_quarantine_entries(settings)[0].id

    shutil.rmtree(original_dir)  # the whole original directory is now gone

    restored_path = await restore_quarantine_file(entry_id, settings=settings)

    assert restored_path.exists()
    assert restored_path.read_bytes() == b"payload"


@pytest.mark.unit
async def test_restore_quarantine_file_raises_not_found_for_an_unknown_id(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))

    with pytest.raises(ClamAvQuarantineNotFoundError):
        await restore_quarantine_file("does-not-exist", settings=settings)


@pytest.mark.unit
async def test_restore_quarantine_file_raises_conflict_when_original_path_is_occupied(tmp_path):
    settings = Settings(clamav_quarantine_dir=str(tmp_path / "quarantine"))
    source = tmp_path / "suspicious.exe"
    source.write_bytes(b"payload")
    destination = await quarantine_file(source, settings=settings, allowed_roots=[tmp_path])
    entry_id = list_quarantine_entries(settings)[0].id

    # Something new now occupies the original path.
    source.write_bytes(b"a brand new, unrelated file")

    with pytest.raises(ClamAvRestoreConflictError):
        await restore_quarantine_file(entry_id, settings=settings)

    # Never destroyed either side of the conflict.
    assert source.read_bytes() == b"a brand new, unrelated file"
    assert destination.exists()


@pytest.mark.unit
async def test_restore_quarantine_file_rejects_a_tampered_sidecar_pointing_outside_quarantine_dir(
    tmp_path,
):
    """Defense in depth (same reasoning as `quarantine_file`'s own
    `_is_within_any_root` check): a metadata sidecar whose recorded
    `quarantined_path` does not actually live inside this settings' own
    quarantine directory must never be trusted to move an arbitrary path."""
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    settings = Settings(clamav_quarantine_dir=str(quarantine_dir))
    outside_target = tmp_path / "not-actually-quarantined.txt"
    outside_target.write_bytes(b"do not move me")

    tampered = {
        "id": "tampered-id",
        "quarantined_path": str(outside_target),
        "original_path": str(tmp_path / "somewhere.txt"),
        "reason": None,
        "quarantined_at": "2026-01-01T00:00:00+00:00",
    }
    (quarantine_dir / "tampered-id.meta.json").write_text(json.dumps(tampered), encoding="utf-8")

    with pytest.raises(ClamAvQuarantineNotFoundError):
        await restore_quarantine_file("tampered-id", settings=settings)

    assert outside_target.exists()  # never moved


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


@_CLOCK_WIN_SKIP
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


@_CLOCK_WIN_SKIP
@pytest.mark.unit
def test_scan_job_registry_most_recent_completed_kind_filter_ignores_other_kinds():
    """Post-merge user request (2026-08-02): `kind="full"` must find the
    most recent FULL job even when a QUICK job completed more recently —
    `fetch_av_clamav_data` relies on exactly this to keep the console's
    "Последняя проверка"/"Угроз не найдено" tiles honestly tied to full
    scans only, per the user's own complaint that a quick scan was
    silently making them look freshly re-checked."""
    registry = ClamAvScanJobRegistry()
    full_job = registry.create("full")
    registry.mark_completed(full_job, scanned_count=500, infected=[])
    quick_job = registry.create("quick")  # completes AFTER full_job
    registry.mark_completed(quick_job, scanned_count=5, infected=[])

    assert registry.most_recent_completed().id == quick_job.id  # unfiltered: quick wins (most recent)
    assert registry.most_recent_completed(kind="full").id == full_job.id
    assert registry.most_recent_completed(kind="custom") is None


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
        "path": None,
    }
