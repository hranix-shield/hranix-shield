"""A-17: ClamAV — signature-based malware scanner, the third and last source
this phase wires into the `av` ("Вирусная активность") console (osquery/A-15
already supplies process telemetry; Wazuh/A-16 is still pending). Unlike
osquery/os_firewall/os_disk_encryption (all subprocess-based, see
`_local_command.py`), this connector talks to `clamd` — a long-running
*daemon*, not a one-shot CLI — over a plain TCP socket, so its shape is
closer to `crowdsec.py`'s network client than to A-15/A-18's subprocess
connectors (see this task's brief: "твой ClamAV-коннектор ближе к этому
паттерну (демон clamd, общение по сокету/сети)").

`clamd` runs as a fully separate Docker container
(infra/security/clamav/docker-compose.yml) — GPLv2-licensed, so CLAUDE.md's
licence gate applies exactly as it did to CrowdSec (A-11): this module never
imports/links any ClamAV code into this process, it only ever speaks
`clamd`'s own line protocol (https://docs.clamav.net/manual/Usage/Scanning.html#clamd-protocol)
over a socket the container exposes.

Why INSTREAM, never SCAN/CONTSCAN by path
------------------------------------------
`clamd`'s classic `SCAN <path>`/`CONTSCAN <path>`/`MULTISCAN <path>` commands
ask the *daemon* to open a path on *its own* filesystem — which would only
work here if this project bind-mounted real host directories (Downloads,
temp, ...) into the clamd container so it could see them. That is exactly
the host-safety trade-off A-15's own docstring already rejected for osquery
("privileged-контейнер/bind-mount /proc, /dev — прямое нарушение
host-safety") and the one this task's own host-safety checklist forbids
("никакого bind-mount реальных /var/log/файловой системы хоста без явного
отдельного решения архитектора").

`INSTREAM` sidesteps this entirely: this process reads the file's bytes
itself (it already has full read access, being the same server process the
user runs the panel with) and streams them to `clamd` over the same
connection it uses to issue the command — `clamd` scans whatever bytes
arrive, with **zero knowledge of, or access to, any host path**. The
container stays exactly as isolated as CrowdSec's (infra/security/clamav/docker-compose.yml
has no bind-mounts of host data at all, only a named volume for its own
signature database) while this connector can still scan any file the server
process can read. The one real cost: each file is a full read-into-memory +
one streamed round trip, capped by `clamd`'s own default `StreamMaxLength`
(25 MiB, see `_MAX_STREAM_BYTES` below) — acceptable for the bounded
directory sets `run_quick_scan`/`run_full_scan` target (see their
docstrings), not attempted here for arbitrary large files.

Protocol details (confirmed empirically against a live
`clamav/clamav-debian:latest` container while building this task — see the
A-17 task report for the transcript):

  - Every command is sent `z`-prefixed and NUL-terminated (`b"zPING\\0"`) —
    this is `clamd`'s "null-terminated" command mode, chosen over the
    newline-terminated (`n`) mode because a filename streamed via
    `INSTREAM`'s raw bytes could itself contain a newline; NUL cannot appear
    in this protocol's own framing, so it is the unambiguous choice.
  - `PING` answers `b"PONG\\0"` — used as this connector's `ok`/`unreachable`
    probe, cheapest possible round trip.
  - `VERSION` answers a single line `b"ClamAV <engine>/<db_version>/<db_build_date>\\0"`
    (live example: `"ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026"`) — this is
    where `databases_updated_at` (see `fetch_av_clamav_data`) comes from: a
    real signature-database build timestamp `clamd` itself reports, never a
    guessed "just now".
  - `INSTREAM`: send `b"zINSTREAM\\0"`, then the file as a sequence of
    `<4-byte big-endian length><chunk bytes>` frames, terminated by one
    zero-length frame. `clamd` replies on the same connection with one line:
    `"stream: OK"` (clean), `"stream: <signature name> FOUND"` (infected —
    live-confirmed: the EICAR test string reports
    `"stream: Eicar-Test-Signature FOUND"`), or `"stream: <message> ERROR"`
    (e.g. stream too large). Parsed by `_parse_scan_response` below.

Three honest states, same vocabulary as every other connector in this stack:
  - `"not_configured"`: `Settings.clamav_enabled` is off (the Phase 0
    default) — see `is_clamav_configured`.
  - `"unreachable"`: enabled, but the socket could not be opened/read within
    `timeout`, or `clamd` answered something this module could not parse.
  - `"ok"`: `clamd` answered `PING`/`VERSION` correctly.

No `"unauthorized"` state (unlike CrowdSec): `clamd`'s TCP listener, as
deployed by infra/security/clamav/docker-compose.yml, has no credential of
its own to reject — network-level access control is the container's
`127.0.0.1`-only port binding, not an API key inside this protocol.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.config import Settings, get_settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry

logger = logging.getLogger(__name__)

CLAMAV_CONNECTOR_NAME = "clamav"

# clamd's own default `StreamMaxLength` (25 MiB) — this connector never
# raises it, it just skips (not errors on) anything already bigger than the
# daemon would accept, so a single oversized file cannot abort an entire
# quick/full scan. See infra/security/clamav/docker-compose.yml: this
# project deploys clamd with its stock config, so the daemon-side limit is
# exactly this value too.
_MAX_STREAM_BYTES = 25 * 1024 * 1024

_INSTREAM_CHUNK_SIZE = 8192


def is_clamav_configured(settings: Settings) -> bool:
    """`clamav_enabled` is the explicit opt-in this module's docstring
    explains (mirrors `ai_enabled`/`backup_enabled`, not
    `is_crowdsec_configured`'s "has a secret been set" check — clamd has no
    secret to set)."""
    return bool(settings.clamav_enabled)


class ClamdError(RuntimeError):
    """Raised by `ClamdClient` methods. `reason` is one of `"unreachable"`
    (see this module's docstring) — `"not_configured"` is never raised from
    here, it is decided one layer up (`fetch_av_clamav_data`,
    `run_quick_scan`, ...) purely from `Settings`, before a `ClamdClient` is
    even constructed."""

    def __init__(self, message: str, *, reason: str = "unreachable") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ScanResult:
    """One `INSTREAM` verdict. `status` is `"clean"` / `"infected"` /
    `"error"` (`clamd` itself failed to scan this particular stream, e.g.
    "size limit exceeded" — not the same as a connection-level
    `ClamdError`). `raw` is `clamd`'s own response line, kept for logging/
    debugging even though every field a caller needs is already parsed out."""

    status: str
    signature: str | None
    raw: str


def _parse_scan_response(text: str) -> ScanResult:
    text = text.strip().strip("\0").strip()
    if text.endswith("OK"):
        return ScanResult(status="clean", signature=None, raw=text)
    if text.endswith("FOUND"):
        # "stream: <signature name> FOUND" — live-confirmed shape (EICAR:
        # "stream: Eicar-Test-Signature FOUND", see this module's docstring).
        body = text.split(":", 1)[1].strip() if ":" in text else text
        signature = body[: -len("FOUND")].strip() or None
        return ScanResult(status="infected", signature=signature, raw=text)
    return ScanResult(status="error", signature=None, raw=text)


class ClamdClient:
    """Thin async TCP client speaking `clamd`'s own line protocol directly
    (see this module's docstring) — no `clamd` code runs in this process.

    Each method opens its own short-lived connection and closes it before
    returning, same "no persistent state to leak between calls" reasoning as
    `CrowdSecClient` reusing one `httpx.AsyncClient`, except `clamd`'s
    protocol has no equivalent of HTTP keep-alive for arbitrary command
    sequences (an `INSTREAM` session in particular owns its connection for
    the whole upload) — so a fresh connection per call is not a missed
    optimization, it is how this protocol is meant to be used for
    independent commands.
    """

    def __init__(self, *, host: str, port: int, timeout: float = 5.0) -> None:
        self._host = host
        self._port = port
        self._timeout = timeout

    async def _open(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(self._host, self._port), timeout=self._timeout
            )
        except (OSError, asyncio.TimeoutError) as exc:
            raise ClamdError(
                f"clamd unreachable at {self._host}:{self._port}: {exc}", reason="unreachable"
            ) from exc

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        writer.close()
        with contextlib.suppress(OSError, asyncio.TimeoutError):
            await writer.wait_closed()

    async def _run_command(self, command: bytes, *, read_size: int = 4096) -> str:
        reader, writer = await self._open()
        try:
            writer.write(command)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(read_size), timeout=self._timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise ClamdError(f"clamd command failed: {exc}", reason="unreachable") from exc
        finally:
            await self._close(writer)
        return data.decode("utf-8", errors="replace").strip("\0").strip()

    async def ping(self) -> None:
        """`PING` -> must answer exactly `"PONG"` — this connector's cheapest
        `ok`/`unreachable` probe (used by `fetch_av_clamav_data` and before
        starting any scan, so a dead `clamd` fails fast with a clear reason
        rather than mid-scan)."""
        response = await self._run_command(b"zPING\0", read_size=64)
        if response != "PONG":
            raise ClamdError(f"clamd PING returned unexpected response: {response!r}")

    async def version(self) -> str:
        """`VERSION` -> `"ClamAV <engine>/<db_version>/<db_build_date>"` —
        see this module's docstring for the live-confirmed shape."""
        return await self._run_command(b"zVERSION\0")

    async def scan_bytes(self, data: bytes) -> ScanResult:
        """`INSTREAM` a file already read into memory — see this module's
        docstring for exactly why this is the only scan primitive this
        connector uses (never `SCAN <path>`)."""
        reader, writer = await self._open()
        try:
            writer.write(b"zINSTREAM\0")
            for offset in range(0, len(data), _INSTREAM_CHUNK_SIZE):
                chunk = data[offset : offset + _INSTREAM_CHUNK_SIZE]
                writer.write(len(chunk).to_bytes(4, "big"))
                writer.write(chunk)
            writer.write((0).to_bytes(4, "big"))
            await writer.drain()
            response = await asyncio.wait_for(reader.read(4096), timeout=self._timeout)
        except (OSError, asyncio.TimeoutError) as exc:
            raise ClamdError(f"clamd INSTREAM failed: {exc}", reason="unreachable") from exc
        finally:
            await self._close(writer)
        return _parse_scan_response(response.decode("utf-8", errors="replace"))


def create_clamav_client(settings: Settings | None = None) -> ClamdClient | None:
    """A `ClamdClient` wired to real Settings, or `None` when
    `clamav_enabled` is off — mirrors `crowdsec.create_crowdsec_client`'s
    "return None when there is nothing to do" shape."""
    settings = settings or get_settings()
    if not is_clamav_configured(settings):
        return None
    return ClamdClient(host=settings.clamav_host, port=settings.clamav_port)


def _parse_version(version_text: str) -> tuple[str | None, str | None, str | None]:
    """Splits `"ClamAV 1.5.3/28059/Mon Jul 13 06:25:07 2026"` into
    `(engine_version, database_version, database_build_date_iso)`. Every
    part is honestly `None` (never guessed) if `clamd` ever answers a shape
    this does not recognize — a future ClamAV release changing this format
    must not crash the console, just report less."""
    parts = version_text.split("/", 2)
    engine_version = parts[0].removeprefix("ClamAV").strip() or None if parts else None
    database_version = parts[1].strip() if len(parts) > 1 and parts[1].strip() else None
    database_build_date: str | None = None
    if len(parts) > 2 and parts[2].strip():
        raw_date = parts[2].strip()
        try:
            # clamd reports this in C `ctime()` format, always UTC-less/naive
            # per ClamAV's own build tooling — treated as UTC here (the best
            # available assumption, not asserted as fact) rather than left
            # unparsed, since every other timestamp this API returns is ISO.
            parsed = datetime.strptime(raw_date, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
            database_build_date = parsed.isoformat()
        except ValueError:
            database_build_date = raw_date  # unparsed but still real, not fabricated
    return engine_version, database_version, database_build_date


def _count_quarantined_files(settings: Settings) -> int:
    quarantine_dir = settings.resolved_clamav_quarantine_dir
    if not quarantine_dir.is_dir():
        return 0
    return sum(1 for entry in quarantine_dir.iterdir() if entry.is_file())


def _placeholder_av_clamav_data(connector_status: str) -> dict[str, Any]:
    return {
        "connector": {"status": connector_status},
        "engine_version": None,
        "database_version": None,
        "databases_updated_at": None,
        "quarantine_count": None,
        "last_scan_at": None,
        "clean": None,
    }


async def fetch_av_clamav_data(
    settings: Settings | None = None, *, job_registry: "ClamAvScanJobRegistry | None" = None
) -> dict[str, Any]:
    """Real data for the `clamav` slice of `av`'s `connectors` dict (see
    `security_console.py._av_payload`) — never raises: `clamav_enabled` off
    or `clamd` unreachable both come back as an honest `connector.status`,
    never a 500 and never a fabricated "no threats found".

    `job_registry`, when given, additionally derives `last_scan_at`/`clean`
    from the most recently *completed* scan job this process has actually
    run (see `ClamAvScanJobRegistry.most_recent_completed` below) — real
    history, not invented, but process-memory only (same accepted Phase 0
    limitation as `SecurityConsoleRegistry`'s toggle state: a restart loses
    it, a future task can persist this to the DB if that turns out to
    matter). Left out (both fields stay `None`) when no registry is passed,
    so this function stays usable standalone (e.g. from a live test) without
    needing a running app's `app.state`.
    """
    settings = settings or get_settings()
    if not is_clamav_configured(settings):
        return _placeholder_av_clamav_data("not_configured")

    client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port)
    try:
        await client.ping()
        version_text = await client.version()
    except ClamdError as exc:
        logger.warning("clamav: %s", exc)
        return _placeholder_av_clamav_data(exc.reason)

    engine_version, database_version, databases_updated_at = _parse_version(version_text)
    data = {
        "connector": {"status": "ok"},
        "engine_version": engine_version,
        "database_version": database_version,
        "databases_updated_at": databases_updated_at,
        "quarantine_count": _count_quarantined_files(settings),
        "last_scan_at": None,
        "clean": None,
    }
    if job_registry is not None:
        last_job = job_registry.most_recent_completed()
        if last_job is not None:
            data["last_scan_at"] = last_job.finished_at
            data["clean"] = not last_job.infected
    return data


# ---------------------------------------------------------------------------
# Quick/full scans
# ---------------------------------------------------------------------------


def _default_quick_scan_targets() -> list[Path]:
    """Bounded, high-risk directories — never the whole disk (A-17 risk note
    #2: "определить разумные дефолтные границы сканирования"). Downloads and
    the OS temp directory are the classic malware landing zones (browser/
    mail downloads, archive extraction) — a much smaller, faster promise
    than "full scan" makes, exactly what "quick" implies. Missing
    directories are silently skipped (e.g. no Downloads folder yet), not an
    error.

    Empirically confirmed live while building this task (see the A-17 task
    report): on a real, in-use macOS dev machine, `tempfile.gettempdir()`
    (`/var/folders/.../T`) is NOT a small directory the way Downloads is —
    it is a per-user scratch space every running application shares, and
    measured over 15,000 files recursively / ~1,000 at its own top level on
    this one dev machine alone. `_iter_scan_candidates` below therefore
    walks it non-recursively (top-level files only) for a quick scan — see
    that function's `recursive` parameter — trading "might miss something
    nested" for "stays fast and bounded", exactly what "quick" promises;
    `start_full_scan`'s recursive home-directory walk is where deeper
    coverage belongs.
    """
    candidates = [Path.home() / "Downloads", Path(tempfile.gettempdir())]
    return [path for path in candidates if path.is_dir()]


def _default_full_scan_targets() -> list[Path]:
    """The user's own home directory — deliberately NOT the whole disk/`/`
    (same risk note as `_default_quick_scan_targets`): this is already an
    order of magnitude broader than the quick-scan set while staying inside
    "the data this one user actually owns", matching CLAUDE.md's own
    open/closed boundary reasoning ("по локальности/однопользовательности").
    Letting an operator point this at more later is an explicit non-goal of
    this task (see A-17 risk note #2), not an oversight."""
    home = Path.home()
    return [home] if home.is_dir() else []


def _iter_scan_candidates(target_dirs: list[Path], *, max_files: int, recursive: bool = True):
    """Yields up to `max_files` regular files from EACH of `target_dirs`
    independently (not one `max_files` budget shared/exhausted across all of
    them) — deliberately per-directory: a live run while building this task
    found that a shared cap let one large directory (the OS temp dir, see
    `_default_quick_scan_targets`'s docstring) starve every other target
    dir's turn before it was ever reached, silently scanning zero files from
    a small, genuinely high-risk directory like Downloads. Skips anything
    already bigger than clamd would accept (`_MAX_STREAM_BYTES`) or that
    this process cannot even `stat` (permission errors, broken symlinks,
    ...) — those are silently skipped, not fatal to the rest of the scan,
    same "one bad file must not abort the whole run" reasoning
    `osquery.py`'s FIM slice already uses for its own sub-failures.

    `recursive=False` (quick scan's own default via `run_quick_scan`) walks
    only each directory's own top-level entries, never its subdirectories —
    see `_default_quick_scan_targets`'s docstring for why this matters for
    the OS temp dir specifically. `recursive=True` (full scan's default)
    walks the whole subtree, appropriate for "полная проверка"."""
    for directory in target_dirs:
        count = 0
        try:
            walker = directory.rglob("*") if recursive else directory.glob("*")
        except OSError:
            continue
        for path in walker:
            if count >= max_files:
                break
            try:
                if not path.is_file() or path.stat().st_size > _MAX_STREAM_BYTES:
                    continue
            except OSError:
                continue
            count += 1
            yield path


async def _scan_paths(client: ClamdClient, paths) -> tuple[int, list[dict[str, Any]]]:
    scanned = 0
    infected: list[dict[str, Any]] = []
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            logger.warning("clamav: could not read %s for scanning: %s", path, exc)
            continue
        scanned += 1
        result = await client.scan_bytes(data)
        if result.status == "infected":
            infected.append({"path": str(path), "signature": result.signature})
        elif result.status == "error":
            logger.warning("clamav: scan error for %s: %s", path, result.raw)
    return scanned, infected


@dataclass
class ScanJob:
    """One quick/full scan's tracked outcome. In-memory only (see
    `ClamAvScanJobRegistry`) — Phase 0's accepted limitation, same reasoning
    as `SecurityConsoleRegistry`'s toggle state: a full scan is expected to
    take, at most, minutes, well inside one process's uptime; losing job
    history across a restart is an acceptable trade-off a future task can
    revisit (persisting to the DB) if it ever matters."""

    id: str
    kind: str  # "quick" | "full"
    status: str = "running"  # "running" | "completed" | "failed"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    scanned_count: int = 0
    infected: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "scanned_count": self.scanned_count,
            "infected": self.infected,
            "error": self.error,
        }


class ClamAvScanJobRegistry:
    """In-memory tracker for quick/full scan jobs — one instance per
    `create_app()` call (attached at `app.state.clamav_scan_job_registry`),
    same non-singleton reasoning as every other registry in
    `app_factory.py` (no state leaks between app instances/tests)."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}

    def create(self, kind: str) -> ScanJob:
        job = ScanJob(id=uuid4().hex, kind=kind)
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    def mark_completed(self, job: ScanJob, *, scanned_count: int, infected: list[dict[str, Any]]) -> None:
        job.status = "completed"
        job.scanned_count = scanned_count
        job.infected = infected
        job.finished_at = datetime.now(timezone.utc).isoformat()

    def mark_failed(self, job: ScanJob, *, error: str) -> None:
        job.status = "failed"
        job.error = error
        job.finished_at = datetime.now(timezone.utc).isoformat()

    def most_recent_completed(self) -> ScanJob | None:
        """The most recently *finished* completed job (quick or full alike)
        — used by `fetch_av_clamav_data` to derive `last_scan_at`/`clean`
        from real history. `None` if nothing has ever completed yet."""
        completed = [job for job in self._jobs.values() if job.status == "completed" and job.finished_at]
        if not completed:
            return None
        return max(completed, key=lambda job: job.finished_at)  # type: ignore[arg-type]


class ClamAvNotConfiguredError(RuntimeError):
    """Raised by `run_quick_scan`/`start_full_scan` when `clamav_enabled` is
    off — callers (the router) translate this into the same honest
    `503 {"error": "clamav_not_configured"}` shape `run_manual_backup`
    already established for `backup_not_configured`."""


async def run_quick_scan(
    *,
    settings: Settings | None = None,
    target_dirs: list[Path] | None = None,
    max_files: int = 50,
    client: ClamdClient | None = None,
) -> dict[str, Any]:
    """Synchronous quick scan: bounded to `_default_quick_scan_targets()`
    (Downloads + temp dir) unless `target_dirs` overrides it (used by tests
    to scan a controlled directory instead of the real ones), capped at
    `max_files` PER target directory (see `_iter_scan_candidates`'s
    docstring for why per-directory, not shared). Walks each target
    directory non-recursively (`recursive=False` — top-level entries only):
    live-confirmed while building this task that the OS temp dir in
    particular can hold thousands of files several directories deep, which
    a "quick" scan has no business fully descending into (see
    `_default_quick_scan_targets`'s docstring). Runs entirely within one
    request — quick by construction, so no background job needed here,
    unlike `start_full_scan` below.

    Raises `ClamAvNotConfiguredError` if `clamav_enabled` is off, and
    `ClamdError` if `clamd` itself is unreachable — both left for the caller
    (the router) to translate into an honest HTTP status, never swallowed
    into a fake "0 files scanned, all clean".
    """
    settings = settings or get_settings()
    if client is None:
        if not is_clamav_configured(settings):
            raise ClamAvNotConfiguredError("clamav_enabled is off")
        client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port)
    await client.ping()  # fail fast with a clear ClamdError before scanning anything

    dirs = target_dirs if target_dirs is not None else _default_quick_scan_targets()
    candidates = list(_iter_scan_candidates(dirs, max_files=max_files, recursive=False))
    scanned_count, infected = await _scan_paths(client, candidates)
    return {"scanned_count": scanned_count, "infected": infected, "target_dirs": [str(d) for d in dirs]}


async def _run_full_scan_job(
    job: ScanJob,
    registry: ClamAvScanJobRegistry,
    *,
    client: ClamdClient,
    target_dirs: list[Path],
    max_files: int,
) -> None:
    """The actual background body of a full scan — updates `job` in place as
    it goes (so a poller sees `scanned_count` grow even before completion),
    and always resolves `job.status` to `"completed"` or `"failed"`, never
    leaves it stuck at `"running"` forever, even on an unexpected exception
    (caught and recorded, never silently swallowed/lost since nothing else
    awaits this background task)."""
    try:
        candidates = list(_iter_scan_candidates(target_dirs, max_files=max_files, recursive=True))
        scanned = 0
        infected: list[dict[str, Any]] = []
        for path in candidates:
            try:
                data = path.read_bytes()
            except OSError as exc:
                logger.warning("clamav: could not read %s for scanning: %s", path, exc)
                continue
            try:
                result = await client.scan_bytes(data)
            except ClamdError as exc:
                # clamd went away mid-scan: stop here. `scanned` only counts
                # files this loop *finished* scanning (incremented below,
                # after a successful `scan_bytes`) — the file that just
                # failed is correctly NOT counted as scanned, so
                # `job.scanned_count` reports real completed work, not an
                # attempt that never got an answer.
                job.scanned_count = scanned
                registry.mark_failed(job, error=str(exc))
                return
            scanned += 1
            if result.status == "infected":
                infected.append({"path": str(path), "signature": result.signature})
            job.scanned_count = scanned
            job.infected = list(infected)
        registry.mark_completed(job, scanned_count=scanned, infected=infected)
    except Exception as exc:  # pragma: no cover - defensive, see docstring
        logger.exception("clamav: full scan job %s crashed", job.id)
        registry.mark_failed(job, error=str(exc))


async def start_full_scan(
    registry: ClamAvScanJobRegistry,
    *,
    settings: Settings | None = None,
    target_dirs: list[Path] | None = None,
    max_files: int = 5000,
    client: ClamdClient | None = None,
) -> ScanJob:
    """Starts a full scan as a background `asyncio.Task` and returns
    immediately with a `"running"` `ScanJob` — never blocks the request for
    however long a full scan of `_default_full_scan_targets()` (the user's
    home directory) actually takes (A-17 risk note #2: "полная проверка...
    может быть долгой"). Poll `registry.get(job.id)` (wired to `GET
    /security/consoles/av/clamav/scan/full/{job_id}`) for progress/result.

    Raises `ClamAvNotConfiguredError`/`ClamdError` (via an eager `ping()`)
    exactly like `run_quick_scan` — checked before any job is created, so a
    misconfigured/unreachable `clamd` fails the request immediately with a
    clear reason instead of silently creating a job doomed to fail.
    """
    settings = settings or get_settings()
    if client is None:
        if not is_clamav_configured(settings):
            raise ClamAvNotConfiguredError("clamav_enabled is off")
        client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port)
    await client.ping()

    dirs = target_dirs if target_dirs is not None else _default_full_scan_targets()
    job = registry.create("full")
    task = asyncio.create_task(
        _run_full_scan_job(job, registry, client=client, target_dirs=dirs, max_files=max_files)
    )
    # Never awaited by the caller (that's the point), but kept referenced on
    # the job's own registry entry indirectly via the task's own lifetime —
    # asyncio only warns about GC'd *unreferenced* tasks, and `registry`
    # (attached to `app.state`, outliving this call) is what keeps this
    # task's eventual result recorded via `_run_full_scan_job`'s side
    # effects on `job`, not via the `Task` object itself.
    _ = task
    return job


class ClamAvPathNotAllowedError(RuntimeError):
    """Raised by `quarantine_file` when `path` resolves outside the known
    scan roots (Downloads + the OS temp dir — the exact same
    `_default_quick_scan_targets()` list `run_quick_scan` itself is bounded
    to, reused here as the single source of truth rather than a duplicated
    constant list).

    Security finding from architect review (2026-07-16): without this
    check, `path` was accepted as an arbitrary string and passed straight
    to `shutil.move` — any authenticated user could quarantine (move) any
    file the server process has write access to anywhere on disk (e.g.
    `path: "/etc/passwd"`), not just something the scanner itself had
    already touched. Quarantine is "move something the scan already had
    permission to see", never an arbitrary-file-move primitive over the
    whole filesystem."""


def _is_within_any_root(path: Path, roots: list[Path]) -> bool:
    """`Path.relative_to`, not a string `startswith` — deliberately, to
    avoid the classic prefix-confusion bug where e.g.
    `/home/user/Downloadsevil` would wrongly count as "inside"
    `/home/user/Downloads` under naive string prefix matching."""
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


async def quarantine_file(
    path: Path, *, settings: Settings | None = None, allowed_roots: list[Path] | None = None
) -> Path:
    """Moves `path` into the quarantine directory — NEVER deletes, so an
    operator can recover a false positive (A-17 task brief: "карантин...
    никогда не удаление"). Returns the new quarantined path.

    Raises `ClamAvPathNotAllowedError` if `path` (after `.resolve()`, which
    normalizes `..`/symlinks) does not fall inside one of `allowed_roots`
    (default: `_default_quick_scan_targets()` — Downloads + the OS temp
    dir, same roots quick scan itself is bounded to; overridable for
    tests). Checked BEFORE existence, so a path outside the allowed roots
    is rejected the same way whether or not it actually exists — no
    existence oracle for out-of-scope paths. See `ClamAvPathNotAllowedError`
    above for why this check exists at all.

    Raises `FileNotFoundError` if `path` does not exist or is not a regular
    file — callers (the router) translate both of these into honest 4xx
    codes, never a silent no-op success.
    """
    settings = settings or get_settings()
    roots = allowed_roots if allowed_roots is not None else _default_quick_scan_targets()
    resolved = path.resolve()
    if not _is_within_any_root(resolved, [root.resolve() for root in roots]):
        raise ClamAvPathNotAllowedError(str(path))
    if not resolved.is_file():
        raise FileNotFoundError(str(path))
    quarantine_dir = settings.resolved_clamav_quarantine_dir
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    # uuid-prefixed: two different quarantined files can share a basename
    # (e.g. two unrelated "invoice.pdf" from different source directories)
    # without colliding.
    destination = quarantine_dir / f"{uuid4().hex}_{resolved.name}"
    await asyncio.to_thread(shutil.move, str(resolved), str(destination))
    return destination


def register_clamav_connector(registry: MCPRegistry, *, settings: Settings | None = None) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as `crowdsec.register_crowdsec_connector`, see that
    function's docstring for what this is (and is not) for."""
    settings = settings or get_settings()
    endpoint = f"tcp://{settings.clamav_host}:{settings.clamav_port}" if is_clamav_configured(settings) else ""
    registry.register(
        MCPConnector(
            name=CLAMAV_CONNECTOR_NAME,
            description=(
                "ClamAV/clamd — signature-based malware scanner (quick/"
                "full scan, quarantine), reached over clamd's own TCP "
                "protocol. GPLv2 license; runs as a separate Docker "
                "container, never linked into this process."
            ),
            transport="tcp",
            endpoint=endpoint,
        )
    )
