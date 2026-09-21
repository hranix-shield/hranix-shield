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
import json
import logging
import platform
import shlex
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import REPO_ROOT, Settings, get_settings
from app.services.mcp.security_connectors._local_command import WINDOWS_CREATE_NO_WINDOW
from app.db.models import ScanHistory
from app.db.session import async_session_maker
from app.services.event_bus import EventBus, Topic
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.elevated import ElevatedRunResult, elevated_run

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
    # A-63-4: clamd's over-`StreamMaxLength` answer — «INSTREAM size limit
    # exceeded. ERROR» — used to fall through to the generic bare-`error`
    # verdict with no extracted reason (and, when clamd slammed the socket
    # shut mid-upload, the client never even saw this text at all, see
    # scan_bytes). Match it explicitly so the raw reason is always carried
    # through to the caller/log instead of an empty "clamd INSTREAM failed: ".
    if "size limit exceeded" in text.lower():
        return ScanResult(status="error", signature=None, raw=text)
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

    async def reload(self) -> None:
        """`RELOAD` -> clamd re-reads the virus databases already present on
        its own disk (the named `clamav-db` volume, see
        infra/security/clamav/docker-compose.yml) and swaps them into the
        running scanner — empirically confirmed against the real
        `hranix-clamav` container while building A-27: `zRELOAD\\0` answers
        exactly `b"RELOADING\\0"`, same one-line-ack shape as `PING`/`PONG`.

        This is deliberately NOT "download new signatures from the
        internet" — that is `freshclam`'s job, a separate process this
        project's docker-compose.yml deliberately keeps disabled by default
        (see infra/security/clamav/docker-compose.yml's freshclam policy
        note) and which is, in any case, unreachable from clamd's own line
        protocol. `RELOAD` only re-reads whatever signature files already
        exist on disk at the moment it is called — e.g. after an operator
        has run `docker compose exec clamav freshclam` by hand. The router
        endpoint that calls this method is named accordingly ("Перечитать
        базы" / "Reread databases"), never "Обновить из интернета", so the
        UI does not imply capability this protocol does not have."""
        response = await self._run_command(b"zRELOAD\0", read_size=64)
        if response != "RELOADING":
            raise ClamdError(f"clamd RELOAD returned unexpected response: {response!r}")

    async def scan_bytes(self, data: bytes) -> ScanResult:
        """`INSTREAM` a file already read into memory — see this module's
        docstring for exactly why this is the only scan primitive this
        connector uses (never `SCAN <path>`).

        A-63-4 (live full-stack finding, 2026-09-21): for a stream over
        clamd's `StreamMaxLength` clamd does NOT read the upload to its end
        — it answers `INSTREAM size limit exceeded. ERROR` and SLAMS the
        connection shut mid-upload. The resulting reset used to surface as
        `ClamdError("clamd INSTREAM failed: ")` — an EMPTY message, the
        owner's live symptom on larger Downloads/*.zip files — losing
        clamd's actual explanation. Now: whatever answer made it through
        before the reset is drained and parsed (a size-limit answer becomes
        an honest `error` verdict carrying the reason, which the scan loops
        log and skip WITHOUT counting as a clamd failure), and only a reset
        with no recoverable answer raises `ClamdError` — whose message now
        always names the exception class, never empty again."""
        reader, writer = await self._open()
        response = b""
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
            recovered = b""
            with contextlib.suppress(OSError, asyncio.TimeoutError):
                recovered = await asyncio.wait_for(reader.read(4096), timeout=1.0)
            combined = (response + recovered).decode("utf-8", errors="replace")
            if "size limit exceeded" in combined.lower():
                return _parse_scan_response(combined)
            raise ClamdError(
                f"clamd INSTREAM failed: {type(exc).__name__}: {exc or '(connection reset)'}",
                reason="unreachable",
            ) from exc
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


# A-27: each quarantined payload file gets a sidecar metadata file next to
# it (see `quarantine_file`/`QuarantineEntry` below) — this suffix is never
# itself a quarantined *payload*, so `_count_quarantined_files` (this
# module's pre-existing "how many files are in quarantine" counter, used by
# `fetch_av_clamav_data`'s `quarantine_count` metric) must exclude it,
# otherwise every quarantined file would count twice (once for the payload,
# once for its own metadata sidecar).
_QUARANTINE_META_SUFFIX = ".meta.json"


def _count_quarantined_files(settings: Settings) -> int:
    quarantine_dir = settings.resolved_clamav_quarantine_dir
    if not quarantine_dir.is_dir():
        return 0
    return sum(
        1
        for entry in quarantine_dir.iterdir()
        if entry.is_file() and not entry.name.endswith(_QUARANTINE_META_SUFFIX)
    )


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
    from the most recently *completed* FULL scan job this process has
    actually run (see `ClamAvScanJobRegistry.most_recent_completed` below)
    — real history, not invented, but process-memory only (same accepted
    Phase 0 limitation as `SecurityConsoleRegistry`'s toggle state: a
    restart loses it, a future task can persist this to the DB if that
    turns out to matter). Left out (both fields stay `None`) when no
    registry is passed, so this function stays usable standalone (e.g. from
    a live test) without needing a running app's `app.state`.

    Post-merge user request (2026-08-02): deliberately `kind="full"`, not
    "any completed job" — a quick scan (~20 files in Downloads/temp) must
    never make these two console tiles look freshly re-checked; only a real
    full system scan counts as "the system was checked" for their purposes.
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
        last_job = job_registry.most_recent_completed(kind="full")
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


_SCAN_PATHS_MAX_CONSECUTIVE_FAILURES = 3


async def _scan_paths(client: ClamdClient, paths) -> tuple[int, list[dict[str, Any]]]:
    """Real bug found live (2026-08-03): `run_custom_scan` against a
    root-level folder (many files, one `ClamdClient` connection per file)
    surfaced a whole-scan 503 `clamav_unreachable` from a single file's
    transient `ClamdError` — even though `clamd` itself was healthy and
    every other file would have scanned fine. Same "one bad item must not
    abort the whole run" reasoning `_iter_scan_candidates` already applies
    to a file it cannot even stat, and the already-adjacent `OSError`
    handling below already applies to a file it cannot read: a single
    failed `scan_bytes` is logged and skipped, not fatal.

    `scanned` only counts files this loop *finished* scanning (incremented
    after a successful `scan_bytes`, not merely after a successful
    `read_bytes`) so the returned count stays honest.

    Not unbounded tolerance, though: if `clamd` has genuinely gone away
    mid-scan (not a one-off blip), every remaining file would otherwise
    fail too — at `ClamdClient`'s default 5s socket timeout, grinding
    through a custom scan's full `max_files` (1000) would block this
    request for up to ~80 minutes before honestly reporting what the
    caller already suspects. `_SCAN_PATHS_MAX_CONSECUTIVE_FAILURES`
    consecutive failures (reset by any success — a real fluke must not
    trip this) re-raises the last `ClamdError` so the caller gets the
    honest `clamav_unreachable` response quickly instead.
    """
    scanned = 0
    infected: list[dict[str, Any]] = []
    consecutive_failures = 0
    for path in paths:
        try:
            data = path.read_bytes()
        except OSError as exc:
            logger.warning("clamav: could not read %s for scanning: %s", path, exc)
            continue
        try:
            result = await client.scan_bytes(data)
        except ClamdError as exc:
            consecutive_failures += 1
            logger.warning("clamav: scan error for %s: %s", path, exc)
            if consecutive_failures >= _SCAN_PATHS_MAX_CONSECUTIVE_FAILURES:
                raise
            continue
        consecutive_failures = 0
        scanned += 1
        if result.status == "infected":
            infected.append({"path": str(path), "signature": result.signature})
        elif result.status == "error":
            logger.warning("clamav: scan error for %s: %s", path, result.raw)
    return scanned, infected


@dataclass
class ScanJob:
    """One quick/full/custom scan's tracked outcome. In-memory only (see
    `ClamAvScanJobRegistry`) — Phase 0's accepted limitation, same reasoning
    as `SecurityConsoleRegistry`'s toggle state: a full scan is expected to
    take, at most, minutes, well inside one process's uptime. A-33 adds a
    SEPARATE, persistent `scan_history` DB table (see `record_scan_history`
    below) precisely because that limitation eventually did matter — this
    in-memory job is still what a poller/`GET .../scan/full/{job_id}` reads
    for live progress, the DB table is the durable "what ran, ever" record.

    `path` (A-33): the specific path a `"custom"` scan targeted — always
    `None` for `"quick"`/`"full"` jobs (those scan a fixed, multi-directory
    target set, not one operator-chosen path), same nullable shape
    `scan_history.path` uses for exactly this reason.
    """

    id: str
    kind: str  # "quick" | "full" | "custom"
    status: str = "running"  # "running" | "completed" | "failed"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    finished_at: str | None = None
    scanned_count: int = 0
    infected: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None
    path: str | None = None

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
            "path": self.path,
        }


class ClamAvScanJobRegistry:
    """In-memory tracker for quick/full/custom scan jobs — one instance per
    `create_app()` call (attached at `app.state.clamav_scan_job_registry`),
    same non-singleton reasoning as every other registry in
    `app_factory.py` (no state leaks between app instances/tests)."""

    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}

    def create(self, kind: str, *, path: str | None = None) -> ScanJob:
        job = ScanJob(id=uuid4().hex, kind=kind, path=path)
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

    def most_recent_completed(self, *, kind: str | None = None) -> ScanJob | None:
        """The most recently *finished* completed job. `None` if nothing has
        ever completed yet.

        Post-merge user request (2026-08-02): `kind` (`"quick"`/`"full"`/
        `"custom"`) narrows this to one scan type — `fetch_av_clamav_data`
        now always passes `kind="full"` for `last_scan_at`/`clean`, per the
        user's own complaint that a quick scan (which only glances at
        ~20 files in Downloads/temp) was silently making the console's
        "Последняя проверка"/"Угроз не найдено" tiles look freshly re-
        checked, when nothing close to a real system check had actually
        happened. `kind=None` (the default) keeps the original
        any-type-counts behaviour for any other caller/test."""
        completed = [
            job
            for job in self._jobs.values()
            if job.status == "completed" and job.finished_at and (kind is None or job.kind == kind)
        ]
        if not completed:
            return None
        return max(completed, key=lambda job: job.finished_at)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# A-33: persistent scan history (scan_history table) — the durable
# counterpart to ClamAvScanJobRegistry's in-memory jobs above.
# ---------------------------------------------------------------------------


async def record_scan_history(
    session: AsyncSession,
    *,
    scan_type: str,
    path: str | None,
    scanned_count: int,
    infected_count: int,
    started_at: datetime,
    finished_at: datetime,
) -> None:
    """Persists one row to the `scan_history` table — the durable
    replacement for "only ever the current/most-recent job status"
    `ClamAvScanJobRegistry`'s own docstring above has flagged as a Phase 0
    limitation since A-17 ("a future task can persist this to the DB if
    that turns out to matter"). Called once, right after a scan of any kind
    (quick/full/custom) genuinely COMPLETES — never for a scan that never
    started at all (clamd unconfigured/unreachable before a single file was
    read): recording `scanned_count=0` for that case would read as "ran a
    clean scan of nothing", not the honest "never actually ran" it would
    be, the same "never fabricate a number" discipline every connector in
    this stack already follows.

    Takes an already-OPEN `session` rather than opening its own (unlike
    e.g. `services/metrics/sampler.py`'s `run_metrics_sample_sweep`, which
    has no request to piggyback on): `run_quick_scan`/`run_custom_scan` run
    synchronously inside one HTTP request and reuse that request's own
    `AsyncSession` (see routers/security_console.py's
    `clamav_quick_scan`/`clamav_custom_scan`); only `start_full_scan`'s
    background job has no request session to reuse, and opens its own via
    `async_session_maker` at its own call site instead (see
    `_run_full_scan_job` below).

    Never raises: a history-write failure must not turn an otherwise-
    successful scan response into a client-facing 500 — logged and
    swallowed, same "best-effort, secondary to the action's own outcome"
    reasoning as every other non-critical write in this stack.
    """
    try:
        session.add(
            ScanHistory(
                scan_type=scan_type,
                path=path,
                scanned_count=scanned_count,
                infected_count=infected_count,
                started_at=started_at,
                finished_at=finished_at,
            )
        )
        await session.commit()
    except Exception:
        logger.exception("clamav: failed to record scan history (scan_type=%r)", scan_type)


async def list_scan_history(session: AsyncSession, *, limit: int = 20) -> list[ScanHistory]:
    """Read side of `record_scan_history` — the last `limit` scans
    (quick/full/custom alike), most-recently-FINISHED first. Backs `GET
    /security/consoles/av/clamav/scan/history`'s "история сканирований"
    list (A-33) with real, persisted rows that survive a server restart,
    unlike `ClamAvScanJobRegistry`'s own in-memory job list."""
    rows = (
        await session.scalars(select(ScanHistory).order_by(ScanHistory.finished_at.desc()).limit(limit))
    ).all()
    return list(rows)


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
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """The actual background body of a full scan — updates `job` in place as
    it goes (so a poller sees `scanned_count` grow even before completion),
    and always resolves `job.status` to `"completed"` or `"failed"`, never
    leaves it stuck at `"running"` forever, even on an unexpected exception
    (caught and recorded, never silently swallowed/lost since nothing else
    awaits this background task).

    A-33: on a genuine `"completed"` outcome, also records a `scan_history`
    row — this background task has no request-scoped `AsyncSession` to
    reuse (unlike `run_quick_scan`/`run_custom_scan`'s router callers), so
    it opens its own via `session_maker` (defaults to the real
    `async_session_maker`, overridable for tests). Wrapped in its own
    try/except, deliberately NOT inside the outer try/except below: a
    history-write hiccup must never flip an otherwise-genuinely-completed
    job to `"failed"`, which the outer handler would do if this raised
    unguarded.
    """
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
        try:
            maker = session_maker or async_session_maker
            async with maker() as session:
                await record_scan_history(
                    session,
                    scan_type="full",
                    path=None,
                    scanned_count=scanned,
                    infected_count=len(infected),
                    started_at=datetime.fromisoformat(job.started_at).replace(tzinfo=None),
                    finished_at=datetime.fromisoformat(job.finished_at).replace(tzinfo=None),  # type: ignore[arg-type]
                )
        except Exception:
            logger.exception("clamav: failed to record full-scan history for job %s", job.id)
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
    session_maker: async_sessionmaker[AsyncSession] | None = None,
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

    `session_maker` (A-33): forwarded to `_run_full_scan_job`, which uses it
    to persist a `scan_history` row on completion — see that function's
    docstring. Overridable for tests, defaults to the real
    `async_session_maker` in production.
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
        _run_full_scan_job(
            job,
            registry,
            client=client,
            target_dirs=dirs,
            max_files=max_files,
            session_maker=session_maker,
        )
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
    whole filesystem.

    A-33: `run_custom_scan` below reuses this exact same error (and the
    same `_is_within_any_root` check) for its own path-scope validation —
    same security boundary ("не открывать сканирование всей файловой
    системы по запросу из UI"), one exception type, not a second,
    parallel one invented for a scan target instead of a quarantine
    target."""


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


def _known_scan_roots() -> list[Path]:
    """A-33: the broadest already-permitted scanning surface a user-chosen
    "custom" path is checked against (see `run_custom_scan` below) — the
    union of `_default_quick_scan_targets()` (Downloads + OS temp dir) and
    `_default_full_scan_targets()` (the user's home directory), resolved.
    Reuses those two functions rather than a third, independently-
    hardcoded root list: a future change to either default (e.g. adding a
    new quick-scan target) automatically becomes an already-allowed
    custom-scan boundary too, with nothing separate to keep in sync.

    De-duplicates only EXACT (resolved) path matches, not "is this root
    already a subdirectory of another root in the list" — in practice the
    real list still contains 3 entries (home, Downloads, OS temp dir), even
    though Downloads is already covered by home for `_is_within_any_root`'s
    purposes: that check accepts a path under ANY listed root, so a
    redundant nested entry costs nothing at validation time and is not
    worth a smarter (and slower) hierarchy-aware de-dup for this small,
    rarely-changing list."""
    seen: set[Path] = set()
    unique: list[Path] = []
    for root in [*_default_quick_scan_targets(), *_default_full_scan_targets()]:
        resolved = root.resolve()
        if resolved not in seen:
            seen.add(resolved)
            unique.append(resolved)
    return unique


async def run_custom_scan(
    path: Path,
    *,
    settings: Settings | None = None,
    allowed_roots: list[Path] | None = None,
    max_files: int = 1000,
    client: ClamdClient | None = None,
) -> dict[str, Any]:
    """A-33: on-demand scan of ONE operator-chosen path — the gap this
    task's own brief identifies ("нет UI для выбора произвольной... папки"):
    quick/full scan only ever cover a fixed set of directories
    (`_default_quick_scan_targets`/`_default_full_scan_targets`), with no
    way for an operator to point the scanner at, say, one specific project
    folder or USB-drive subdirectory they are personally suspicious of.

    Post-merge user finding (2026-08-02) — REVISITS A-33's own original
    `_known_scan_roots()` restriction, the same way A-45 later revisited
    A-43's own earlier "never for hub updates" position: this action is
    now reachable via a real native OS folder-picker
    (`pick_scan_folder`/app.js's «Проверить папку» → «Выбрать папку…»), and
    an operator who deliberately picked, e.g., `/Applications` or an
    external drive to check for malware found the scanner refusing every
    normal AV use case outside `~/Downloads`/temp/`$HOME` — the exact
    complaint that prompted this change. Re-examining WHY the restriction
    existed: it was written for `quarantine_file`, which MOVES a file — a
    genuine "arbitrary-file-move primitive over the whole filesystem" risk
    if any authenticated caller could trigger it remotely with any path.
    Scanning is read-only (`INSTREAM` streams bytes to `clamd`, nothing on
    disk is touched or reported back beyond a clean/infected verdict) AND
    always operator-initiated through this project's own authenticated
    admin UI (a native dialog requiring physical presence, or a typed
    path) — the original remote-arbitrary-primitive concern does not
    transfer to a read-only action a local operator explicitly asked for.
    `quarantine_file`'s OWN restriction is UNCHANGED and untouched by this
    — moving a file discovered by an unrestricted scan still requires its
    own separate, still-restricted quarantine call.

    `allowed_roots` stays as a parameter (tests, or a future caller that
    DOES want to restrict) but the production default is now `None`,
    meaning NO root restriction at all — only "the path must actually
    exist" is still checked. `ClamAvPathNotAllowedError` is only ever
    raised now when a caller explicitly passes `allowed_roots`.

    Raises `FileNotFoundError` if `path` does not exist (or falls outside
    an explicitly-passed `allowed_roots`); `ClamAvNotConfiguredError`/
    `ClamdError` (via an eager `ping()`, exactly like `run_quick_scan`) if
    `clamd` itself is off/unreachable — all left for the caller (the
    router) to translate into an honest HTTP status, never swallowed into
    a fake "0 files scanned, all clean".

    Runs synchronously within one request, same "fast enough to answer
    within one request" reasoning as `run_quick_scan` — bounded by
    `max_files` (a generous but real cap, not "the whole subtree no matter
    how large"): an operator who points this at their entire home
    directory gets a scan that stops at `max_files`, not one that silently
    turns into an unbounded full scan under a different name. Walks `path`
    itself recursively when it is a directory (`recursive=True`, unlike
    quick scan's shallow walk — this is an operator-CHOSEN, presumably
    narrower target, not the OS temp dir's own sprawling top level); scans
    `path` alone (no directory walk at all) when it is already a single
    file.

    `path.expanduser()` runs before `.resolve()`: the panel's own input
    placeholder (see app.js's `avCustomScanPath`) suggests a natural
    `~/Downloads/...`-style value, and a bare `.resolve()` treats a literal
    `~` as just another directory name (confirmed live while building this
    task — it does NOT expand to the real home directory on its own),
    which would wrongly reject every path typed exactly the way the UI
    invites. `expanduser()` only ever expands to THIS process's own real
    home directory (the same one `_default_full_scan_targets()` already
    trusts) — no new filesystem surface is exposed by allowing the
    shorthand.
    """
    settings = settings or get_settings()
    resolved = path.expanduser().resolve()
    if allowed_roots is not None and not _is_within_any_root(resolved, [root.resolve() for root in allowed_roots]):
        raise ClamAvPathNotAllowedError(str(path))
    if not resolved.exists():
        raise FileNotFoundError(str(path))

    if client is None:
        if not is_clamav_configured(settings):
            raise ClamAvNotConfiguredError("clamav_enabled is off")
        client = ClamdClient(host=settings.clamav_host, port=settings.clamav_port)
    await client.ping()  # fail fast with a clear ClamdError before scanning anything

    if resolved.is_file():
        candidates = [resolved] if resolved.stat().st_size <= _MAX_STREAM_BYTES else []
    else:
        candidates = list(_iter_scan_candidates([resolved], max_files=max_files, recursive=True))
    scanned_count, infected = await _scan_paths(client, candidates)
    return {"scanned_count": scanned_count, "infected": infected, "path": str(resolved)}


async def quarantine_file(
    path: Path,
    *,
    settings: Settings | None = None,
    allowed_roots: list[Path] | None = None,
    reason: str | None = None,
    event_bus: EventBus | None = None,
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

    A-27: also writes a small JSON metadata sidecar (`{id}.meta.json`,
    same quarantine directory, see `QuarantineEntry`) recording the
    ORIGINAL path (so `restore_quarantine_file` can put the file back where
    it came from — this docstring's own "never deletes" promise was, before
    A-27, only half-kept: nothing recorded where a quarantined file had come
    from, so no code anywhere could actually restore one) plus `reason`
    (the detected threat/signature name, when the caller has one — e.g. from
    a just-completed scan's `infected[].signature`; honestly `None` when
    quarantining a file the caller only suspects, not a scan-confirmed hit,
    never a guessed name) and `quarantined_at` (real wall-clock time, not
    derived from the filesystem's own mtime, which `shutil.move` can leave
    unchanged on some platforms).

    Post-merge user request (2026-08-02): `event_bus`, when given, publishes
    a real `Topic.SECURITY_ALERT` event (`reason="file_quarantined"`) after
    a genuinely successful move — same "real notification, not just a
    console banner" the user asked for ("везде уведомления"). Optional
    (default `None`, same shape `services/backup/service.run_backup`'s own
    `event_bus` parameter already establishes) so this function stays
    usable standalone (tests, a future non-HTTP caller) without a running
    app's event bus.
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
    # without colliding. The same uuid also names this entry's metadata
    # sidecar and doubles as its `id` for the list/restore endpoints, so no
    # separate id-to-file lookup table is needed.
    entry_id = uuid4().hex
    destination = quarantine_dir / f"{entry_id}_{resolved.name}"
    await asyncio.to_thread(shutil.move, str(resolved), str(destination))
    metadata = {
        "id": entry_id,
        "quarantined_path": str(destination),
        "original_path": str(resolved),
        "reason": reason,
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
    }
    meta_path = quarantine_dir / f"{entry_id}{_QUARANTINE_META_SUFFIX}"
    meta_path.write_text(json.dumps(metadata), encoding="utf-8")
    if event_bus is not None:
        await event_bus.publish(
            Topic.SECURITY_ALERT,
            {
                "reason": "file_quarantined",
                "original_path": str(resolved),
                "signature": reason,
            },
        )
    return destination


# ---------------------------------------------------------------------------
# Quarantine list + restore (A-27)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class QuarantineEntry:
    """One quarantined file's real, on-disk record — read back from the
    JSON sidecar `quarantine_file` writes next to it, never fabricated."""

    id: str
    quarantined_path: str
    original_path: str
    reason: str | None
    quarantined_at: str

    def to_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "quarantined_path": self.quarantined_path,
            "original_path": self.original_path,
            "reason": self.reason,
            "quarantined_at": self.quarantined_at,
        }


class ClamAvQuarantineNotFoundError(RuntimeError):
    """Raised by `restore_quarantine_file` when `entry_id` does not match a
    known quarantine metadata sidecar — the router translates this into an
    honest 404, never a silent no-op."""


class ClamAvRestoreConflictError(RuntimeError):
    """Raised by `restore_quarantine_file` when `original_path` is already
    occupied by a different file (e.g. a new file was created at that exact
    path after quarantining) — restoring would silently clobber whatever is
    there now, which this connector never does (same "never destroy data
    without telling the operator" principle as `quarantine_file` itself
    never deleting). The router translates this into an honest 409, leaving
    the quarantined file exactly where it was so the operator can decide."""


def _quarantine_meta_path(settings: Settings, entry_id: str) -> Path:
    return settings.resolved_clamav_quarantine_dir / f"{entry_id}{_QUARANTINE_META_SUFFIX}"


def _read_quarantine_metadata(meta_path: Path) -> dict[str, Any] | None:
    """`None` (never raises) for anything not a valid metadata sidecar this
    module itself wrote — a corrupt/foreign file in the quarantine
    directory must not crash the whole list, same "one bad entry does not
    abort the rest" principle `_iter_scan_candidates` already applies to
    scan targets."""
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def list_quarantine_entries(settings: Settings | None = None) -> list[QuarantineEntry]:
    """Real quarantine list for `GET /consoles/av/clamav/quarantine` — reads
    every metadata sidecar this connector has ever written, newest first.
    Skips (does not list) any entry whose quarantined payload file is no
    longer actually present on disk (e.g. removed by hand outside this
    API) — an honestly-empty list is better than a restore button that
    would 404, and skips (rather than raises on) any sidecar this process
    cannot parse, same defensive reasoning as `_read_quarantine_metadata`.
    """
    settings = settings or get_settings()
    quarantine_dir = settings.resolved_clamav_quarantine_dir
    if not quarantine_dir.is_dir():
        return []
    entries: list[QuarantineEntry] = []
    for meta_path in quarantine_dir.glob(f"*{_QUARANTINE_META_SUFFIX}"):
        data = _read_quarantine_metadata(meta_path)
        if data is None:
            continue
        quarantined_path = data.get("quarantined_path")
        entry_id = data.get("id")
        if not quarantined_path or not entry_id:
            continue
        if not Path(quarantined_path).is_file():
            continue  # payload gone — do not offer a restore that would 404
        entries.append(
            QuarantineEntry(
                id=entry_id,
                quarantined_path=quarantined_path,
                original_path=data.get("original_path", ""),
                reason=data.get("reason"),
                quarantined_at=data.get("quarantined_at", ""),
            )
        )
    entries.sort(key=lambda entry: entry.quarantined_at, reverse=True)
    return entries


async def restore_quarantine_file(entry_id: str, *, settings: Settings | None = None) -> Path:
    """Moves a quarantined file back to the ORIGINAL path `quarantine_file`
    recorded for it — the operator-recovers-a-false-positive path this
    connector's own docstring has promised since A-17 ("никогда не
    удаление... значит false positive можно восстановить") but which, until
    this function, no code anywhere actually implemented.

    Raises `ClamAvQuarantineNotFoundError` if `entry_id` has no metadata
    sidecar, or the sidecar is unparseable, or its recorded quarantined
    file no longer exists (same "no restore button for a payload that is
    already gone" reasoning as `list_quarantine_entries` not listing it).

    Raises `ClamAvRestoreConflictError` if something already occupies
    `original_path` — never silently overwritten (see that error's
    docstring). The quarantined file stays exactly where it was; the
    operator can resolve the conflict by hand and try again.

    Recreates `original_path`'s parent directory if it no longer exists
    (e.g. the user emptied/removed their Downloads folder while the file
    sat in quarantine) — restoring "as best as possible" rather than
    failing on a technicality the original quarantine action had no part
    in causing.
    """
    settings = settings or get_settings()
    quarantine_dir = settings.resolved_clamav_quarantine_dir
    meta_path = _quarantine_meta_path(settings, entry_id)
    data = _read_quarantine_metadata(meta_path) if meta_path.is_file() else None
    if data is None:
        raise ClamAvQuarantineNotFoundError(entry_id)

    quarantined_path = Path(data.get("quarantined_path", ""))
    original_path = Path(data.get("original_path", ""))
    # Defense in depth (same reasoning as `_is_within_any_root`'s use in
    # `quarantine_file`): the recorded quarantined path must actually be
    # inside this settings' own quarantine directory, so a hand-edited/
    # corrupted sidecar cannot trick this into moving an arbitrary file.
    if not _is_within_any_root(quarantined_path.resolve(), [quarantine_dir.resolve()]):
        raise ClamAvQuarantineNotFoundError(entry_id)
    if not quarantined_path.is_file():
        raise ClamAvQuarantineNotFoundError(entry_id)
    if original_path.exists():
        raise ClamAvRestoreConflictError(str(original_path))

    original_path.parent.mkdir(parents=True, exist_ok=True)
    await asyncio.to_thread(shutil.move, str(quarantined_path), str(original_path))
    with contextlib.suppress(OSError):
        meta_path.unlink()
    return original_path


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


# ---------------------------------------------------------------------------
# Post-merge user request (2026-08-02): "Обновить базы сейчас" — a narrow
# elevated docker-exec exception for ClamAV, the same shape A-43 first
# established for CrowdSec (crowdsec.py's own "A-43 addendum" docstring
# section) and A-45 later extended there too. Opened here because
# infra/security/clamav/docker-compose.yml's own freshclam-policy note
# ALREADY documents the one-off opt-in path this wires up server-side
# ("docker compose ... exec clamav freshclam") — that compose file
# deliberately disables the background freshclam daemon
# (CLAMAV_NO_FRESHCLAMD=true, safe-default/no-network-by-default) and
# explicitly says "no server API exposes a 'trigger update' action" at the
# time A-17 was built, reasoning that docker-exec access was "a much larger
# attack surface than justified" for that task's own scope. This revisits
# that call now, the same way A-45 revisited A-43's own earlier "never for
# hub updates" position: a real product need (operators asking "are my
# signatures actually current?" with no way to say yes) plus the SAME
# narrow, one-shot, always-human-approved mechanism already proven safe for
# CrowdSec — never a standing/automated capability (see this project's own
# explicit rejection of a SCHEDULED version of this action: an unattended
# trigger would have no human present to approve the OS admin-password
# prompt `elevated_run` always pops, a direct contradiction of "never
# without a human's fresh approval" — "Обновить базы сейчас" is a button,
# deliberately never a cron-like schedule).
#
# Unlike CrowdSec's scenario-threshold write (A-43) or scenario-updates
# apply (A-45), this one performs NO separate mandatory readback comparing
# a written value against a re-read one: freshclam's own behaviour when
# signatures are already current is to exit 0 having changed nothing, which
# is just as legitimate a "success" as actually downloading an update —
# there is no "did the write really take" ambiguity the way a sed-based
# file write has, only "did the command run without error". What this DOES
# do afterward is a fresh, real re-query of clamd's own `VERSION` (the same
# `fetch_av_clamav_data` call `GET /security/consoles/av` itself uses) so
# the operator sees the CURRENT `databases_updated_at` immediately, not the
# stale pre-update value until the next passive page load.
# ---------------------------------------------------------------------------

CLAMAV_CONTAINER_NAME = "hranix-clamav"

# infra/security/clamav/docker-compose.yml's own real path, resolved
# against REPO_ROOT — same reasoning crowdsec.py's own
# `_CROWDSEC_COMPOSE_FILE` docstring already gives (`elevated_run`'s
# underlying osascript/pkexec/UAC mechanisms do not run with this app's own
# CWD).
_CLAMAV_COMPOSE_FILE = REPO_ROOT / "infra" / "security" / "clamav" / "docker-compose.yml"

_DB_UPDATE_REASON_RU = "Hranix Shield: обновить базы сигнатур ClamAV"
_DB_UPDATE_REASON_EN = "Hranix Shield: update ClamAV signature databases"

# Real network fetch against ClamAV's own signature CDN (same class of
# concern crowdsec.py's own `_SCENARIO_UPDATES_ELEVATED_TIMEOUT` documents
# for CrowdSec's hub update) — `elevated_run`'s 120s default was sized
# around purely local docker-exec latency plus human password-entry time,
# not a real download on top of that.
_DB_UPDATE_ELEVATED_TIMEOUT = 300.0

# Real bug found live (2026-08-03): RELOAD's own "RELOADING" response is an
# immediate fire-and-forget ack, not proof the reload has actually
# finished — see `_poll_until_databases_updated_at_changes`'s own
# docstring. 10 attempts * 1.5s = up to 15s of polling after RELOAD, well
# within a real reload's typical completion time for a database this
# size, still bounded (never hangs the HTTP response indefinitely).
_DB_UPDATE_RELOAD_POLL_ATTEMPTS = 10
_DB_UPDATE_RELOAD_POLL_DELAY_SECONDS = 1.5


class ClamAvDbUpdateError(RuntimeError):
    """Raised by `update_clamav_databases` below. `reason` is
    `"elevation_cancelled"`/`"elevation_failed"` — the same two
    `elevated_run()` outcomes every other elevated action in this codebase
    already uses (see elevated.py's own docstring)."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _raise_for_db_update_result(result: ElevatedRunResult) -> None:
    if result.status == "cancelled":
        raise ClamAvDbUpdateError("the user declined the elevation prompt", reason="elevation_cancelled")
    raise ClamAvDbUpdateError(
        f"elevated command failed: {result.stderr.strip() or result.stdout.strip()}",
        reason="elevation_failed",
    )


def _resolve_docker_binary() -> str:
    """This module's own copy of crowdsec.py's identical helper — kept
    separate rather than imported (same "each connector module keeps its
    own copy of small elevated-action helpers" convention crowdsec.py's own
    `_raise_for_scenario_elevated_result` docstring already states, for
    module independence). Resolves `docker`'s absolute path from this
    (unprivileged) process's own PATH before ever building an elevated
    command — `osascript ... with administrator privileges`'s own default
    PATH does not include `/usr/local/bin`, where Docker Desktop's own CLI
    actually lives (confirmed live while building A-36/A-43)."""
    return shutil.which("docker") or "docker"


def _build_db_update_script(docker_binary: str) -> str:
    """The full HOST-side bash script `update_clamav_databases` below runs
    via ONE `elevated_run(["/bin/bash", <this script's path>], ...)` call.
    A single step: `docker exec <container> freshclam` — the exact one-off
    command infra/security/clamav/docker-compose.yml's own freshclam-policy
    note already documents as the supported manual-update path. No restart
    needed afterward (unlike CrowdSec's scenario writes): `freshclam`
    updates the signature files clamd already re-reads from disk on its own
    the moment they change (confirmed by ClamAV's own documented behaviour,
    not something this project's own container config alters), so there is
    no analogous "container never reloads what was written to disk" risk
    A-45's own review found for CrowdSec's scenario updates."""
    docker_quoted = shlex.quote(docker_binary)
    lines = [
        "#!/bin/bash",
        "set -e",
        f"{docker_quoted} exec {CLAMAV_CONTAINER_NAME} freshclam",
        "",
    ]
    return "\n".join(lines)


async def update_clamav_databases(*, settings: Settings | None = None) -> dict[str, Any]:
    """Post-merge user request (2026-08-02): "Обновить базы сейчас" — ONE
    elevated `docker exec` (the same
    one-shot, never-cached, visible OS admin-password prompt every other
    elevated action in this module family already uses), running `freshclam`
    inside the ClamAV container, THEN a plain (non-elevated) `RELOAD` —
    `ClamdClient.reload`'s own docstring already documented this exact
    follow-up step as necessary ("e.g. after an operator has run `docker
    compose exec clamav freshclam` by hand") but this function originally
    skipped it, a real bug found live: `freshclam` only writes new signature
    files to disk, it does not itself tell the ALREADY-RUNNING `clamd`
    process to pick them up — clamd only re-reads its databases on `RELOAD`
    (or its own internal periodic self-check, whose interval this project
    does not control) — so `databases_updated_at` kept reporting the stale
    pre-update value until the operator happened to trigger a reload some
    other way (e.g. clicking "Перечитать базы", or a scan touching it).
    `RELOAD` itself needs no elevation (same plain TCP call the "Перечитать
    базы" button already uses) — only the `docker exec freshclam` step
    above does. Finally, a fresh re-query of clamd's own `VERSION` so the
    response carries the CURRENT `databases_updated_at`.

    Raises `ClamAvDbUpdateError` (`elevation_cancelled`/`elevation_failed`)
    on anything other than a clean `ok` from the elevated step — see this
    section's own module docstring for why there is no `readback_mismatch`
    case here. A RELOAD failure after a successful freshclam is logged, not
    raised: the databases genuinely did update on disk (the elevated step
    already succeeded), a reload hiccup is honestly reflected by the
    readback below simply still showing the old timestamp, not a fabricated
    error about the download itself having failed.

    Real bug found live (2026-08-03): `RELOAD` answers `"RELOADING"` the
    MOMENT clamd starts reloading, not once it has finished (same
    fire-and-forget ack shape as `PING`/`PONG` — see `ClamdClient.reload`'s
    own docstring) — reloading a real signature set is not instant, so a
    readback taken immediately after that ack kept reporting the stale
    pre-update `databases_updated_at` even though the reload was already
    correctly triggered and would have finished moments later. This
    function now POLLS `fetch_av_clamav_data` for a few seconds after
    RELOAD, comparing against the timestamp read BEFORE the update even
    started, and returns as soon as it changes — honestly returning
    whatever the LAST read showed if it never changes within the poll
    window (either a genuinely slow reload, or freshclam genuinely found
    nothing new to install — this function cannot tell those two apart from
    the outside, and does not pretend to)."""
    settings = settings or get_settings()
    docker_binary = _resolve_docker_binary()

    # A-63 follow-up (live finding, 2026-09-21): the bash-script path below
    # is POSIX-only — on Windows `/bin/bash` does not exist, so the button
    # failed instantly with cmd exit 3 «Система не может найти указанный
    # путь» (found live in the installed app's log). On Windows the same
    # single step runs DIRECTLY as the elevated command — `docker exec
    # <container> freshclam` needs no script file, and since the A-63-1
    # follow-up the quoted `C:\Program Files\...` docker path survives
    # cmd's quote-stripping (the /S wrapper). POSIX keeps the script file
    # (shlex-quoting of the docker path matters there).
    if platform.system() == "Windows":
        result = await elevated_run(
            [docker_binary, "exec", CLAMAV_CONTAINER_NAME, "freshclam"],
            reason_ru=_DB_UPDATE_REASON_RU,
            reason_en=_DB_UPDATE_REASON_EN,
            timeout=_DB_UPDATE_ELEVATED_TIMEOUT,
        )
    else:
        script = _build_db_update_script(docker_binary)

        with tempfile.TemporaryDirectory(prefix="hranix-clamav-freshclam-") as tmp:
            script_path = Path(tmp) / "hranix-clamav-freshclam.sh"
            script_path.write_text(script, encoding="utf-8")
            result = await elevated_run(
                ["/bin/bash", str(script_path)],
                reason_ru=_DB_UPDATE_REASON_RU,
                reason_en=_DB_UPDATE_REASON_EN,
                timeout=_DB_UPDATE_ELEVATED_TIMEOUT,
            )
    if result.status != "ok":
        _raise_for_db_update_result(result)

    # The "before" baseline is only worth reading once the elevated step has
    # genuinely succeeded (a cancelled/failed elevation never reaches here,
    # matching the "never reads back after a cancelled/failed elevation"
    # contract this function's tests already pin) — and is safe to read only
    # now rather than at function entry: clamd's in-memory
    # `databases_updated_at` cannot change on its own before RELOAD runs
    # below, so "just before RELOAD" and "at function entry" are equally
    # valid snapshots of the same pre-reload state.
    before = await fetch_av_clamav_data(settings=settings)
    before_databases_updated_at = before.get("databases_updated_at")

    reload_client = create_clamav_client(settings)
    if reload_client is not None:
        try:
            await reload_client.reload()
        except ClamdError:
            logger.warning("clamav: RELOAD after freshclam failed", exc_info=True)

    refreshed = await _poll_until_databases_updated_at_changes(settings, before_databases_updated_at)
    return {
        "status": "ok",
        "databases_updated_at": refreshed["databases_updated_at"],
        "database_version": refreshed["database_version"],
    }


async def _poll_until_databases_updated_at_changes(
    settings: Settings,
    before: str | None,
    *,
    attempts: int = _DB_UPDATE_RELOAD_POLL_ATTEMPTS,
    delay_seconds: float = _DB_UPDATE_RELOAD_POLL_DELAY_SECONDS,
    sleep: Callable[[float], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Re-reads `fetch_av_clamav_data` up to `attempts` times, `delay_seconds`
    apart, stopping as soon as `databases_updated_at` differs from `before`
    — see `update_clamav_databases`'s own docstring for why this polling
    exists at all (RELOAD's ack is fire-and-forget, not "done"). `sleep` is
    the same test-injection seam every scheduler in this codebase already
    uses (defaults to real `asyncio.sleep`), so a unit test can drive every
    attempt instantly rather than waiting the real delay."""
    sleep_fn = sleep or asyncio.sleep
    latest = await fetch_av_clamav_data(settings=settings)
    for _ in range(attempts - 1):
        if latest.get("databases_updated_at") != before:
            return latest
        await sleep_fn(delay_seconds)
        latest = await fetch_av_clamav_data(settings=settings)
    return latest


# ---------------------------------------------------------------------------
# Post-merge user request (2026-08-02): a REAL native OS folder-picker
# dialog for "Проверить папку" (moved from an inline text input into a
# "Управление" button that opens this). Phase 0 has no Tauri/webview and no
# JS-to-native bridge of any kind (CLAUDE.md: "Фаза 0 — ... ВЕБ-панель
# (localhost, без Tauri)"), and a browser's own `<input type="file"
# webkitdirectory>` cannot give this a real absolute filesystem path either
# (browsers deliberately never expose one to page JS, for the same sandbox
# reasons this project's own principles would applaud). The way around
# both: this server process already runs LOCALLY on the operator's own
# machine with full OS access — the exact same fact `elevated.py`'s whole
# design already leans on for admin-password prompts — so it can shell out
# to a real native "choose folder" dialog itself. Unlike `elevated_run()`,
# this needs NO privilege escalation at all (picking a folder is not a
# privileged operation on any OS), so it is a plain subprocess call, not
# routed through `elevated_run`/`osascript ... with administrator
# privileges`.
#
# The path this returns is NOT pre-filtered to `_known_scan_roots()` — no
# OS folder-picker API supports constraining its own navigable tree to an
# arbitrary allowlist, so the operator can browse anywhere. Server-side
# enforcement is unchanged and still the real gate: `run_custom_scan`'s own
# `_is_within_any_root` check (see that function's docstring) runs exactly
# as before on whatever path actually gets submitted — a pick outside
# `~/Downloads`/temp/`$HOME` still comes back as the same honest
# `path_outside_scan_roots` 403 it always has, now just discoverable via a
# real dialog instead of a guess-and-check text field.
# ---------------------------------------------------------------------------


class ClamAvFolderPickError(RuntimeError):
    """Raised by `pick_scan_folder` below. `reason` is one of:
      - `"folder_pick_cancelled"`: the operator dismissed the native dialog
        (clicked Cancel) — not an error, a legitimate, expected outcome.
        Deliberately NOT named `"cancelled"`/`"elevation_cancelled"` — this
        dialog never asked for OS admin privileges at all, so reusing that
        wording would falsely imply a password prompt was declined.
      - `"unsupported_platform"`: no native folder-picker is wired up for
        this OS yet (see the function's own docstring — macOS only today).
      - `"failed"`: the dialog mechanism itself is unavailable, timed out,
        or returned something this function could not parse.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


async def _default_folder_pick_runner(argv: list[str], *, timeout: float) -> tuple[int, str, str]:
    """The real subprocess runner used in production — same
    `asyncio.create_subprocess_exec` + `asyncio.wait_for` shape
    `elevated.py`'s own `_default_runner` already establishes, kept as this
    module's own copy for the same "each connector module keeps its own
    small subprocess helpers" reasoning `_resolve_docker_binary` above
    already documents."""
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=WINDOWS_CREATE_NO_WINDOW,
        )
    except FileNotFoundError as exc:
        raise ClamAvFolderPickError("osascript is not available on this host", reason="failed") from exc

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        raise ClamAvFolderPickError(f"osascript did not return within {timeout}s", reason="failed") from exc

    return (
        process.returncode if process.returncode is not None else 1,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )


async def pick_scan_folder(
    *,
    timeout: float = 120.0,
    runner: Callable[..., Awaitable[tuple[int, str, str]]] | None = None,
) -> str:
    """Pops a real, native "choose a folder" dialog and returns the
    operator's pick as an absolute path string.

    macOS only for now, via `osascript -e 'choose folder'` — the same
    subprocess-invocation technique `elevated.py`'s own `_elevated_run_macos`
    established (`asyncio.create_subprocess_exec`, a bounded `timeout`),
    just without the `with administrator privileges` clause, since choosing
    a folder needs no elevation on any OS. AppleScript's own well-documented
    behaviour for a cancelled `choose folder`/`choose file` dialog is to
    raise error **-128** ("User canceled") — this is standard, stable
    AppleScript behaviour, not something specific to this integration, but
    it has NOT been exercised by an actual live click-Cancel test while
    building this (unlike `elevated_run`'s own macOS path, which was:
    popping this exact dialog to click through it interactively is not
    something an automated verification pass can safely do — it would open
    a real, unexpected window on the operator's own screen — so this
    documents the same honest "not live-verified this one branch" gap
    `elevated.py`'s own docstring already discloses for its Windows/Linux
    paths, just for a different reason here).

    Windows/Linux: raises `ClamAvFolderPickError(reason="unsupported_platform")`
    — an honest "not implemented yet" rather than a silent no-op or a
    fabricated path; the existing text-input fallback the frontend already
    has for other cases (see app.js's handlePickScanFolder) is the
    operator's path forward there today.

    `runner` is the same test-injection seam `elevated.elevated_run`'s own
    `runner` parameter already established — production code never passes
    it (defaults to `_default_folder_pick_runner`, a real subprocess);
    tests inject a fake to exercise every ok/cancelled/failed branch
    without ever popping a real OS dialog.
    """
    system = platform.system()
    if system != "Darwin":
        raise ClamAvFolderPickError(
            f"native folder picker not implemented on {system}", reason="unsupported_platform"
        )
    run = runner or _default_folder_pick_runner

    prompt = "Hranix Shield: выберите папку для проверки / choose a folder to scan"
    applescript = f'POSIX path of (choose folder with prompt "{prompt}")'
    returncode, stdout_text, stderr_text = await run(["osascript", "-e", applescript], timeout=timeout)

    if returncode != 0:
        if "-128" in stderr_text:
            raise ClamAvFolderPickError(
                "the operator cancelled the folder picker", reason="folder_pick_cancelled"
            )
        raise ClamAvFolderPickError(f"osascript failed: {stderr_text.strip()}", reason="failed")

    path = stdout_text.strip()
    if not path:
        raise ClamAvFolderPickError("osascript returned an empty path", reason="failed")
    return path
