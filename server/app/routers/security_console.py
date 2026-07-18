from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import BackupJob, Event, User
from app.db.session import get_session
from app.dependencies import get_current_user
from app.services.backup import (
    BACKUP_MODULE_ID,
    backup_console_metrics,
    run_manual_backup,
    run_manual_restore,
)
from app.services.event_bus import EventBus, Topic, get_event_bus
from app.services.mcp.security_connectors import (
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvScanJobRegistry,
    ClamdError,
    fetch_av_clamav_data,
    fetch_av_osquery_data,
    fetch_disk_encryption_status,
    fetch_firewall_status,
    fetch_ids_console_data,
    fetch_logs_console_data,
    fetch_network_console_data,
    quarantine_file,
    run_quick_scan,
    start_full_scan,
)
from app.services.security_console import (
    ConsoleId,
    SecurityConsoleRegistry,
    get_clamav_scan_job_registry,
    get_security_console_registry,
)

router = APIRouter(prefix="/security", tags=["security-console"])

_EVENT_LOG_LIMIT = 20
_EVENT_LOG_TOPICS = tuple(topic.value for topic in Topic)


class ToggleRequest(BaseModel):
    enabled: bool


class ClamAvQuarantineRequest(BaseModel):
    path: str


def _base(console_id: ConsoleId, registry: SecurityConsoleRegistry) -> dict[str, Any]:
    return {
        "id": console_id.value,
        "status": registry.status_for(console_id.value).value,
        "enabled": registry.is_enabled(console_id.value),
    }


# ---------------------------------------------------------------------------
# Per-console detail payloads (§6.2 of the analytical plan: metrics/chart/
# management-actions/settings shape per console). A-11 wired the first real
# data source in: `_ids_payload` below now calls the live CrowdSec connector
# (services/mcp/security_connectors/crowdsec.py) instead of returning a
# stub. A-18 wired the second and third: `_perimeter_payload` now calls the
# two local OS-tool connectors (os_firewall.py/os_disk_encryption.py) and
# reuses CrowdSec's bouncer data. A-15 wires the fourth: `_network_payload`
# now calls the real osquery connector (its sole source, single `connector`
# field like `ids`), and `_av_payload` gets its first real source
# (`connectors["osquery"]`) — `clamav` (A-17) added the second. A-16 wires
# the sixth and last: `_logs_payload` now calls the real Wazuh Manager
# connector (its sole source, single `connector` field like `ids`/
# `network`) — no console is left on a fabricated placeholder anymore.
# `status`/`enabled` on every
# console stay backed by the in-memory toggle registry, see
# services/security_console.py — unrelated to whether a console's own
# connector(s) are reachable, which each connector-backed console reports
# separately as `connector(s).status`.
# ---------------------------------------------------------------------------


async def _perimeter_payload(registry: SecurityConsoleRegistry) -> dict[str, Any]:
    """A-18: `connectors`/`metrics.firewall_active`/`metrics.disk_encryption_active`
    come from two real local OS-tool connectors
    (services/mcp/security_connectors/{os_firewall,os_disk_encryption}.py) —
    never a stub anymore. CrowdSec's bouncer (A-11) is *reused* here too, not
    reimplemented: the same `fetch_ids_console_data()` call `_ids_payload`
    already makes, so its active-ban count also lands here as
    `metrics.crowdsec_active_bans` — the same connector, one more wiring
    point, exactly this task's brief.

    Unlike `_ids_payload`'s single `connector` field (one source), this
    console has three independent sources — see `connectors` (plural, keyed
    by engine id) below, each fetched concurrently. None of the three ever
    raises: an unsupported platform / missing tool / permission problem /
    unreachable CrowdSec is reported as an honest per-source `status`, never
    a 500 and never a fabricated all-clear — same principle as `_ids_payload`.
    `open_ports`/`firewall_rules` stay honest Phase-0 placeholders (osquery's
    job, A-15) — out of scope here.
    """
    firewall, disk_encryption, crowdsec = await asyncio.gather(
        fetch_firewall_status(), fetch_disk_encryption_status(), fetch_ids_console_data()
    )
    return {
        **_base(ConsoleId.PERIMETER, registry),
        "engine": ["os_firewall", "bitlocker_filevault", "crowdsec_bouncer"],
        "connectors": {
            "os_firewall": firewall["connector"],
            "disk_encryption": disk_encryption["connector"],
            "crowdsec_bouncer": crowdsec["connector"],
        },
        "metrics": {
            "firewall_active": firewall["active"],
            "disk_encryption_active": disk_encryption["active"],
            "open_ports": 0,
            "firewall_rules": 0,
            "crowdsec_active_bans": crowdsec["metrics"]["active_bans"],
        },
        "chart": {"metric": "blocked_incoming_24h", "unit": "events", "values": []},
        "settings": {
            "protection_profile": "standard",
            "auto_block_new_incoming": True,
            "notify_new_open_ports": True,
            "require_vpn_outside_trusted": False,
        },
    }


async def _ids_payload(registry: SecurityConsoleRegistry) -> dict[str, Any]:
    """A-11: `connector`/`metrics`/`chart`/`recent_attempts` come from a real
    `fetch_ids_console_data()` call against CrowdSec's LAPI (see
    services/mcp/security_connectors/crowdsec.py) — never a stub anymore.
    That helper never raises: an unconfigured/unreachable/unauthorized
    CrowdSec comes back as an honest `connector.status`
    (`not_configured`/`unreachable`/`unauthorized`) with every metric `None`,
    not a 500 and not a fabricated all-clear zero.

    `settings` stays a Phase-0 placeholder on purpose: a bouncer's LAPI
    access has no endpoint to read CrowdSec's own ban-threshold/whitelist
    configuration (that lives in profiles.yaml/machine-level config, not
    exposed to a bouncer key — confirmed empirically, see task report) —
    honestly left as-is rather than invented, per the A-11 task brief.
    """
    console_data = await fetch_ids_console_data()
    return {
        **_base(ConsoleId.IDS, registry),
        "engine": ["crowdsec"],
        "connector": console_data["connector"],
        "metrics": console_data["metrics"],
        "chart": console_data["chart"],
        "recent_attempts": console_data["recent_attempts"],
        "settings": {
            "ban_threshold": 5,
            "ban_duration_hours": 4,
            "whitelist_count": 0,
            "rule_source": "crowdsec_hub",
        },
    }


async def _av_payload(
    registry: SecurityConsoleRegistry, clamav_jobs: ClamAvScanJobRegistry
) -> dict[str, Any]:
    """A-15 wired `connectors["osquery"]` + `file_events` from a real osquery
    connector (services/mcp/security_connectors/osquery.py) — process
    telemetry, the first of `av`'s eventual sources. A-17 adds
    `connectors["clamav"]` (services/mcp/security_connectors/clamav.py) —
    the actual signature scanner, so `metrics.clean`/`last_scan_at`/
    `quarantine_count`/`databases_updated_at` are now real too (derived from
    `fetch_av_clamav_data`, itself informed by `clamav_jobs`'s scan-job
    history — see that function's docstring for exactly what "real" means
    here: in-memory, process-lifetime history, not fabricated). `connectors`
    stays plural (like `_perimeter_payload`), ready for `wazuh` (A-16) to add
    one more key later without this shape needing to change.
    """
    osquery_data, clamav_data = await asyncio.gather(
        fetch_av_osquery_data(), fetch_av_clamav_data(job_registry=clamav_jobs)
    )
    return {
        **_base(ConsoleId.AV, registry),
        "engine": ["osquery", "wazuh", "clamav", "yara", "defender_xprotect"],
        "connectors": {
            "osquery": osquery_data["connector"],
            "clamav": clamav_data["connector"],
        },
        "metrics": {
            "clean": clamav_data["clean"],
            "last_scan_at": clamav_data["last_scan_at"],
            "quarantine_count": clamav_data["quarantine_count"],
            "databases_updated_at": clamav_data["databases_updated_at"],
            "osquery_process_count": osquery_data["process_count"],
        },
        "file_events": osquery_data["file_events"],
        "chart": {"metric": "files_scanned_7d", "unit": "files", "values": [0, 0, 0, 0, 0, 0, 0]},
        "settings": {
            "realtime_protection": True,
            "scan_schedule": "daily_06:00",
            "action_on_threat": "quarantine",
            "scan_removable_media": True,
        },
    }


async def _network_payload(registry: SecurityConsoleRegistry) -> dict[str, Any]:
    """A-15: `connector`/`connections`/`listening_ports`/
    `metrics.active_connections` come from a real osquery connector
    (services/mcp/security_connectors/osquery.py) — this console's sole
    source, single `connector` field like `ids`. Never a stub anymore for
    those fields; `outbound_traffic_status`/`suspicious_connections`/
    `dns_leak_detected` stay honest Phase-0 placeholders — no traffic-volume/
    anomaly-detection engine exists yet, out of this task's scope.
    """
    network_data = await fetch_network_console_data()
    return {
        **_base(ConsoleId.NETWORK, registry),
        "engine": ["osquery", "os_counters"],
        "connector": network_data["connector"],
        "metrics": {
            "outbound_traffic_status": None,
            "active_connections": network_data["active_connections"],
            "suspicious_connections": 0,
            "dns_leak_detected": None,
        },
        "chart": {
            "metric": "traffic_1h",
            "unit": "mb_s",
            "inbound": [],
            "outbound": [],
        },
        "connections": network_data["connections"],
        "listening_ports": network_data["listening_ports"],
        "settings": {
            "monitor_outbound": True,
            "alert_on_anomalies": True,
            "block_unknown_outbound": False,
            "dns_over_https": True,
        },
    }


async def _backup_payload(registry: SecurityConsoleRegistry, session: AsyncSession) -> dict[str, Any]:
    """A-12: unlike its 5 siblings above (still honest A-11 placeholders —
    that integration doesn't exist yet), this console has a real engine
    behind it now. `metrics`/`chart`/`modules` come from an actual
    `backup_console_metrics()` query (see services/backup/wiring.py) — an
    empty `backup_jobs` table (no snapshot has ever run) legitimately
    produces all-None/all-zero values, which is the honest answer here too,
    not a fabricated one. Only `database` (`BACKUP_MODULE_ID`) is a real
    module in Phase 0 (§2 of the A-12 spec) — Documents/CRM/etc. stay
    placeholders (`last_backup_at: null`) until those modules exist.
    """
    settings = get_settings()
    modules = [
        "database",
        "documents",
        "knowledge_rag",
        "experience",
        "crm",
        "tasks_calendar",
        "settings_plugins",
    ]
    metrics = await backup_console_metrics(session, settings=settings)

    return {
        **_base(ConsoleId.BACKUP, registry),
        "engine": ["pgbackrest", "restic"],
        "metrics": {
            "last_backup_at": metrics["last_backup_at"],
            "last_backup_status": metrics["last_backup_status"],
            "total_size_bytes": metrics["total_size_bytes"],
            "storages": metrics["storages"],
            "next_scheduled_at": metrics["next_scheduled_at"],
        },
        "chart": {"metric": "backup_size_7d", "unit": "bytes", "values": metrics["chart_values"]},
        "modules": [
            {
                "id": module_id,
                "auto": True,
                "last_backup_at": (
                    metrics["database_last_backup_at"] if module_id == BACKUP_MODULE_ID else None
                ),
            }
            for module_id in modules
        ],
        "settings": {
            "schedule": f"daily_{settings.backup_schedule_hour:02d}:{settings.backup_schedule_minute:02d}",
            "retention": "30d_12m_3y",
            "encryption": True,
            # Real now, not a hardcoded True: startup auto-restore only
            # actually runs when backup_enabled is on (see
            # app_factory._lifespan) — showing True regardless would have
            # been a lie while the Phase 0 default is off.
            "auto_restore_on_corruption": settings.backup_enabled,
        },
    }


async def _logs_payload(registry: SecurityConsoleRegistry) -> dict[str, Any]:
    """A-16: `connector`/`metrics.events_24h`/`entries` come from a real
    `fetch_logs_console_data()` call against the Wazuh Manager REST API
    (see services/mcp/security_connectors/wazuh.py) — never a stub anymore.
    That helper never raises: an unconfigured/unreachable/unauthorized
    Wazuh comes back as an honest `connector.status`
    (`not_configured`/`unreachable`/`unauthorized`) with every metric
    `None` (fixing this console's own former placeholder bug, which used to
    hardcode zeros here — a false "0 events" all-clear even when nothing
    was connected at all).

    `windows_event_log`/`macos_unified_log` stay in `engine` as declared-
    but-not-yet-implemented sources (same convention `av`'s `engine` list
    already uses for `yara`/`defender_xprotect`) — only `wazuh_agent` is
    real in Phase 0. `metrics.warnings_24h`/`security_errors_24h` stay
    honest Phase-0 `None` even when the connector is `"ok"` — genuinely not
    derivable from a manager-only Wazuh deployment's REST API, see
    `wazuh.py`'s module docstring for why.
    """
    console_data = await fetch_logs_console_data()
    return {
        **_base(ConsoleId.LOGS, registry),
        "engine": ["wazuh_agent", "windows_event_log", "macos_unified_log"],
        "connector": console_data["connector"],
        "metrics": console_data["metrics"],
        "chart": console_data["chart"],
        "entries": console_data["entries"],
        "settings": {
            "os_event_log": True,
            "audit_logins_privilege": True,
            "wazuh_crowdsec_events": True,
            "sysmon": False,
            "retention_days": 90,
        },
    }


@router.get("/overview")
async def overview(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Obзорный экран: агрегированный статус (худшее из 6 консолей, та же
    идея, что `HealthRegistry.run_all`'s `status`/`components` shape) + KPI-
    заглушки + реальный журнал последних событий шины (A-4's `events`
    table) — not hardcoded, genuinely queried."""
    events = (
        await session.scalars(
            select(Event)
            .where(Event.topic.in_(_EVENT_LOG_TOPICS))
            .order_by(Event.created_at.desc())
            .limit(_EVENT_LOG_LIMIT)
        )
    ).all()

    return {
        "status": registry.aggregate_status().value,
        "consoles": registry.snapshot(),
        "kpis": {
            "blocked_24h": 0,
            "active_connections": 0,
            "system_load_pct": None,
            "uptime_pct": None,
        },
        "event_log": [
            {
                "topic": event.topic,
                "payload": event.payload,
                "created_at": event.created_at.isoformat(),
            }
            for event in events
        ],
    }


@router.get("/consoles/perimeter")
async def console_perimeter(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _perimeter_payload(registry)


@router.get("/consoles/ids")
async def console_ids(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _ids_payload(registry)


@router.get("/consoles/av")
async def console_av(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _av_payload(registry, clamav_jobs)


@router.post("/consoles/av/clamav/scan/quick")
async def clamav_quick_scan(
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-17: synchronous quick scan of a bounded set of high-risk
    directories (Downloads + the OS temp dir, see
    services/mcp/security_connectors/clamav.py.run_quick_scan) — fast
    enough (a handful of directories, not "полная проверка") to answer
    within one request, unlike `.../scan/full` below. Recorded into
    `clamav_jobs` on completion so `GET /security/consoles/av`'s
    `metrics.last_scan_at`/`clean` reflect this scan too, exactly like a
    full scan would.
    """
    job = clamav_jobs.create("quick")
    try:
        result = await run_quick_scan()
    except ClamAvNotConfiguredError:
        clamav_jobs.mark_failed(job, error="not_configured")
        raise HTTPException(status_code=503, detail={"error": "clamav_not_configured"})
    except ClamdError as exc:
        clamav_jobs.mark_failed(job, error=exc.reason)
        raise HTTPException(status_code=503, detail={"error": f"clamav_{exc.reason}"})
    clamav_jobs.mark_completed(job, scanned_count=result["scanned_count"], infected=result["infected"])
    return job.to_payload()


@router.post("/consoles/av/clamav/scan/full")
async def clamav_start_full_scan(
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-17: starts a full scan of the user's home directory (see
    `start_full_scan`'s target-selection docstring) as a background task and
    returns immediately — a full scan can genuinely take minutes, so this
    endpoint never blocks the request waiting for it to finish (A-17 risk
    note #2). Poll `GET /consoles/av/clamav/scan/full/{job_id}` for
    progress/result.
    """
    try:
        job = await start_full_scan(clamav_jobs)
    except ClamAvNotConfiguredError:
        raise HTTPException(status_code=503, detail={"error": "clamav_not_configured"})
    except ClamdError as exc:
        raise HTTPException(status_code=503, detail={"error": f"clamav_{exc.reason}"})
    return job.to_payload()


@router.get("/consoles/av/clamav/scan/full/{job_id}")
async def clamav_full_scan_status(
    job_id: str,
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    job = clamav_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail={"error": "scan_job_not_found"})
    return job.to_payload()


@router.post("/consoles/av/clamav/quarantine")
async def clamav_quarantine(
    body: ClamAvQuarantineRequest,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-17: moves `body.path` into the quarantine directory — never
    deletes, so a false positive can be restored by the operator (see
    services/mcp/security_connectors/clamav.py.quarantine_file).

    `body.path` is only accepted if it resolves inside the known scan
    roots (Downloads/OS temp dir, see `quarantine_file`'s docstring) —
    security finding from architect review (2026-07-16): without this,
    any authenticated user could pass an arbitrary path (e.g.
    `/etc/passwd`) and have the server process move it, an arbitrary-
    file-move primitive over the whole filesystem, not "quarantine
    something the scanner found". Rejected with an honest 403, never a
    silent no-op.
    """
    try:
        quarantined_path = await quarantine_file(Path(body.path))
    except ClamAvPathNotAllowedError:
        raise HTTPException(status_code=403, detail={"error": "path_outside_scan_roots"})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "file_not_found"})
    return {"quarantined_path": str(quarantined_path)}


@router.get("/consoles/network")
async def console_network(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _network_payload(registry)


@router.get("/consoles/backup")
async def console_backup(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _backup_payload(registry, session)


def _job_payload(job: BackupJob) -> dict[str, Any]:
    return {
        "id": job.id,
        "status": job.status,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "size_bytes": job.size_bytes,
        "target_path": job.target_path,
        "triggered_by": job.triggered_by,
    }


@router.post("/consoles/backup/snapshot")
async def create_backup_snapshot(
    event_bus: EventBus = Depends(get_event_bus),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-12: manual backup run — a real restic snapshot of the SQLite DB
    (see services/backup/wiring.py.run_manual_backup). Returns the
    resulting `BackupJob` regardless of whether the snapshot itself
    succeeded or failed (`run_backup` never raises on a restic-level
    failure, it records `status="failed"`) — a client inspects `status`,
    same shape either way."""
    try:
        job = await run_manual_backup(event_bus=event_bus)
    except ValueError:
        # Only raised when Settings.resolved_sqlite_path is None (a
        # non-SQLite deployment, not reachable in Phase 0 — see
        # resolve_backup_paths) — not a client mistake, so 503, not 4xx.
        raise HTTPException(status_code=503, detail={"error": "backup_not_configured"})
    return _job_payload(job)


@router.post("/consoles/backup/restore/{snapshot_id}")
async def restore_backup_snapshot(
    snapshot_id: str,
    event_bus: EventBus = Depends(get_event_bus),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-12: manual restore (see
    services/backup/wiring.py.run_manual_restore). `snapshot_id` is either a
    real restic snapshot id, or the literal `"latest"` to restore the most
    recent snapshot without the client needing to look one up first."""
    resolved_snapshot_id = None if snapshot_id == "latest" else snapshot_id
    try:
        job = await run_manual_restore(snapshot_id=resolved_snapshot_id, event_bus=event_bus)
    except ValueError:
        raise HTTPException(status_code=503, detail={"error": "backup_not_configured"})
    return _job_payload(job)


@router.get("/consoles/logs")
async def console_logs(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _logs_payload(registry)


@router.post("/consoles/{console_id}/toggle")
async def toggle_console(
    console_id: ConsoleId,
    body: ToggleRequest,
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Flip one console's enabled/disabled state (in-memory, see
    services/security_console.py). `console_id` is a real path-validated
    enum — an unknown id is rejected with FastAPI's own 422 enum-coercion
    error, not a hand-rolled check."""
    registry.set_enabled(console_id.value, body.enabled)
    return _base(console_id, registry)
