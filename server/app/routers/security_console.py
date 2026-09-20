from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, NoReturn

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import BackupJob, Event, MetricSample, User
from app.db.session import get_session
from app.dependencies import get_current_user, require_role
from app.services.backup import (
    BACKUP_MODULE_ID,
    backup_console_metrics,
    run_manual_backup,
    run_manual_restore,
)
from app.services.event_bus import EventBus, Topic, get_event_bus
from app.services.av import AvScheduleSettings, get_av_settings, update_av_settings
from app.services.mcp.security_connectors import (
    ClamAvDbUpdateError,
    ClamAvFolderPickError,
    ClamAvNotConfiguredError,
    ClamAvPathNotAllowedError,
    ClamAvQuarantineNotFoundError,
    ClamAvRestoreConflictError,
    ClamAvScanJobRegistry,
    ClamdError,
    CrowdSecAllowlistError,
    CrowdSecError,
    CrowdSecNotConfiguredError,
    CrowdSecScenarioError,
    OSFirewallError,
    OSProcessError,
    WazuhError,
    WazuhNotConfiguredError,
    add_to_allowlist,
    apply_scenario_updates,
    ban_ip,
    block_all_incoming,
    block_ip,
    block_port,
    check_scenario_updates,
    country_centroid,
    create_clamav_client,
    delete_blocked_ip,
    delete_blocked_port,
    fetch_active_decision_values,
    fetch_allowlists,
    fetch_av_clamav_data,
    fetch_av_osquery_data,
    fetch_disk_encryption_status,
    fetch_firewall_rules,
    fetch_firewall_status,
    fetch_ids_console_data,
    fetch_listening_ports,
    fetch_logs_console_data,
    fetch_network_console_data,
    fetch_traffic_counters,
    ip_matches_any_decision,
    is_geoip_configured,
    list_blocked_ips,
    list_blocked_ports,
    list_quarantine_entries,
    list_scan_history,
    pick_scan_folder,
    quarantine_file,
    read_firewall_rules,
    read_scenario_thresholds,
    record_blocked_ip,
    record_blocked_port,
    record_scan_history,
    remove_from_allowlist,
    resolve_country,
    restore_quarantine_file,
    run_custom_scan,
    run_quick_scan,
    start_full_scan,
    terminate_process,
    trigger_syscheck_scan,
    unban_decision,
    unblock_all_incoming,
    unblock_ip,
    unblock_port,
    update_clamav_databases,
    write_scenario_threshold,
)
from app.services.mcp.security_connectors.network_profile import (
    detect_current_network,
    network_profile_payload,
    set_network_category,
)
from app.services.mcp.security_connectors.traffic_counters import TrafficCounterRegistry
from app.services.metrics import (
    METRIC_ACTIVE_BANS_COMMUNITY,
    METRIC_ACTIVE_BANS_LOCAL,
    METRIC_ACTIVE_CONNECTIONS,
    METRIC_EVENTS_24H,
    METRIC_QUARANTINE_COUNT,
    IDS_CONSOLE_ID,
    NETWORK_CONSOLE_ID,
    chart_values_7d,
)
from app.services.security_console import (
    ConsoleId,
    SecurityConsoleRegistry,
    get_clamav_scan_job_registry,
    get_security_console_registry,
    get_traffic_counter_registry,
)
from app.services.security_console_export import export_filename, export_rows
from app.services.stack import run_stack_bootstrap, stack_status

router = APIRouter(prefix="/security", tags=["security-console"])

_EVENT_LOG_LIMIT = 20
_EVENT_LOG_TOPICS = tuple(topic.value for topic in Topic)


class ToggleRequest(BaseModel):
    enabled: bool


class ClamAvQuarantineRequest(BaseModel):
    path: str
    # A-27: optional — a caller that already knows the detected signature
    # (e.g. quarantining a file straight out of a just-completed scan's
    # `infected[]` list) can attach it here so `GET .../quarantine` can show
    # it later. Honestly `None` when quarantining a merely-suspected file
    # with no scan-confirmed verdict yet (see `quarantine_file`'s docstring
    # — never guessed).
    reason: str | None = None


class ClamAvCustomScanRequest(BaseModel):
    """A-33: body for `POST /consoles/av/clamav/scan/custom` — `path` is
    validated by `run_custom_scan` against the known scan roots (see that
    function's docstring), never accepted as an arbitrary filesystem path."""

    path: str


class PerimeterBlockPortRequest(BaseModel):
    """A-37: optional per-port context the client already has on hand —
    exactly the `protocol`/`process_name` fields the `ports` list row the
    operator clicked already carries (see `app.js`'s `openPortModal`/
    `handleBlockPort`, and `osquery.fetch_listening_ports`'s own row
    shape) — attached to the persisted `blocked_ports` row purely for
    later display (see `BlockedPort`'s own docstring), never re-validated
    against a fresh osquery query here: this endpoint's whole job is the
    one-shot elevated block action, not a second port-list read. Both
    fields (and the body itself) are optional — a bare `POST` with no body
    still blocks the port, just without the descriptive context."""

    protocol: str | None = None
    process_name: str | None = None


class NetworkBlockIpRequest(BaseModel):
    """A-52: optional per-IP context the client already has on hand from
    the connections table row it was clicked from (`app.js`'s
    `openConnectionModal`/`handleBlockIp`) — same "descriptive, never
    re-validated, purely for later display" shape as
    `PerimeterBlockPortRequest` above. `reason` is new here (not on the
    port-block request): the connection modal's own honest note of why
    (e.g. "Подозрительный узел (CrowdSec)" when `is_suspicious` was true
    on the row blocked)."""

    country: str | None = None
    process_name: str | None = None
    reason: str | None = None


class NetworkTerminateProcessRequest(BaseModel):
    """A-52: `process_name` is REQUIRED (unlike every other optional
    display-only body above) — it is not decoration, it is the exact
    identity `terminate_process()` re-checks against the real process
    table immediately before signalling anything (see
    `os_processes.py`'s own module docstring for the full "why", point 3).
    A request with no `process_name` at all cannot safely proceed and is
    rejected by FastAPI's own validation (422) before this code ever
    runs — there is no reasonable default to fall back to for a check
    whose entire point is refusing to guess."""

    process_name: str


class NetworkCategoryRequest(BaseModel):
    """A-38: body for `POST /consoles/perimeter/network-profile/category` —
    `category` only, never `network_key`: the endpoint always re-detects
    the CURRENT network itself (same "server is the source of truth for
    what IS the current network" discipline as every other perimeter
    action in this router), never trusts a client-supplied identity."""

    category: Literal["trusted", "public"]


class ConsoleExportRequest(BaseModel):
    """A-30: request body for the universal `/consoles/export` endpoint —
    `rows` is exactly what the client already has rendered (`entries` for
    `logs`, `connections` for `network`, see app.js's `handleExportLog`),
    `console_id` is only used to build a readable filename (never re-used to
    re-fetch/validate anything server-side, see that endpoint's docstring
    for why it deliberately does not)."""

    console_id: str
    format: Literal["csv", "json"] = "csv"
    rows: list[dict[str, Any]]


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


async def _perimeter_payload(registry: SecurityConsoleRegistry, session: AsyncSession) -> dict[str, Any]:
    """A-18: `connectors`/`metrics.firewall_active`/`metrics.disk_encryption_active`
    come from two real local OS-tool connectors
    (services/mcp/security_connectors/{os_firewall,os_disk_encryption}.py) —
    never a stub anymore. CrowdSec's bouncer (A-11) is *reused* here too, not
    reimplemented: the same `fetch_ids_console_data()` call `_ids_payload`
    already makes, so its active-ban count also lands here as
    `metrics.crowdsec_active_bans` — the same connector, one more wiring
    point, exactly this task's brief. Post-merge user question
    (2026-07-31): `metrics.active_bans_local`/`active_bans_community` now
    ALSO surface here (the exact same honest split A-23 already computes
    for `ids`) — the current, right-now number, not just the two chart
    series above; a user opening this console should see at a glance
    "0 local, protection is working" without waiting on 7-day history.

    A-28 wires the two metrics A-18 had honestly left as placeholders:
    `open_ports` now comes from `osquery.fetch_listening_ports()` — the
    exact same `listening_ports` query `network` already runs (see that
    module's docstring), not a second implementation — and `firewall_rules`
    from `os_firewall.fetch_firewall_rules()`, a *different* pf/netsh/
    iptables invocation than `fetch_firewall_status()` above (listing the
    ruleset, not the on/off toggle) with its own, independently-failing
    permission requirement — confirmed live on this dev machine (macOS):
    `pfctl -s rules` genuinely needs root where `socketfilterfw
    --getglobalstate` (the toggle) does not, so this needed its own
    `connectors` entry rather than reusing `os_firewall`'s.

    Five independent sources now — see `connectors` (plural, keyed by
    engine id) below, each fetched concurrently. None of the five ever
    raises: an unsupported platform / missing tool / permission problem /
    unreachable CrowdSec is reported as an honest per-source `status`, never
    a 500 and never a fabricated all-clear — same principle as `_ids_payload`.

    A-26: `chart.values` is now real last-7-days history of
    `metrics.crowdsec_active_bans` (see services/metrics/chart.py), sampled
    every `Settings.metrics_sample_interval_seconds` by
    services/metrics/sampler.py — an empty list means "not enough history
    yet" (fresh install / CrowdSec only just configured), not "chart
    unimplemented". `open_ports`/`firewall_rules` are deliberately NOT
    sampled even though A-28 made them real numbers: sampler.py's own
    docstring only samples fields already displayed as a console-level
    "current state" metric, and these two only became that with A-28 —
    out of scope for this task to also backfill into the sampler.

    Post-merge user question (2026-07-31): a single summed bar (local +
    community) reads as "this many things happened on my machine" when in
    practice almost all of it is CrowdSec's shared worldwide blocklist —
    the exact "real number, misleading label" trap A-23 already fixed for
    `ids`'s own metric tiles, just not carried over to this chart. `chart`
    below is now TWO series instead of one: `values_community` (this
    console's own new `active_bans_community` sample, see sampler.py) and
    `values_local` — deliberately READ from `ids`'s own already-sampled
    `(console_id="ids", metric="active_bans_local")` history rather than a
    second, duplicate sample of the same real fact under a second
    console_id (same "one connector, reused" spirit the module docstring
    above already states for the old combined number). `app.js`'s
    `renderConsoleChart` draws these as paired bars per day with a
    two-colour legend — `chart.values` (singular, old shape) is gone for
    this console; every OTHER console's chart is untouched, still the
    single-series shape.

    A-31: `ports` (top-level, alongside `metrics`/`connectors` — same
    placement `network`'s own `connections`/`listening_ports` already use,
    not nested inside `metrics` since it is a list of rows, not a scalar)
    is `osquery.fetch_listening_ports()`'s new deduplicated row list — the
    per-port process/pid/protocol detail this console's `open_ports` metric
    always summarized into a bare count, now shown alongside it so the user
    can see WHICH ports (and whose process), not just how many (this task's
    own brief, and the user complaint that prompted it: "31 — а какие,
    кем?").

    A-37: each row in `ports` now also carries `is_blocked` — `True` when
    that exact port number has a row in the persistent `blocked_ports`
    table (see `os_firewall.list_blocked_ports`), i.e. `block_port()` was
    already applied for it and never subsequently undone by
    `unblock_port()`. This is what lets the port-detail modal
    (`app.js`'s `openPortModal`) show the right state — and disable the
    matching one of «Блокировать»/«Разблокировать» — without a second,
    separate request. `list_blocked_ports(session)` is deliberately
    awaited on its own, BEFORE the `asyncio.gather` below rather than
    inside it: `chart_values_7d(session, ...)` already uses this same
    request's `session` inside that gather, and `AsyncSession` does not
    support two concurrently-in-flight statements on one session instance
    — interleaving a second session-using coroutine into the same gather
    would risk exactly that "this session is already in use" failure.

    A-38 adds `network_profile` — a NEW top-level key (deliberately NOT
    folded into `connectors` above: "which network am I on" is not one of
    this console's protection TOOLS the way os_firewall/CrowdSec/osquery
    are, it is its own independent kind of context, see
    network_profile.py's own docstring), a pure read of the current
    network + its persisted category (`network_profile.
    network_profile_payload`) — never writes to the DB itself, see that
    function's own docstring for why (only the background scheduler's own
    tick, or the operator's explicit category-assignment click below,
    ever persist a sighting). Fetched SEQUENTIALLY after the `asyncio.gather`
    below, not folded into it — same reasoning as A-37's `list_blocked_ports`
    above, just on the other side of the gather instead of before it: none
    of `list_blocked_ports` (before), `chart_values_7d` (inside the gather),
    and `network_profile_payload` (after) ever overlap in-flight on this one
    `session`, so this stays the one safe sequential pattern already
    established by A-26 rather than a second, concurrent session user.
    """
    blocked_rows = await list_blocked_ports(session)
    firewall, disk_encryption, crowdsec, ports, firewall_rules = await asyncio.gather(
        fetch_firewall_status(),
        fetch_disk_encryption_status(),
        fetch_ids_console_data(),
        fetch_listening_ports(),
        fetch_firewall_rules(),
    )
    # Sequential, not folded into the gather above: both read the same
    # `session`, and AsyncSession does not support two concurrently
    # in-flight statements on one instance — same reasoning already
    # documented for `list_blocked_ports` above / `network_profile_payload`
    # below.
    community_chart_values = await chart_values_7d(
        session, console_id=ConsoleId.PERIMETER.value, metric=METRIC_ACTIVE_BANS_COMMUNITY
    )
    local_chart_values = await chart_values_7d(
        session, console_id=ConsoleId.IDS.value, metric=METRIC_ACTIVE_BANS_LOCAL
    )
    network_profile = await network_profile_payload(session)
    blocked_port_numbers = {row.port for row in blocked_rows}
    ports_with_block_state = [
        {**port_row, "is_blocked": port_row["port"] in blocked_port_numbers} for port_row in ports["ports"]
    ]
    return {
        **_base(ConsoleId.PERIMETER, registry),
        "engine": ["os_firewall", "bitlocker_filevault", "crowdsec_bouncer", "osquery", "network_profile"],
        "connectors": {
            "os_firewall": firewall["connector"],
            "disk_encryption": disk_encryption["connector"],
            "crowdsec_bouncer": crowdsec["connector"],
            "osquery": ports["connector"],
            "firewall_rules": firewall_rules["connector"],
        },
        "metrics": {
            "firewall_active": firewall["active"],
            "disk_encryption_active": disk_encryption["active"],
            "open_ports": ports["open_ports"],
            "firewall_rules": firewall_rules["count"],
            "crowdsec_active_bans": crowdsec["metrics"]["active_bans"],
            # Замечание пользователя (2026-07-31): текущее число прямо
            # сейчас, не только 7-дневная история — тот же честный split
            # A-23 уже вычисляет для ids, просто до сих пор не всплывал
            # плиткой на этой консоли (только суммой в chart). None
            # означает "не проверялось" (CrowdSec не настроен/недоступен),
            # тот же контракт, что и у `crowdsec_active_bans` выше.
            "active_bans_local": crowdsec["metrics"]["active_bans_local"],
            "active_bans_community": crowdsec["metrics"]["active_bans_community"],
        },
        "chart": {
            "metric": "crowdsec_active_bans_7d",
            "unit": "count",
            "values_community": community_chart_values,
            "values_local": local_chart_values,
        },
        "ports": ports_with_block_state,
        "network_profile": network_profile,
        "settings": {
            "protection_profile": "standard",
            "auto_block_new_incoming": True,
            "notify_new_open_ports": True,
            "require_vpn_outside_trusted": False,
        },
    }


async def _ids_payload(registry: SecurityConsoleRegistry, session: AsyncSession) -> dict[str, Any]:
    """A-11: `connector`/`metrics`/`recent_attempts` come from a real
    `fetch_ids_console_data()` call against CrowdSec's LAPI (see
    services/mcp/security_connectors/crowdsec.py) — never a stub anymore.
    That helper never raises: an unconfigured/unreachable/unauthorized
    CrowdSec comes back as an honest `connector.status`
    (`not_configured`/`unreachable`/`unauthorized`) with every metric `None`,
    not a 500 and not a fabricated all-clear zero.

    A-26: `chart.values` is real last-7-days history of
    `metrics.active_bans_local` (services/metrics/chart.py) — deliberately
    NOT read off `console_data` anymore (that connector no longer returns a
    `chart` key at all, see crowdsec.py's docstring): this console's
    history now comes exclusively from the metric_samples table, so it
    survives even a moment where CrowdSec itself is temporarily
    unreachable (yesterday's real samples are still real).

    A-42: `settings` used to carry four A-11 placeholders
    (`ban_threshold: 5`, `ban_duration_hours: 4`, `whitelist_count: 0`,
    `rule_source: "crowdsec_hub"`) that were never read from CrowdSec and
    never editable — a real user asked how to change them. Investigated
    live (see crowdsec.py's "A-42 addendum" docstring section) and fixed
    honestly, not by making them editable (both are architecturally
    impossible, not merely unbuilt — see below):

      - `whitelist_count` is gone from `settings` entirely, replaced by a
        NEW top-level `allowlist` key (own `connector`/`items`, same shape
        family as `network_profile` on `_perimeter_payload` — a real list,
        not a settings-panel number) fed by `fetch_allowlists()` — genuine
        CrowdSec allowlist data, read-only by construction: `fetch_
        allowlists`'s own docstring explains why writing it needs
        `docker exec`, which this project never does.
      - `ban_threshold`/`ban_duration_hours` are gone too, replaced by one
        `ban_policy` key carrying the single machine-readable value
        `"per_scenario"` — never a number, because CrowdSec has no single
        global ban threshold to report (confirmed live: `/v1/scenarios`,
        `/v1/hub`, `/v1/config` all 404). Per CLAUDE.md's localisation
        rule, the server sends only this code; app.js's
        `CONSOLE_META.ids.settingLabels.ban_policy.values.per_scenario`
        supplies the actual RU/EN explanation text.
      - `rule_source: "crowdsec_hub"` is UNCHANGED data-wise (still the
        only rule source this project actually wires up) — only its label
        in app.js now honestly notes it is this project's own configured
        constant, not something read from CrowdSec.
    """
    console_data, allowlist_data = await asyncio.gather(
        fetch_ids_console_data(),
        fetch_allowlists(),
    )
    chart_values = await chart_values_7d(
        session, console_id=ConsoleId.IDS.value, metric=METRIC_ACTIVE_BANS_LOCAL
    )
    return {
        **_base(ConsoleId.IDS, registry),
        "engine": ["crowdsec"],
        "connector": console_data["connector"],
        "metrics": console_data["metrics"],
        "chart": {"metric": "active_bans_local_7d", "unit": "count", "values": chart_values},
        "recent_attempts": console_data["recent_attempts"],
        "allowlist": {
            "connector": allowlist_data["connector"],
            "items": allowlist_data["allowlists"],
        },
        "settings": {
            "ban_policy": "per_scenario",
            "rule_source": "crowdsec_hub",
        },
    }


async def _av_payload(
    registry: SecurityConsoleRegistry, clamav_jobs: ClamAvScanJobRegistry, session: AsyncSession
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

    A-26: `chart.values` is real last-7-days history of
    `metrics.quarantine_count` (services/metrics/chart.py) — chosen over a
    "files scanned" count precisely because it survives process restarts
    (quarantine_count is a live count of files actually on disk;
    `ClamAvScanJobRegistry`'s scan history is process-memory-only, see its
    own docstring, and would silently go quiet on every restart).

    Post-merge user question (2026-08-02): `settings` used to have FOUR
    fields, all hardcoded Python literals with zero real capability behind
    them — see `AvSettings`'s own docstring (app/db/models.py) for the full
    investigation. `realtime_protection`/`scan_removable_media` are gone
    entirely (no on-access scanning, no removable-media detection exists
    anywhere in this codebase — inventing a fake toggle for either would be
    exactly the "real number, no capability behind it" dishonesty this
    project's own review discipline keeps catching). `action_on_threat`
    stays, but fixed at `"quarantine"` — the only action
    `clamav.quarantine_file` can actually perform, no "block"/"delete" code
    path exists to make this a real choice. `full_scan_schedule` REPLACES
    the old fake `scan_schedule` string with the real, DB-persisted,
    genuinely-enforced schedule `services/av/scheduler.AvScanScheduler`
    actually reads (see that module's own docstring for why it polls
    rather than using `BackupScheduler`'s fixed-at-startup shape — this one
    must be editable from the console UI without a restart).
    """
    osquery_data, clamav_data, chart_values = await asyncio.gather(
        fetch_av_osquery_data(),
        fetch_av_clamav_data(job_registry=clamav_jobs),
        chart_values_7d(session, console_id=ConsoleId.AV.value, metric=METRIC_QUARANTINE_COUNT),
    )
    # Sequential, not folded into the gather above: `chart_values_7d` above
    # already used this same `session` inside that gather, and AsyncSession
    # does not support two concurrently in-flight statements on one
    # instance — same reasoning already documented for `_perimeter_payload`'s
    # own sequential chart_values_7d calls.
    av_settings = await get_av_settings(session)
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
        "chart": {"metric": "quarantine_count_7d", "unit": "count", "values": chart_values},
        "settings": {
            "action_on_threat": "quarantine",
            "full_scan_schedule": {
                "enabled": av_settings.full_scan_schedule_enabled,
                "hour": av_settings.full_scan_hour,
                "minute": av_settings.full_scan_minute,
                "days": list(av_settings.full_scan_days),
            },
        },
    }


def _enrich_connections(
    connections: list[dict[str, Any]],
    reputation: dict[str, Any],
    traffic_by_pid: dict[int, dict[str, int | None]],
    blocked_ips: set[str],
) -> list[dict[str, Any]]:
    """Adds three honest per-row fields on top of osquery's raw
    `connections` (see osquery.py's `fetch_network_console_data`):

      - `bytes_sent`/`bytes_received` (A-39): a real per-PROCESS traffic-
        byte DELTA since the previous poll
        (services/mcp/security_connectors/traffic_counters.py), joined by
        `pid`. Every connection row sharing a pid gets the SAME totals —
        the underlying OS tools aggregate PER PROCESS (nettop `-P` / `ss`
        summed by pid), not per individual socket. Honestly `None` when
        the row's `pid` is `None`, the traffic connector is not `status:
        ok` on this platform/host (see `connectors.os_counters` in the
        response), or this pid was first seen this very poll (no baseline
        yet to diff against).
      - `country` (A-40): geoip.py's offline `resolve_country`, `None`
        when the vendored database is not present or the address isn't
        covered.
      - `lat`/`lon` (A-41): the resolved `country`'s approximate centroid
        (country_centroids.py's `country_centroid`, a bare static lookup —
        see that module's own docstring), feeding the network console's
        canvas map. Honestly `None`/`None` (never a fabricated `(0.0,
        0.0)`, a real point in the Gulf of Guinea) whenever `country`
        itself is `None`, OR `country` resolved to a real code this small
        table simply does not (yet) carry a centroid for — the exact same
        "absence of data is not an error, and never gets a fabricated
        answer" rule `country` itself already follows one field over.
      - `is_suspicious` (A-40): whether `remote_address` matches a
        currently-active CrowdSec decision, via
        `ip_matches_any_decision`/`fetch_active_decision_values`. A THREE-
        state field, not a boolean — `True`/`False` only when
        `reputation["connector"]["status"] == "ok"` (CrowdSec was actually
        reachable and its decisions were actually checked against this
        row); `None` on every row when it was not. A `False` on a row that
        was never actually checked would read as "checked, clean" exactly
        the way a fabricated `metrics.suspicious_connections == 0` would
        (see `_network_payload`'s own docstring) — this function keeps the
        two honest states in sync at the per-row level too, not just the
        summary metric.
      - `is_blocked` (A-52): whether `remote_address` has a row in the
        persistent `blocked_ips` table (os_firewall.py's `list_blocked_ips`
        — the operator already blocked this exact address via the
        connection modal, A-53). A plain boolean, not three-state like
        `is_suspicious`: unlike CrowdSec reputation, there is no "not
        checked" state here — `blocked_ips` is always readable locally
        (own SQLite table, no external connector to be unreachable), so
        "not in the set" always honestly means "not blocked", never
        "unknown". Feeds the modal's own "Заблокировать" button disabled
        state, same "the button matching the current state is disabled"
        convention `portModal`'s `is_blocked` already established (A-37).
    """
    reputation_checked = reputation["connector"]["status"] == "ok"
    decision_values = reputation["values"]
    enriched = []
    for connection in connections:
        remote_address = connection.get("remote_address")
        is_suspicious = (
            ip_matches_any_decision(remote_address, decision_values)
            if reputation_checked
            else None
        )
        pid = connection.get("pid")
        traffic = traffic_by_pid.get(pid) if pid in traffic_by_pid else None
        country = resolve_country(remote_address)
        centroid = country_centroid(country)
        enriched.append(
            {
                **connection,
                "bytes_sent": traffic["bytes_sent"] if traffic else None,
                "bytes_received": traffic["bytes_received"] if traffic else None,
                "country": country,
                "lat": centroid[0] if centroid else None,
                "lon": centroid[1] if centroid else None,
                "is_suspicious": is_suspicious,
                "is_blocked": remote_address is not None and remote_address in blocked_ips,
            }
        )
    return enriched


async def _network_payload(
    registry: SecurityConsoleRegistry,
    session: AsyncSession,
    traffic_registry: TrafficCounterRegistry,
) -> dict[str, Any]:
    """A-15: `connector`/`connections`/`listening_ports`/
    `metrics.active_connections` come from a real osquery connector
    (services/mcp/security_connectors/osquery.py) — this console's primary
    source. `outbound_traffic_status`/`dns_leak_detected` stay honest
    Phase-0 placeholders — no anomaly-detection engine exists yet, out of
    this task's scope.

    A-26: `chart` used to be a dead `{"inbound": [], "outbound": []}`
    shape — a hoped-for traffic-VOLUME split this project has no data
    source for at all (no traffic-volume/anomaly engine exists, see above).
    Replaced with the same uniform `{"metric", "unit", "values"}` shape
    every other console uses, populated with real last-7-days history of
    `metrics.active_connections` (services/metrics/chart.py) — a number
    this console actually has, instead of an inbound/outbound split it
    never did.

    A-39 (11б): each `connections[]` row also carries `bytes_sent`/
    `bytes_received` — see `_enrich_connections` above for the exact
    honesty rules. Not built inside osquery.py itself — osquery has no
    byte-count source at all; this is deliberately a second, independent
    connector composed at this router layer, exactly mirroring how A-40
    composes GeoIP/CrowdSec-reputation onto the same rows.

    A-40: `metrics.suspicious_connections` used to be a hardcoded `0`,
    documented right here as an honest placeholder — that was accurate for
    traffic volume/anomaly detection (still true, still out of scope), but
    CrowdSec's own community-reputation data (already live for `ids` since
    A-11) was sitting right there, unused, for exactly this number. Each
    `connections[]` row is now cross-referenced against CrowdSec's
    currently active decisions (`fetch_active_decision_values`/
    `ip_matches_any_decision`, reusing `ids`'s own read path — no new
    CrowdSec integration) via `_enrich_connections`, and the aggregate
    count is the real sum of matches — but ONLY when CrowdSec was actually
    reachable this request: `suspicious_connections` stays `None` (not a
    silent `0`) when `reputation["connector"]["status"] != "ok"`, so "not
    configured/unreachable" never renders as "checked, all clear". `country`
    is a new field on the same rows (geoip.py, offline, see that module's
    own licence-research docstring), independent of CrowdSec entirely — an
    unconfigured geoip database and an unconfigured CrowdSec are two
    separate honest `None`s, not coupled to each other.

    A-41: `connectors.geoip.status` is new — until now geoip.py's own
    `is_geoip_configured()` was never surfaced as an explicit top-level
    connector status on this console at all, only implicitly visible as
    every row's `country` being `None` (which is ALSO the honest answer
    for a single unresolvable address even when geoip IS configured — the
    two cases were indistinguishable from the payload alone). Two honest
    reasons to add it now, not before: (1) it lets `app.js`'s new map
    component show a specific "GeoIP не настроен" placeholder instead of a
    silently empty map when nothing is configured at all, rather than
    guessing from an all-`None` `country` column; (2) it is a plain local
    file check (`is_geoip_configured()`, no I/O, no network — see
    geoip.py's docstring), so, unlike `reputation`/`traffic_data`, it needs
    no extra `asyncio.gather` branch. Only two states on purpose (`"ok"` /
    `"not_configured"`), not three like `reputation`'s CrowdSec status —
    this is a local file existence check, not a live remote call that can
    also be "unreachable"/"unauthorized".
    """
    network_data, chart_values, traffic_data, reputation, blocked_ip_rows = await asyncio.gather(
        fetch_network_console_data(),
        chart_values_7d(session, console_id=ConsoleId.NETWORK.value, metric=METRIC_ACTIVE_CONNECTIONS),
        fetch_traffic_counters(traffic_registry),
        fetch_active_decision_values(),
        list_blocked_ips(session),
    )
    blocked_ips = {row.ip for row in blocked_ip_rows}
    connections = _enrich_connections(network_data["connections"], reputation, traffic_data["by_pid"], blocked_ips)
    suspicious_connections = (
        sum(1 for connection in connections if connection["is_suspicious"])
        if reputation["connector"]["status"] == "ok"
        else None
    )
    geoip_status = "ok" if is_geoip_configured() else "not_configured"
    return {
        **_base(ConsoleId.NETWORK, registry),
        "engine": ["osquery", "os_counters", "crowdsec", "geoip"],
        "connector": network_data["connector"],
        "connectors": {"os_counters": traffic_data["connector"], "geoip": {"status": geoip_status}},
        "metrics": {
            "outbound_traffic_status": None,
            "active_connections": network_data["active_connections"],
            "suspicious_connections": suspicious_connections,
            "dns_leak_detected": None,
        },
        "chart": {"metric": "active_connections_7d", "unit": "count", "values": chart_values},
        "connections": connections,
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

    A-55: `connector` is the real, cheap restic configuration status
    (`backup_connector_status()` — same machine-readable `status`/`reason`
    shape every other connector-backed console already reports), and
    `metrics.storages` now follows it (1 configured / 0 not), no longer a
    hardcoded 1 (GUI-прогон 2026-09-19, находка F1).
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
        "connector": metrics["connector"],
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


async def _logs_payload(registry: SecurityConsoleRegistry, session: AsyncSession) -> dict[str, Any]:
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

    A-26: `chart.values` is real last-7-days history of `metrics.events_24h`
    (services/metrics/chart.py) — deliberately NOT read off `console_data`
    anymore (that connector no longer returns a `chart` key at all, see
    wazuh.py's docstring), same reasoning as `_ids_payload`.
    """
    console_data, chart_values = await asyncio.gather(
        fetch_logs_console_data(),
        chart_values_7d(session, console_id=ConsoleId.LOGS.value, metric=METRIC_EVENTS_24H),
    )
    return {
        **_base(ConsoleId.LOGS, registry),
        "engine": ["wazuh_agent", "windows_event_log", "macos_unified_log"],
        "connector": console_data["connector"],
        "metrics": console_data["metrics"],
        "chart": {"metric": "events_24h_7d", "unit": "count", "values": chart_values},
        "entries": console_data["entries"],
        "settings": {
            "os_event_log": True,
            "audit_logins_privilege": True,
            "wazuh_crowdsec_events": True,
            "sysmon": False,
            "retention_days": 90,
        },
    }


async def _last_metric_value(
    session: AsyncSession, console_id: str, metric: str
) -> float | None:
    """A-56: the most recent `MetricSample.value` for one (console_id,
    metric) series — same write side as services/metrics/sampler.py, same
    (console_id, metric, sampled_at) read shape as
    services/metrics/chart.py's `chart_values_7d`. None (honest "no sample
    yet") when the sampler has never recorded this metric — never a
    fabricated zero."""
    return (
        await session.scalars(
            select(MetricSample.value)
            .where(MetricSample.console_id == console_id, MetricSample.metric == metric)
            .order_by(MetricSample.sampled_at.desc())
            .limit(1)
        )
    ).first()


@router.get("/overview")
async def overview(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Obзорный экран: агрегированный статус (худшее из 6 консолей, та же
    идея, что `HealthRegistry.run_all`'s `status`/`components` shape) + KPI
    из реальных источников + реальный журнал последних событий шины (A-4's
    `events` table) — not hardcoded, genuinely queried.

    A-56: `blocked_24h`/`active_connections` — последние значения из
    `metric_samples` (те же (console_id, metric) пары, что пишет сэмплер:
    `("ids", "active_bans_local")` и `("network", "active_connections")`);
    None, если сэмплов ещё нет — честное «—» на клиенте, а не фабричный
    ноль, который читался как «проверено, всё спокойно» (находка F2
    GUI-прогона 2026-09-19: обзор показывал «0» при 200 живых соединениях в
    консоли «Сеть»). `system_load_pct`/`uptime_pct` остаются None —
    источника для них в Фазе 0 genuinely нет."""
    events = (
        await session.scalars(
            select(Event)
            .where(Event.topic.in_(_EVENT_LOG_TOPICS))
            .order_by(Event.created_at.desc())
            .limit(_EVENT_LOG_LIMIT)
        )
    ).all()

    blocked_24h = await _last_metric_value(session, IDS_CONSOLE_ID, METRIC_ACTIVE_BANS_LOCAL)
    active_connections = await _last_metric_value(
        session, NETWORK_CONSOLE_ID, METRIC_ACTIVE_CONNECTIONS
    )
    # Гаuge-метрики сэмплер пишет как float; для счётчиков (баны/соединения)
    # целочисленное представление того же числа честнее виду (3, не 3.0).
    if blocked_24h is not None and float(blocked_24h).is_integer():
        blocked_24h = int(blocked_24h)
    if active_connections is not None and float(active_connections).is_integer():
        active_connections = int(active_connections)

    return {
        "status": registry.aggregate_status().value,
        "consoles": registry.snapshot(),
        "kpis": {
            "blocked_24h": blocked_24h,
            "active_connections": active_connections,
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
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _perimeter_payload(registry, session)


@router.post("/consoles/perimeter/rescan-ports")
async def perimeter_rescan_ports(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-28: on-demand re-run of the same osquery `listening_ports` query
    `_perimeter_payload` already runs passively on every poll (see
    `fetch_listening_ports`). Genuinely redundant with auto-refresh —
    osquery has no cache to invalidate here, every poll already is a fresh
    one-shot query — but this task's own brief asks for it anyway: a
    concrete, user-triggered action the "Пересканировать порты" button can
    do and confirm, rather than leaving it a silent placeholder. Never
    500s: a connector failure comes back as an honest
    `connector.status`, exactly like the passive path."""
    return await fetch_listening_ports()


# ---------------------------------------------------------------------------
# A-36: real, one-shot ELEVATED actions for the perimeter console — the
# "Правила фаервола"/"Заблокировать все входящие"/"Разблокировать все
# входящие" buttons, previously disabled `soon` placeholders (A-28/A-31).
# Every request here triggers a REAL, one-time OS admin-password prompt on
# the server host (see os_firewall.py's "A-36" section + elevated.py) — a
# slow endpoint by nature (it blocks on a human answering that prompt),
# never called passively/automatically, only from an explicit user click.
#
# `OSFirewallError.reason` maps to its own dedicated HTTP codes here,
# mirroring `_CROWDSEC_WRITE_ERROR_STATUS`'s shape above for the same
# "typed write-action error -> distinct HTTP status" pattern:
#   - `elevation_cancelled` -> 409 (Conflict): a genuine, expected, user-
#     initiated non-outcome — NOT a server error, but still surfaced via
#     the same `{"error": ...}` machine-code channel (CLAUDE.md) so the
#     client can render it distinctly (see app.js's `'warn'` status kind)
#     from a real `elevation_failed`.
#   - `elevation_failed` -> 502 (Bad Gateway): the elevated command itself
#     (pfctl/iptables/netsh) failed — a real problem, distinct from the
#     user simply declining.
#   - anything else (in practice only `not_configured` — no implementation
#     exists for this host's platform, see os_firewall.py's per-function
#     scope notes) -> 503, reusing the SAME `connector_not_configured`
#     code every other console-connector-not-configured case already uses
#     (see e.g. `crowdsec_write_not_configured`'s own sibling shape above)
#     rather than inventing a third near-duplicate string.
# ---------------------------------------------------------------------------

_ELEVATED_FIREWALL_ERROR_STATUS = {
    "elevation_cancelled": 409,
    "elevation_failed": 502,
    # A-52: `os_firewall._validate_ip`'s own reason — a malformed IP is a
    # client input problem (422, FastAPI's own convention for that), never
    # confused with `elevation_failed`'s "the elevated command itself
    # failed" (502) or the generic `connector_not_configured` fallback (503)
    # below, both of which would misdirect an operator toward "is my
    # firewall broken" instead of "I mistyped/tampered with the address".
    "invalid_ip": 422,
}

# A-52: `OSProcessError`'s own reason set — a DIFFERENT exception class
# from `OSFirewallError`, own mapper function, not folded into
# `_raise_for_os_firewall_error` above (this project's convention when two
# error vocabularies are related but not identical, same reasoning
# CrowdSec/ClamAV/os_firewall already each keep their own `_raise_for_*`
# rather than one giant shared dispatcher). `process_identity_mismatch` —
# 409, the same "the request was well-formed, but the state of the world
# it assumed has moved on" status this project already uses for CrowdSec's
# `readback_mismatch`-class outcomes, not 422 (nothing about the REQUEST
# was invalid) and not 5xx (nothing on the SERVER failed).
_ELEVATED_PROCESS_ERROR_STATUS = {
    "elevation_cancelled": 409,
    "elevation_failed": 502,
    "process_identity_mismatch": 409,
    "invalid_pid": 422,
}


def _raise_for_os_process_error(exc: OSProcessError) -> NoReturn:
    if exc.reason in _ELEVATED_PROCESS_ERROR_STATUS:
        raise HTTPException(status_code=_ELEVATED_PROCESS_ERROR_STATUS[exc.reason], detail={"error": exc.reason})
    raise HTTPException(status_code=503, detail={"error": "connector_not_configured"})


def _raise_for_os_firewall_error(exc: OSFirewallError) -> NoReturn:
    if exc.reason in _ELEVATED_FIREWALL_ERROR_STATUS:
        raise HTTPException(status_code=_ELEVATED_FIREWALL_ERROR_STATUS[exc.reason], detail={"error": exc.reason})
    raise HTTPException(status_code=503, detail={"error": "connector_not_configured"})


@router.post("/consoles/perimeter/firewall/rules")
async def perimeter_firewall_rules(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-36: on-demand ELEVATED `pfctl -s rules` (macOS)/`iptables -S`
    (Linux)/`netsh advfirewall firewall show rule name=all` (Windows) — a
    real, one-time OS admin-password prompt (see
    `os_firewall.read_firewall_rules`), NOT `fetch_firewall_rules()`'s
    passive, never-privileged ruleset COUNT that `GET
    /consoles/perimeter` already returns on every poll. This project never
    asks for admin credentials on a page load — only on this explicit
    button click."""
    try:
        return await read_firewall_rules()
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)


@router.post("/consoles/perimeter/firewall/block-all")
async def perimeter_firewall_block_all(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-36: "Заблокировать все входящие" — a real, elevated, wide-blast-
    radius action (see `os_firewall.block_all_incoming`'s own docstring
    for exactly what it does per platform). The frontend requires an
    explicit `window.confirm()` before ever calling this endpoint (see
    app.js's `handleBlockAllIncoming`) — mirrored here by nothing extra on
    the server side, matching this project's existing `crowdsec_ban_ip`
    precedent (confirmation is a client-side UX gate, the server's own
    contract is simply "do the thing that was asked, honestly report the
    real outcome")."""
    try:
        return await block_all_incoming()
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)


@router.post("/consoles/perimeter/firewall/unblock-all")
async def perimeter_firewall_unblock_all(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-36: the reverse of `perimeter_firewall_block_all` above."""
    try:
        return await unblock_all_incoming()
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)


# ---------------------------------------------------------------------------
# A-37: per-PORT block/unblock — the port-detail modal's own two buttons
# (see app.js's openPortModal/handleBlockPort/handleUnblockPort), a
# genuinely narrower elevated action than block-all/unblock-all above (see
# os_firewall.py's "A-37" section docstring). Same one-shot elevated-prompt
# mechanism and the exact same `_raise_for_os_firewall_error` error mapping
# as A-36's three endpoints above — this task's own brief explicitly asks
# to mirror it, not invent a fourth near-duplicate error-mapping table.
# ---------------------------------------------------------------------------


@router.post("/consoles/perimeter/ports/{port}/block")
async def perimeter_block_port(
    port: int,
    body: PerimeterBlockPortRequest | None = None,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-37: one-shot ELEVATED per-port block (see
    `os_firewall.block_port`) — triggers a real, one-time OS admin-password
    prompt, same as every A-36/A-37 elevated endpoint in this file.

    Reads the CURRENT persisted `blocked_ports` table first, adds `port`
    to that set, and passes the resulting complete list to `block_port()`
    — needed by macOS's own pf-anchor reconstruction (see
    `os_firewall._build_macos_sync_blocked_ports_script`'s own docstring
    for exactly why a full list, not just `port` alone, is required
    there).

    The persistent DB row (`record_blocked_port`) is written ONLY after
    `block_port()` has already returned successfully — never before,
    never speculatively: a DB row here always means the elevated OS action
    genuinely already applied, matching this whole project's "never
    fabricate a state that has not happened yet" discipline (same
    ordering `perimeter_unblock_port` below mirrors in reverse)."""
    existing = await list_blocked_ports(session)
    desired_ports = sorted({row.port for row in existing} | {port})
    try:
        result = await block_port(port, all_blocked_ports=desired_ports)
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)
    await record_blocked_port(
        session,
        port=port,
        protocol=body.protocol if body else None,
        process_name=body.process_name if body else None,
    )
    return result


@router.delete("/consoles/perimeter/ports/{port}/block")
async def perimeter_unblock_port(
    port: int,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-37: the reverse of `perimeter_block_port` above — reads the
    current `blocked_ports` table, computes the desired set with `port`
    REMOVED, syncs the OS-level enforcement to that (elevated), and only
    THEN deletes the DB row (see `unblock_port`/`delete_blocked_port`'s
    own docstrings for why this ordering matters)."""
    existing = await list_blocked_ports(session)
    desired_ports = sorted({row.port for row in existing} - {port})
    try:
        result = await unblock_port(port, all_blocked_ports=desired_ports)
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)
    await delete_blocked_port(session, port=port)
    return result


@router.post("/consoles/network/ips/{ip}/block")
async def network_block_ip(
    ip: str,
    body: NetworkBlockIpRequest | None = None,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-52: one-shot ELEVATED per-IP block (see `os_firewall.block_ip`) —
    same real, one-time OS admin-password prompt every A-36/A-37/A-52
    elevated endpoint in this file already uses. `ip` is validated (and
    raises the new honest `invalid_ip` — 422, see
    `_ELEVATED_FIREWALL_ERROR_STATUS` above) inside `block_ip()` itself,
    not re-checked here — one validation point, not two that could drift
    apart. Same "DB row written only after the elevated action already
    returned ok" ordering as `perimeter_block_port` above."""
    existing = await list_blocked_ips(session)
    desired_ips = sorted({row.ip for row in existing} | {ip})
    try:
        result = await block_ip(ip, all_blocked_ips=desired_ips)
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)
    await record_blocked_ip(
        session,
        ip=result["ip"],
        country=body.country if body else None,
        process_name=body.process_name if body else None,
        reason=body.reason if body else None,
    )
    return result


@router.delete("/consoles/network/ips/{ip}/block")
async def network_unblock_ip(
    ip: str,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-52: the reverse of `network_block_ip` above — same ordering as
    `perimeter_unblock_port` (OS-level sync first, DB row deleted only
    after that genuinely succeeded)."""
    existing = await list_blocked_ips(session)
    desired_ips = sorted({row.ip for row in existing} - {ip})
    try:
        result = await unblock_ip(ip, all_blocked_ips=desired_ips)
    except OSFirewallError as exc:
        _raise_for_os_firewall_error(exc)
    await delete_blocked_ip(session, ip=result["ip"])
    return result


@router.post("/consoles/network/processes/{pid}/terminate")
async def network_terminate_process(
    pid: int,
    body: NetworkTerminateProcessRequest,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-52: one-shot ELEVATED SIGTERM (see `os_processes.terminate_process`
    — read that module's own docstring FIRST, it explains the multi-layer
    protection this single endpoint sits at the bottom of). No persisted
    table (unlike the block-port/block-ip endpoints above) — terminating a
    process is not an ongoing enforcement state to remember across a
    restart, it is a one-off action with no "undo" or "currently applied"
    concept at all.

    `process_identity_mismatch` (409) is the single most important outcome
    this endpoint can return — it means the safety check inside the
    elevated script itself refused to act because the process at `pid` no
    longer matches `body.process_name` (see os_processes.py). The router
    does nothing special with it beyond the standard mapping below; the
    honesty is already baked into `terminate_process()` never sending a
    signal at all in that case."""
    try:
        return await terminate_process(pid, body.process_name)
    except OSProcessError as exc:
        _raise_for_os_process_error(exc)


# ---------------------------------------------------------------------------
# A-38: manual network-category assignment — the "Сделать доверенной"/
# "Сделать публичной" toggle for the CURRENT network (see
# network_profile.py's docstring: which category the background monitor
# nudges the operator about is entirely driven by this persisted value).
# Deliberately NOT elevated (unlike the three A-36 endpoints above) —
# writing to this app's own `network_profiles` table needs no OS privilege
# at all, only reading pf/firewall state does.
# ---------------------------------------------------------------------------


@router.post("/consoles/perimeter/network-profile/category")
async def perimeter_set_network_category(
    payload: NetworkCategoryRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Re-detects the current network LIVE (never trusts a client-supplied
    identity) and persists the operator's chosen `category` for it — a
    network never seen before can be categorised immediately (no prior
    background-scheduler tick required, see `set_network_category`'s own
    upsert behaviour). Returns the SAME shape `GET /consoles/perimeter`'s
    own `network_profile` key does, so the frontend can render the update
    without a second round-trip.

    `network_not_detected` (409): the current network could not be
    determined at all right now (e.g. no active interface) — there is
    nothing to attach this category to. A genuine, expected outcome, never
    a 500."""
    detection = await detect_current_network()
    if not detection["network_key"]:
        raise HTTPException(status_code=409, detail={"error": "network_not_detected"})

    now = datetime.now(timezone.utc).replace(tzinfo=None)
    await set_network_category(
        session,
        network_key=detection["network_key"],
        display_name=detection["display_name"],
        id_kind=detection["id_kind"],
        category=payload.category,
        now=now,
    )
    return await network_profile_payload(session)


@router.get("/consoles/ids")
async def console_ids(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _ids_payload(registry, session)


# A-29: HTTP status a given CrowdSecError.reason maps to — both the ban and
# unban endpoints below share this (a wrong/expired machine credential or an
# unreachable LAPI reads the same to a client either way); "not_found" is
# handled as its own branch in crowdsec_unban_ip below since it needs a
# genuinely different status (404) and error code than everything else.
_CROWDSEC_WRITE_ERROR_STATUS = {
    "unauthorized": 503,
    "unreachable": 503,
    "invalid_ip": 422,
    "rejected": 502,
}


class CrowdSecBanRequest(BaseModel):
    ip: str


@router.post("/consoles/ids/crowdsec/ban")
async def crowdsec_ban_ip(
    body: CrowdSecBanRequest,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-29: "Забанить вручную" — a real `POST /v1/alerts` against
    CrowdSec's LAPI using the machine-level write credential (see
    services/mcp/security_connectors/crowdsec.py's "A-29 addendum"
    docstring section), never the read-only bouncer key `console_ids`
    above uses. `body.ip` is validated by `CrowdSecClient.create_ban`
    itself (Python's `ipaddress`) before any request reaches LAPI — see
    that method's docstring for why LAPI's own validation cannot be
    trusted to reject a bad IP for us.
    """
    try:
        alert_ids = await ban_ip(body.ip)
    except CrowdSecNotConfiguredError:
        raise HTTPException(status_code=503, detail={"error": "crowdsec_write_not_configured"})
    except CrowdSecError as exc:
        status_code = _CROWDSEC_WRITE_ERROR_STATUS.get(exc.reason, 503)
        raise HTTPException(status_code=status_code, detail={"error": f"crowdsec_{exc.reason}"})
    return {"banned": True, "ip": body.ip, "alert_ids": alert_ids}


@router.delete("/consoles/ids/crowdsec/decisions/{decision_id}")
async def crowdsec_unban_ip(
    decision_id: int,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-29: "Разбанить IP" — a real `DELETE /v1/decisions/{id}` against
    CrowdSec's LAPI, same machine-level write credential as
    `crowdsec_ban_ip` above. `decision_id` is the same `id` the console's
    own `recent_attempts` rows already carry (see `_ids_payload`/
    `fetch_ids_console_data`'s "A-29" docstring note) — the frontend never
    has to look one up separately.
    """
    try:
        deleted_count = await unban_decision(decision_id)
    except CrowdSecNotConfiguredError:
        raise HTTPException(status_code=503, detail={"error": "crowdsec_write_not_configured"})
    except CrowdSecError as exc:
        if exc.reason == "not_found":
            raise HTTPException(status_code=404, detail={"error": "crowdsec_decision_not_found"})
        status_code = _CROWDSEC_WRITE_ERROR_STATUS.get(exc.reason, 503)
        raise HTTPException(status_code=status_code, detail={"error": f"crowdsec_{exc.reason}"})
    return {"deleted": deleted_count > 0, "count": deleted_count}


# ---------------------------------------------------------------------------
# A-43: scenario capacity/leakspeed ("порог") — real, one-shot ELEVATED
# docker-exec read/write. See crowdsec.py's own "A-43 addendum" docstring
# section for the full architectural rationale (a narrow, explicit
# exception to "никогда docker exec", mirroring how A-36 already narrowed
# "никогда не повышать привилегии приложения целиком" — see
# docs/план-спецификация-фаза-0-порог-сценариев-2026-07-24.md's own "Важное
# архитектурное решение", not reargued here). `elevation_cancelled`/
# `elevation_failed` map to the SAME 409/502 `_raise_for_os_firewall_error`
# above already uses, per this task's own brief ("зеркалят уже
# существующие") — the rest are scenario-specific, never seen from A-36/
# A-37's own OSFirewallError.
# ---------------------------------------------------------------------------

_CROWDSEC_SCENARIO_ERROR_STATUS = {
    "elevation_cancelled": 409,
    "elevation_failed": 502,
    "scenario_has_no_threshold": 422,
    "scenario_not_found": 404,
    "invalid_capacity": 422,
    "invalid_leakspeed": 422,
    "readback_mismatch": 502,
}


def _raise_for_crowdsec_scenario_error(exc: CrowdSecScenarioError) -> NoReturn:
    status_code = _CROWDSEC_SCENARIO_ERROR_STATUS.get(exc.reason, 503)
    raise HTTPException(status_code=status_code, detail={"error": exc.reason})


class ScenarioThresholdRequest(BaseModel):
    """A-43: body for `PUT .../scenario-thresholds/{scenario_name}` —
    deliberately unconstrained Pydantic fields (just type-checked): real
    validation (positive int or `-1` / `\\d+[smh]`) happens inside
    `crowdsec.write_scenario_threshold` itself, returning this project's
    own `{"error": "invalid_capacity"}`-style machine code (CLAUDE.md's
    localisation rule) — a Pydantic-level field constraint would instead
    surface FastAPI's differently-shaped default validation-error body."""

    capacity: int
    leakspeed: str


@router.get("/consoles/ids/crowdsec/scenario-thresholds")
async def crowdsec_scenario_thresholds(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-43: on-demand ELEVATED read of every installed SSH scenario's real
    `capacity`/`leakspeed` (see `crowdsec.read_scenario_thresholds`) — a
    real, one-time OS admin-password prompt, same "never on page load, only
    on this explicit button click" discipline as A-36's «Правила
    фаервола»."""
    try:
        return await read_scenario_thresholds()
    except CrowdSecScenarioError as exc:
        _raise_for_crowdsec_scenario_error(exc)


@router.put("/consoles/ids/crowdsec/scenario-thresholds/{scenario_name:path}")
async def crowdsec_write_scenario_threshold(
    scenario_name: str,
    body: ScenarioThresholdRequest,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-43: the elevated WRITE half — `{scenario_name}` uses FastAPI's
    `:path` converter because a real scenario name always contains a
    literal `/` (`crowdsecurity/<name>`, see crowdsec.py's own module
    docstring), never URL-encoded away by this project's own frontend (see
    app.js's handleSaveScenarioThreshold)."""
    try:
        return await write_scenario_threshold(scenario_name, capacity=body.capacity, leakspeed=body.leakspeed)
    except CrowdSecScenarioError as exc:
        _raise_for_crowdsec_scenario_error(exc)


# ---------------------------------------------------------------------------
# A-45: "Проверить обновления"/"Применить обновления" — REVISES this file's
# own former "Обновить сценарии" disabled placeholder (see crowdsec.py's own
# "A-45 addendum" docstring section and
# docs/план-спецификация-фаза-0-обновление-сценариев-2026-07-25.md's
# "Пересмотр решения A-43" for the full rationale, not reargued here). Same
# `_CROWDSEC_SCENARIO_ERROR_STATUS`/`_raise_for_crowdsec_scenario_error`
# above — this task's own brief explicitly asks to mirror A-43/A-44's error
# mapping, not invent a new one.
# ---------------------------------------------------------------------------


@router.post("/consoles/ids/crowdsec/scenario-updates/check")
async def crowdsec_check_scenario_updates(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-45: "Проверить обновления" — on-demand ELEVATED `cscli hub update
    && cscli hub upgrade --dry-run` (see crowdsec.check_scenario_updates) —
    a real, one-time OS admin-password prompt, same "never on page load,
    only on this explicit button click" discipline as A-36/A-43. Neither
    `cscli hub update` (refreshes the local catalogue only) nor
    `--dry-run` installs anything — see crowdsec.py's own "A-45 addendum"
    docstring section for the live confirmation."""
    try:
        return await check_scenario_updates()
    except CrowdSecScenarioError as exc:
        _raise_for_crowdsec_scenario_error(exc)


@router.post("/consoles/ids/crowdsec/scenario-updates/apply")
async def crowdsec_apply_scenario_updates(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-45: "Применить обновления" — the elevated WRITE half (see
    crowdsec.apply_scenario_updates: a real `cscli hub upgrade` + a
    conditional `docker compose restart crowdsec` + a mandatory separate
    readback). The frontend only ever shows this button after a successful
    `check` above reported `has_upgrades: true` (see app.js's
    renderScenarioUpdatesSection) — this endpoint itself does not re-verify
    that ordering: CrowdSec's own state can change between the two calls,
    see crowdsec.py's own docstring for why `applied: false` is still an
    honest, non-error outcome rather than something this endpoint needs to
    reject."""
    try:
        return await apply_scenario_updates()
    except CrowdSecScenarioError as exc:
        _raise_for_crowdsec_scenario_error(exc)


# ---------------------------------------------------------------------------
# A-44: allowlist write ("Добавить в белый список"/"Удалить") — real,
# one-shot ELEVATED docker-exec write, applying A-43's already-established
# narrow exception to "никогда docker exec" to a second action. See
# services/mcp/security_connectors/crowdsec.py's own "A-44 addendum"
# docstring section for the full rationale (not reargued here — per
# docs/план-спецификация-фаза-0-белый-список-запись-2026-07-25.md's own
# "Архитектурное решение — не переоткрывается") and `add_to_allowlist`/
# `remove_from_allowlist` for the actual write+readback logic this router
# only ever calls through.
# ---------------------------------------------------------------------------

_CROWDSEC_ALLOWLIST_ERROR_STATUS = {
    "elevation_cancelled": 409,
    "elevation_failed": 502,
    "invalid_value": 422,
    "allowlist_write_failed": 502,
    "allowlist_readback_mismatch": 502,
    "allowlist_readback_unavailable": 502,
}


def _raise_for_crowdsec_allowlist_error(exc: CrowdSecAllowlistError) -> NoReturn:
    status_code = _CROWDSEC_ALLOWLIST_ERROR_STATUS.get(exc.reason, 503)
    raise HTTPException(status_code=status_code, detail={"error": exc.reason})


class AllowlistAddRequest(BaseModel):
    """A-44: body for `POST .../allowlist` — deliberately unconstrained
    Pydantic fields (just type-checked, same reasoning as
    `ScenarioThresholdRequest` above): real validation (a genuine IP/CIDR)
    happens inside `crowdsec.add_to_allowlist` itself, returning this
    project's own `{"error": "invalid_value"}` machine code (CLAUDE.md's
    localisation rule)."""

    value: str
    comment: str | None = None


@router.post("/consoles/ids/crowdsec/allowlist")
async def crowdsec_add_to_allowlist(
    body: AllowlistAddRequest,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-44: "Добавить в белый список" — a real, one-time OS admin-password
    prompt (same `elevated_run()` mechanism as A-43's scenario thresholds
    above), never on page load, only on this explicit button click."""
    try:
        return await add_to_allowlist(body.value, comment=body.comment)
    except CrowdSecAllowlistError as exc:
        _raise_for_crowdsec_allowlist_error(exc)


@router.delete("/consoles/ids/crowdsec/allowlist/{value:path}")
async def crowdsec_remove_from_allowlist(
    value: str,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-44: "Удалить" on an existing allowlist row. `{value}` uses
    FastAPI's `:path` converter — same reason as A-43's own
    `{scenario_name:path}` above: a real value can be a CIDR block
    (`203.0.113.0/24`) containing a literal `/`, sent URL-encoded
    (`encodeURIComponent`) by app.js's `handleRemoveFromAllowlist`."""
    try:
        return await remove_from_allowlist(value)
    except CrowdSecAllowlistError as exc:
        _raise_for_crowdsec_allowlist_error(exc)


@router.get("/consoles/av")
async def console_av(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _av_payload(registry, clamav_jobs, session)


@router.post("/consoles/av/clamav/scan/quick")
async def clamav_quick_scan(
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    session: AsyncSession = Depends(get_session),
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

    A-33: also records a persistent `scan_history` row on completion (see
    `record_scan_history`) — reuses this request's own `session` (unlike
    the full-scan background job, which has none to reuse), the durable
    counterpart to `clamav_jobs`'s in-memory job that survives a restart.
    """
    job = clamav_jobs.create("quick")
    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        result = await run_quick_scan()
    except ClamAvNotConfiguredError:
        clamav_jobs.mark_failed(job, error="not_configured")
        raise HTTPException(status_code=503, detail={"error": "clamav_not_configured"})
    except ClamdError as exc:
        clamav_jobs.mark_failed(job, error=exc.reason)
        raise HTTPException(status_code=503, detail={"error": f"clamav_{exc.reason}"})
    clamav_jobs.mark_completed(job, scanned_count=result["scanned_count"], infected=result["infected"])
    await record_scan_history(
        session,
        scan_type="quick",
        path=None,
        scanned_count=result["scanned_count"],
        infected_count=len(result["infected"]),
        started_at=started_at,
        finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    return job.to_payload()


_CLAMAV_FOLDER_PICK_ERROR_STATUS = {
    "folder_pick_cancelled": 409,
    "unsupported_platform": 501,
}


@router.post("/consoles/av/clamav/pick-folder")
async def clamav_pick_folder(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Post-merge user request (2026-08-02): pops the real native OS
    folder-picker (clamav.pick_scan_folder) and returns the operator's pick
    — the frontend then feeds that path into the SAME `POST
    /consoles/av/clamav/scan/custom` this already used to require typing a
    path into a text field for."""
    try:
        path = await pick_scan_folder()
    except ClamAvFolderPickError as exc:
        status_code = _CLAMAV_FOLDER_PICK_ERROR_STATUS.get(exc.reason, 502)
        raise HTTPException(status_code=status_code, detail={"error": exc.reason})
    return {"path": path}


@router.post("/consoles/av/clamav/scan/custom")
async def clamav_custom_scan(
    body: ClamAvCustomScanRequest,
    clamav_jobs: ClamAvScanJobRegistry = Depends(get_clamav_scan_job_registry),
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-33: on-demand scan of ONE operator-chosen path — see
    services/mcp/security_connectors/clamav.py.run_custom_scan's docstring
    for exactly why quick/full scan alone were not enough (this task's own
    brief: "нет UI для выбора произвольной... папки").

    Post-merge user finding (2026-08-02): `body.path` is NO LONGER
    restricted to the old known-scan-roots allowlist —
    `run_custom_scan`'s own docstring explains why that restriction (written
    for `quarantine_file`'s move-a-file risk) does not transfer to a
    read-only, always operator-initiated scan, and was blocking normal AV
    use (scanning `/Applications`, an external drive, ...) once this action
    became reachable via a real native folder-picker. `quarantine_file`'s
    OWN restriction is untouched. Only `FileNotFoundError` (path does not
    exist) is still possible from the path itself.

    Recorded into BOTH `clamav_jobs` (so `GET /security/consoles/av`'s
    `GET .../scan/full/{job_id}`-style job polling can show this scan's own
    progress/result) AND the persistent `scan_history` table (see
    `record_scan_history`) — the second write is what survives a server
    restart. Note: `metrics.last_scan_at`/`clean` deliberately do NOT
    reflect custom (or quick) scans — see `fetch_av_clamav_data`'s own
    docstring, `kind="full"` only, per the user's own request that only a
    real full system scan should move that console tile.
    """
    job = clamav_jobs.create("custom", path=body.path)
    started_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        result = await run_custom_scan(Path(body.path))
    except FileNotFoundError:
        clamav_jobs.mark_failed(job, error="path_not_found")
        raise HTTPException(status_code=404, detail={"error": "scan_path_not_found"})
    except ClamAvNotConfiguredError:
        clamav_jobs.mark_failed(job, error="not_configured")
        raise HTTPException(status_code=503, detail={"error": "clamav_not_configured"})
    except ClamdError as exc:
        clamav_jobs.mark_failed(job, error=exc.reason)
        raise HTTPException(status_code=503, detail={"error": f"clamav_{exc.reason}"})
    clamav_jobs.mark_completed(job, scanned_count=result["scanned_count"], infected=result["infected"])
    await record_scan_history(
        session,
        scan_type="custom",
        path=result["path"],
        scanned_count=result["scanned_count"],
        infected_count=len(result["infected"]),
        started_at=started_at,
        finished_at=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    return job.to_payload()


@router.get("/consoles/av/clamav/scan/history")
async def clamav_scan_history(
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-33: persistent history of quick/full/custom scans (see
    services/mcp/security_connectors/clamav.py.record_scan_history) — the
    durable replacement for "only ever the current/most-recent job status"
    this task's own brief flags (`ClamAvScanJobRegistry` resets on every
    restart, this table does not). Newest-finished-first, capped at 20
    rows — the console only ever shows "the last few scans", not a full
    unbounded history browser.
    """
    entries = await list_scan_history(session)
    return {
        "items": [
            {
                "id": entry.id,
                "scan_type": entry.scan_type,
                "path": entry.path,
                "scanned_count": entry.scanned_count,
                "infected_count": entry.infected_count,
                "started_at": entry.started_at.isoformat(),
                "finished_at": entry.finished_at.isoformat(),
            }
            for entry in entries
        ]
    }


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
    event_bus: EventBus = Depends(get_event_bus),
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

    Post-merge user request (2026-08-02): `event_bus` is forwarded into
    `quarantine_file` so a genuinely successful quarantine also publishes a
    real `Topic.SECURITY_ALERT` notification (panel icon/text/sound/email,
    per the notification matrix) — not just an in-console banner.
    """
    try:
        quarantined_path = await quarantine_file(Path(body.path), reason=body.reason, event_bus=event_bus)
    except ClamAvPathNotAllowedError:
        raise HTTPException(status_code=403, detail={"error": "path_outside_scan_roots"})
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "file_not_found"})
    return {"quarantined_path": str(quarantined_path)}


@router.get("/consoles/av/clamav/quarantine")
async def clamav_quarantine_list(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-27: the list `quarantine_file` (A-17) never had a reader for —
    path, quarantine date, and the detected threat/reason (when known) for
    every currently-quarantined file, read back from the real metadata
    sidecars `quarantine_file` writes (see
    services/mcp/security_connectors/clamav.py.list_quarantine_entries).
    Never raises: an empty/missing quarantine directory is an honest empty
    list, not an error.
    """
    entries = list_quarantine_entries()
    return {"items": [entry.to_payload() for entry in entries]}


@router.post("/consoles/av/clamav/quarantine/{item_id}/restore")
async def clamav_quarantine_restore(
    item_id: str,
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-27: moves a quarantined file back to the path it was quarantined
    FROM — the reversibility `quarantine_file`'s own docstring has promised
    since A-17 ("никогда не удаление... false positive можно
    восстановить"), finally implemented (see
    services/mcp/security_connectors/clamav.py.restore_quarantine_file).

    404s honestly when `item_id` is unknown/already restored/its payload
    file is gone; 409s (never silently overwrites) when something already
    occupies the original path.
    """
    try:
        restored_path = await restore_quarantine_file(item_id)
    except ClamAvQuarantineNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "quarantine_item_not_found"})
    except ClamAvRestoreConflictError:
        raise HTTPException(status_code=409, detail={"error": "restore_path_conflict"})
    return {"restored_path": str(restored_path)}


@router.post("/consoles/av/clamav/reload")
async def clamav_reload(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """A-27: `clamd`'s own `RELOAD` command (see
    services/mcp/security_connectors/clamav.py.ClamdClient.reload) — makes
    clamd re-read the signature databases already present on its disk.
    Deliberately NOT "download new signatures from the internet" (that is
    `freshclam`'s job, a separate process this connector cannot trigger —
    see `ClamdClient.reload`'s docstring); the panel's own button is
    labelled "Перечитать базы" / "Reread databases", never "Update", so
    this honestly matches what actually happens.
    """
    client = create_clamav_client()
    if client is None:
        raise HTTPException(status_code=503, detail={"error": "clamav_not_configured"})
    try:
        await client.reload()
    except ClamdError as exc:
        raise HTTPException(status_code=503, detail={"error": f"clamav_{exc.reason}"})
    return {"reloaded": True}


# ---------------------------------------------------------------------------
# Post-merge user request (2026-08-02): the real, DB-persisted full-scan
# schedule + the elevated "Обновить базы сейчас" action — see
# `AvSettings`/`services/av/`/`clamav.update_clamav_databases`'s own
# docstrings for the full rationale.
# ---------------------------------------------------------------------------


class AvScanScheduleRequest(BaseModel):
    """Body for `POST /consoles/av/settings/full-scan-schedule`. `hour`/
    `minute`/`days` are range-constrained here (the request boundary)
    rather than inside `services/av/settings.update_av_settings` — same
    "validate at the boundary" split every other write path in this
    codebase follows.

    `days` (post-merge user request, 2026-08-02): 0=Monday...6=Sunday
    (Python's own `datetime.weekday()` convention, see
    AvSettings.full_scan_days's own docstring) — an empty list is accepted
    (not a 422): a schedule with `enabled=True` and no days checked yet is
    an honest, harmless interim state (never fires, self-explanatory in
    the settings display), not an error worth blocking the save over.
    """

    enabled: bool
    hour: int = Field(ge=0, le=23)
    minute: int = Field(ge=0, le=59)
    days: list[Annotated[int, Field(ge=0, le=6)]] = Field(default_factory=list)


@router.post("/consoles/av/settings/full-scan-schedule")
async def update_av_full_scan_schedule(
    body: AvScanScheduleRequest,
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    updated = await update_av_settings(
        session,
        enabled=body.enabled,
        hour=body.hour,
        minute=body.minute,
        days=body.days,
        now=datetime.now(timezone.utc).replace(tzinfo=None),
    )
    return {
        "enabled": updated.full_scan_schedule_enabled,
        "hour": updated.full_scan_hour,
        "minute": updated.full_scan_minute,
        "days": list(updated.full_scan_days),
    }


_CLAMAV_DB_UPDATE_ERROR_STATUS = {
    "elevation_cancelled": 409,
    "elevation_failed": 502,
}


@router.post("/consoles/av/clamav/update-databases")
async def clamav_update_databases(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """"Обновить базы сейчас" — real, one-shot elevated `docker exec
    freshclam` (see clamav.update_clamav_databases's own docstring for the
    full rationale, including why this is a button, never a schedule)."""
    try:
        result = await update_clamav_databases()
    except ClamAvDbUpdateError as exc:
        status_code = _CLAMAV_DB_UPDATE_ERROR_STATUS.get(exc.reason, 502)
        raise HTTPException(status_code=status_code, detail={"error": exc.reason})
    return result


@router.get("/consoles/network")
async def console_network(
    registry: SecurityConsoleRegistry = Depends(get_security_console_registry),
    session: AsyncSession = Depends(get_session),
    traffic_registry: TrafficCounterRegistry = Depends(get_traffic_counter_registry),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _network_payload(registry, session, traffic_registry)


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
    session: AsyncSession = Depends(get_session),
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await _logs_payload(registry, session)


@router.post("/consoles/logs/wazuh/syscheck")
async def wazuh_trigger_syscheck(_user: User = Depends(get_current_user)) -> dict[str, Any]:
    """A-30: `logs` console's "Запустить FIM-скан" action — an on-demand
    Wazuh FIM rescan of this deployment's configured agent. See
    `services/mcp/security_connectors/wazuh.py`'s
    `WazuhClient.trigger_syscheck` docstring for the live-verified real
    request shape: `PUT /syscheck` with `agents_list` as a query parameter —
    NOT the Wazuh REST API's own documented `PUT /syscheck/{agent_id}`, which
    405s against this deployment's actual manager (confirmed live before
    writing this, see the A-30 task report).

    Mirrors `clamav_quick_scan`'s not-configured/tool-error -> HTTPException
    mapping convention: an honest 503 with a machine-readable `error` code,
    never a raw 500.
    """
    try:
        affected = await trigger_syscheck_scan()
    except WazuhNotConfiguredError:
        raise HTTPException(status_code=503, detail={"error": "wazuh_not_configured"})
    except WazuhError as exc:
        raise HTTPException(status_code=503, detail={"error": f"wazuh_{exc.reason}"})
    return {"affected_items": affected}


@router.post("/consoles/export")
async def export_console_rows(
    body: ConsoleExportRequest,
    _user: User = Depends(get_current_user),
) -> Response:
    """A-30: universal "Экспорт журнала" mechanism, shared by BOTH the
    `logs` and `network` consoles (see app.js's `ACTION_HANDLERS.export_log`
    — one handler, wired to both consoles' export button) — not two
    separate export code paths. The client sends exactly the rows it
    already has rendered (`entries` for `logs`, `connections` for
    `network`); this endpoint only serializes them (see
    `services/security_console_export.py`), it never re-fetches or
    re-derives anything from a connector itself. Exporting exactly what is
    ON SCREEN at click time — not a fresh, possibly-different live snapshot
    fetched a moment later — is what "export the current console" honestly
    means, and is what the DoD's "byte-for-byte matches the UI" check
    verifies.
    """
    content, media_type = export_rows(body.rows, fmt=body.format)
    filename = export_filename(body.console_id, fmt=body.format)
    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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


# ---------------------------------------------------------------------------
# A-60: «Настройки → Стек защиты» — bootstrap стека (CrowdSec/ClamAV/Wazuh)
# прямо из приложения (services/stack/bootstrap.py) вместо ручных DevOps-
# шагов из infra/security/*/README.md.
#
# Только POST admin-only (require_role("admin")) — поднятие контейнеров и
# выдача креденшелов это write-операция уровня оператора; чтение статуса —
# обычный get_current_user, вровень с остальными GET-консолями.
#
# Оба эндпоинта возвращают машиночитаемые статусы и НИКОГДА не бросают
# 500 по причине «Docker не установлен» — это честные статусы шагов
# (plan-spec: «никаких исключений наружу»), текст локализует клиент.
# ---------------------------------------------------------------------------


@router.post("/stack/bootstrap")
async def stack_bootstrap(
    _user: User = Depends(require_role("admin")),
) -> dict[str, Any]:
    return await run_stack_bootstrap()


@router.get("/stack/status")
async def stack_current_status(
    _user: User = Depends(get_current_user),
) -> dict[str, Any]:
    return await stack_status()
