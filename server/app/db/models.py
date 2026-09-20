from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Index, Integer, String, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class BackupJob(Base):
    __tablename__ = "backup_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    target_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(50), nullable=False)


class Notification(Base):
    """A-13: one delivery attempt of an event-bus event through the
    notification channel matrix (see services/notifications/).

    `channels` is the JSON list of channel ids the matrix had enabled for
    `topic` at the moment this row was created (post quiet-hours filtering
    below) — an empty list on a `suppressed_quiet_hours=True` row means
    "matched channels existed, but none were actually used", not "no
    channels were configured".

    `read_at`/`acknowledged_at` are distinct: `read_at` is the lightweight
    "seen in the panel" mark used by the topbar's unread badge (channel 4);
    `acknowledged_at` is the explicit "someone dealt with this" action that
    stops the escalation sweep (services/notifications/escalation.py) from
    treating a critical notification as still outstanding. A row can be
    read without being acknowledged (glanced at the bell, didn't act yet).
    """

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    critical: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    channels: Mapped[list | None] = mapped_column(JSON, nullable=True)
    suppressed_quiet_hours: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    email_sent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    escalated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MetricSample(Base):
    """A-26: one point-in-time numeric reading of a security console's
    metric — the history mechanism this project never had (see
    docs/план-спецификация-фаза-0-реальные-функции-панели-2026-07-19.md's
    "Технический аудит": every console's `chart.values` was a hardcoded
    `[]`, even on `perimeter`/`ids` where CrowdSec already computed a real
    `active_bans` number — it just never landed anywhere durable). Written
    every `Settings.metrics_sample_interval_seconds` by
    `services/metrics/sampler.py`'s `MetricsSampleScheduler`, read back by
    `services/metrics/chart.py`'s `chart_values_7d()` — which
    `routers/security_console.py`'s per-console payload functions call to
    fill each console's own `chart.values` (`backup` excluded: it already
    has its own real history in `backup_jobs`, see
    services/backup/wiring.py._size_chart_7d — untouched by this table).

    `console_id`/`metric` together identify one time series (e.g.
    `("ids", "active_bans_local")`) — deliberately two plain string columns,
    not a foreign key to `ConsoleId`/an enum column: a metric name is this
    table's own concern, chosen per-console by the sampler
    (services/metrics/sampler.py documents exactly which field from each
    connector is sampled, and why), not a fixed schema-level enum that
    would need a migration every time a new metric is added.

    Indexed on `(console_id, metric, sampled_at)` — the exact shape every
    read query filters/orders by (`chart_values_7d`'s "last 7 days of this
    one console's one metric, oldest first").
    """

    __tablename__ = "metric_samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    console_id: Mapped[str] = mapped_column(String(50), nullable=False)
    metric: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[float] = mapped_column(Float, nullable=False)
    sampled_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index(
            "ix_metric_samples_console_metric_sampled_at",
            "console_id",
            "metric",
            "sampled_at",
        ),
    )


class ScanHistory(Base):
    """A-33: one COMPLETED ClamAV scan (quick/full/custom alike) — the
    persistent history `services/mcp/security_connectors/clamav.py`'s own
    `ClamAvScanJobRegistry` docstring has flagged as a Phase 0 limitation
    since A-17 ("in-memory only... a future task can persist this to the DB
    if that turns out to matter"): that registry resets on every restart, so
    an operator could only ever see the CURRENT/most-recent scan's outcome,
    never "what ran last Tuesday". Written once, by
    `clamav.record_scan_history()`, right after `run_quick_scan`/
    `start_full_scan`/`run_custom_scan` genuinely finish — never for a scan
    that never started at all (clamd unconfigured/unreachable before a
    single file was read), so every row here represents real, completed
    work, never a fabricated "0 scanned, 0 infected".

    `scan_type` is `"quick"` | `"full"` | `"custom"` — deliberately a plain
    string column, not an enum/FK, same "the value space is this module's
    own concern" reasoning `MetricSample.metric` already documents.

    `path` is nullable: quick/full scan a fixed, multi-directory target set
    (Downloads+temp / the home directory), not one operator-chosen path —
    only `"custom"` rows ever populate this column (see
    `clamav.run_custom_scan`).

    Indexed on `finished_at` alone (not a composite like `MetricSample`):
    every read query here is "the last N scans across all types", not
    "history of one specific (console, metric) pair" — `chart_values_7d`'s
    per-series lookup has no equivalent here, so a single-column index on
    the one column every query orders by is enough.
    """

    __tablename__ = "scan_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_type: Mapped[str] = mapped_column(String(20), nullable=False)
    path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    scanned_count: Mapped[int] = mapped_column(Integer, nullable=False)
    infected_count: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    finished_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_scan_history_finished_at", "finished_at"),
    )


class BlockedPort(Base):
    """A-37: one PORT this operator has explicitly asked Hranix Shield to
    block, via the perimeter console's per-port detail modal (see
    `app.js`'s `openPortModal`/`handleBlockPort`) — the persistent,
    survives-a-server-restart counterpart to the one-shot OS-level
    enforcement `services/mcp/security_connectors/os_firewall.py`'s
    `block_port()`/`unblock_port()` actually apply (macOS: a dedicated pf
    anchor `hranix-blocked-ports`; Linux: the `HRANIX-BLOCKED` iptables
    chain; Windows: `New-NetFirewallRule` rules named `"Hranix Shield -
    Block port N (...)"`) — same "the OS-level action was already A-36's
    real work, this table is durable bookkeeping" relationship
    `scan_history` (A-33) already has to `ClamAvScanJobRegistry`'s
    in-memory jobs, see that model's own docstring for the identical
    reasoning.

    Written ONLY once `os_firewall.block_port()` has already returned
    `status: "ok"` (see `routers/security_console.py`'s
    `perimeter_block_port`) — never speculatively before the elevated OS
    action is confirmed to have actually applied, matching this whole
    project's "never fabricate a state that has not genuinely happened
    yet" discipline. `port` is UNIQUE: a port is either currently blocked
    (one row) or it is not (no row) — there is no meaningful "blocked
    twice" state, re-blocking an already-blocked port updates the existing
    row in place (see `os_firewall.record_blocked_port`) rather than
    inserting a second one.

    `protocol`/`process_name` are both nullable, purely descriptive context
    captured from the `ports` table row the operator clicked at block time
    (see `security_console.py`'s `PerimeterBlockPortRequest`) — never
    re-validated against a fresh osquery query here, and honestly `None`
    when a caller does not supply them (e.g. a bare API call with no
    body), never guessed. Note this table's OWN enforcement is
    deliberately NOT scoped to `protocol`: `block_port`/`unblock_port`
    always block/unblock the whole port number (both TCP and UDP) — the
    `POST/DELETE .../ports/{port}/block` endpoint shape this task's own
    plan document specifies has no `?protocol=` parameter, so `protocol`
    here is display-only, not an enforcement filter.

    Unlike `ScanHistory`/`MetricSample` above, `list_blocked_ports()`
    (os_firewall.py) is not just an append-only history read — it is also
    the single source of truth `block_port()`/`unblock_port()` themselves
    read back BEFORE every single call, to reconstruct macOS's own pf
    anchor content in full each time (pf has no incremental
    add-one-rule-to-an-anchor primitive, see
    `os_firewall._build_macos_sync_blocked_ports_script`'s own docstring
    for why) — so, unlike `record_scan_history`'s deliberate "never let a
    history-write failure block the primary action's own success
    response" swallow-and-log discipline, `record_blocked_port`/
    `delete_blocked_port` deliberately do NOT swallow their own write
    failures: a silently-failed write here would leave this table out of
    sync with the real OS-level state that future calls reconstruct from,
    a genuine correctness bug, not just a missing history entry.
    """

    __tablename__ = "blocked_ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    port: Mapped[int] = mapped_column(Integer, nullable=False, unique=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class BlockedIp(Base):
    """A-52: one IP address this operator has explicitly asked Hranix
    Shield to block, via the network console's connection-detail modal
    (see `app.js`'s `openConnectionModal`/`handleBlockIp`) — the
    persistent, survives-a-server-restart counterpart to the one-shot
    OS-level enforcement `os_firewall.py`'s `block_ip()`/`unblock_ip()`
    actually apply. Mirrors `BlockedPort` above 1-to-1 (same "written only
    after the elevated action already returned ok" discipline, same
    upsert-not-duplicate `ip` uniqueness, same "this table is the source
    of truth macOS's pf-anchor reconstruction reads back on every call, a
    lost write here is a correctness bug not just a missing history row")
    — see that class's own docstring for the full reasoning, not repeated
    here. Kept as its own table (not folded into `BlockedPort` with a
    nullable `port`) because a blocked IP and a blocked port are genuinely
    different enforcement scopes with different OS-level mechanisms
    (own pf anchor `hranix-blocked-ips`, own iptables chain
    `HRANIX-BLOCKED-IPS`) — see `os_firewall.py`'s own A-52 section
    docstring.

    `country`/`process_name` are the same purely-descriptive, never
    re-validated display context `BlockedPort.protocol`/`process_name`
    already are — captured from the connection row the operator clicked
    at block time. `reason` is new here (not on `BlockedPort`) — the
    connection modal's own honest note of WHY (e.g. "подозрительный узел
    по CrowdSec" when `is_suspicious` was true on the row blocked, `None`
    when the operator just blocked a plain address with no CrowdSec
    signal either way)."""

    __tablename__ = "blocked_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    process_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    blocked_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class NetworkProfile(Base):
    """A-38: one KNOWN network this host has connected to — an operator-
    assigned CATEGORY (`"trusted"` | `"public"`, plain string column, same
    "value space is this module's own concern" reasoning `ScanHistory.
    scan_type`/`MetricSample.metric` above already document, not an enum/FK)
    that decides how strict a posture
    `services/mcp/security_connectors/network_profile.py`'s background
    monitor nudges the operator toward while THIS network is the current
    one — see that module's own docstring for the full detection mechanism
    and why the monitor only ever NUDGES (a `security.alert` notification)
    rather than silently calling `os_firewall.block_all_incoming()` itself.

    Every network ever detected gets a row here — written on first sight by
    `network_profile.touch_network_profile()` (called by the background
    scheduler's own periodic tick, NEVER by a passive `GET
    /consoles/perimeter` page load — a read must stay a pure read, same
    principle every other console payload function in this codebase already
    follows) — defaulting to `"public"`, the safe default for an unfamiliar
    network (this task's own brief: "по умолчанию — 'Публичная', безопасный
    дефолт для незнакомой сети"). The only thing that ever CHANGES an
    already-persisted `category` is the operator's own explicit click (`POST
    .../network-profile/category`, `network_profile.set_network_category()`)
    — a scheduler tick never overwrites an operator's prior choice.

    `network_key` is NOT always a human-readable SSID: see
    `network_profile.py`'s docstring for the honest, LIVE-CONFIRMED
    limitation that macOS's own Wi-Fi-name read (`networksetup
    -getairportnetwork`) is access-gated even for a plain, non-root process
    on this dev machine — `network_key` is whatever STABLE identifier the
    detector actually obtained (a real SSID when readable, a gateway-IP-
    based fallback key otherwise, a NetworkManager connection UUID on
    Linux, an `Get-NetConnectionProfile` profile name on Windows), always
    tagged with `id_kind` so the UI can render an honest label instead of
    presenting every key as if it were a real network name.
    """

    __tablename__ = "network_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    network_key: Mapped[str] = mapped_column(String(300), nullable=False)
    display_name: Mapped[str] = mapped_column(String(300), nullable=False)
    id_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    category: Mapped[str] = mapped_column(String(20), nullable=False, default="public")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (
        Index("ix_network_profiles_network_key", "network_key", unique=True),
    )


class AvSettings(Base):
    """Post-merge user request (2026-08-02): `av`'s "Настройки" panel used to
    display 4 fields that were ALL hardcoded Python literals in
    `_av_payload` — `realtime_protection`/`scan_removable_media` described
    capabilities this project's ClamAV connector genuinely does not
    implement at all (no on-access scanning, no OS-level removable-media
    detection anywhere in this codebase — see the investigation this task
    started from), and `scan_schedule` was a displayed string with zero
    background enforcement (no scheduler ever read it). This table is the
    honest, real, DB-persisted replacement for the one setting that COULD
    be made genuinely real without inventing a new OS subsystem: an actual
    daily full-scan schedule a real background scheduler
    (`services/mcp/security_connectors/clamav.AvScanScheduler`) reads and
    acts on.

    Single-row table (id is always 1 — enforced by convention in
    `clamav.get_av_settings`/`update_av_settings`, not a DB constraint,
    same "one row of config" shape `NotificationRegistry` uses in-memory,
    just durable here because the user explicitly wants this to survive a
    restart and be editable without one). `full_scan_hour`/
    `full_scan_minute` are naive UTC, same convention
    `services/backup/scheduler.py`'s own module docstring already commits
    this whole codebase to (sidesteps DST ambiguity; "HH:MM" means UTC, not
    the operator's own laptop time — same scoped simplification, not a new
    one invented here).

    `action_on_threat`/`scan_removable_media` are NOT columns here: the
    former stays a fixed, honest "quarantine" (the only action this
    project's ClamAV connector can actually perform, see
    `clamav.quarantine_file` — no "block"/"delete" code path exists to
    make configurable), and the latter was removed outright rather than
    persisted-but-inert (same "don't keep a permanently-disabled ghost
    setting" convention this project already applied when the dead
    top-level "Разбанить IP" placeholder was removed, A-29-era fix).

    `full_scan_days` (post-merge user request, 2026-08-02): which days of
    the week the schedule fires on, a JSON list of ints (Python's own
    `datetime.weekday()` convention — 0=Monday...6=Sunday), e.g. `[0,2,4]`
    for Mon/Wed/Fri. Defaults to all 7 days (`[0,1,2,3,4,5,6]`, both at the
    Python level for a fresh row and via a server-side migration default for
    any row that already existed before this column was added) so an
    already-configured daily schedule keeps firing every day exactly as
    before, rather than silently going quiet because "no days" reads as
    "never" — the same "don't let a schema change silently change existing
    behaviour" care `full_scan_schedule_enabled`'s own honest-off default
    already takes for a FRESH row."""

    __tablename__ = "av_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    full_scan_schedule_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    full_scan_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=6)
    full_scan_minute: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    full_scan_days: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=lambda: [0, 1, 2, 3, 4, 5, 6])
    updated_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
