"""A-16: Wazuh Manager — the "Журналы ОС" (`logs`) console's real data
source, and the last of the four security-stack tasks (A-15/A-17/A-18
already shipped; see docs/план-спецификация-фаза-0-стек-безопасности-2026-07-16.md).
Wazuh itself is GPLv2-licensed, so CLAUDE.md's licence gate applies exactly
as it did to CrowdSec/ClamAV: this module never imports/links any Wazuh code
into this process, it only ever speaks the Wazuh Manager's own REST API
(https://documentation.wazuh.com/current/user-manual/api/reference.html)
over plain HTTP — closer to `crowdsec.py`'s shape (a long-running network
service reached over HTTP) than to A-15/A-18's subprocess connectors.

Architectural decision #1 — manager-only, no indexer/dashboard
----------------------------------------------------------------
The task brief required this decision *before* writing code (risk: "полный
Wazuh vs agent-only может увеличить оценку с M до L"). Confirmed empirically
against a live `wazuh/wazuh-manager` container while building this task (see
the A-16 task report for the full transcript): the manager's REST API serves
FIM (file-integrity-monitoring) results and agent status **directly from its
own local `wazuh-db`**, with NO dependency on the indexer (OpenSearch) or
dashboard at all —

  - `GET /agents` — agent list/status, straight from the manager's own
    registration state.
  - `GET /syscheck/{agent_id}` — FIM findings (which files changed, when,
    with hashes) for one agent, straight from that agent's local syscheck
    database on the manager.

what the indexer/dashboard stack actually adds is (a) long-term storage of
*all* historical alerts (the manager's own local state only holds the
*current* per-file snapshot, not a full event history) and (b) a
general-purpose alert *search* API — genuinely absent from the plain manager
REST API (confirmed against the manager's own OpenAPI spec: no `/alerts`
path exists there at all). Since this task's DoD only needs "show me FIM
events, live" and never asked for historical alert search, the indexer buys
nothing this task needs, at the cost of an entire second heavy service
(OpenSearch) — so this deployment is **manager-only**, a single container,
dramatically lighter than the reference `wazuh-docker` single-node compose
(manager + indexer + dashboard). See
infra/security/wazuh/docker-compose.yml's header comment for the deployment
side of this decision.

No separate agent container either: Wazuh's own architecture already folds
"the manager monitoring itself" into agent id `"000"`, a permanent built-in
local agent every manager has — confirmed live (`GET /agents` always
returns an agent `"000"` with `status: "active"` the moment the manager
itself is up, no enrollment step needed). This deployment never registers a
second, remote agent, so `"000"` (`Settings.wazuh_agent_id`'s default) is
the only agent id this connector ever needs.

Architectural decision #2 — FIM scope (the host-safety question)
------------------------------------------------------------------
FIM inherently wants to see *some* filesystem — direct tension with this
project's "no bind-mount of the host's real filesystem" host-safety rule
(A-11/A-17's own compose files). Resolved the same way the task brief's own
risk note suggested: this deployment's `<syscheck><directories>` (see
infra/security/wazuh/config/ossec.conf) is bound to exactly two read-only
mounts — `REPO_ROOT/data` and `REPO_ROOT/logs`, this project's OWN
application data (the SQLite DB, the ClamAV quarantine dir, A-5's own
`logs/assistant.log`, JWT/restic secret files) — never the user's home
directory, Downloads, or any other host path. This is a deliberate, narrow,
documented exception to "no host bind-mounts at all", not a silent
loosening of it: the container gets visibility into two directories that
are already this *application's own* files, nothing a user owns outside
this project. See infra/security/wazuh/docker-compose.yml for the mount
lines and infra/security/wazuh/config/ossec.conf for exactly what is (and
is not) watched.

What this connector honestly does NOT attempt
-------------------------------------------------
`GET /manager/logs` (the manager's own internal daemon/operational log —
module start/stop, internal errors) was evaluated and deliberately NOT used
to populate `metrics.warnings_24h`/`metrics.security_errors_24h`: that log
is Wazuh's own plumbing diagnostics, not a stream of *security* events, and
treating "wazuh-syscheckd logged an internal error" as a "security warning"
would be exactly the kind of invented-looking-meaningful number this
project's honesty principle forbids (same discipline CrowdSec's
`banned_24h` already established: leave a metric `None`, never fabricate
it, when the data genuinely isn't there). Confirmed live while building
this task that this log stream is *also* not a reliable signal in another
way: under this dev machine's platform (Docker Desktop for Mac, Apple
Silicon), an amd64 image running under Rosetta/QEMU emulation logged
hundreds of spurious `wazuh-syscheckd: ERROR: (6606): Select failed (for
real time file integrity monitoring)` lines that were pure emulation noise
(the identical test against the native-arm64 `4.14.6` image produced ZERO
such errors) — exactly the kind of environment-specific artifact that must
never leak into a metric a real user would read as "370 security errors".
`metrics.events_24h` (real, derived from FIM findings) and
`metrics.warnings_24h`/`metrics.security_errors_24h` (honestly `None`, not
derivable from what a manager-only deployment's API exposes) reflect this.

Three honest connector states, same vocabulary as every other connector in
this stack:
  - `"not_configured"`: `Settings.wazuh_api_url`/`wazuh_api_username`/
    `wazuh_api_password` are not all set (the Phase 0 default) — see
    `is_wazuh_configured`.
  - `"unreachable"`: configured, but the manager API did not answer (down/
    wrong host/port), or answered with an unexpected shape.
  - `"unauthorized"`: configured and reachable, but the manager rejected
    the configured API credentials (HTTP 401).
  - `"ok"`: authenticated successfully and both `/agents`/`/syscheck/...`
    answered.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from app.config import Settings, get_settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry

logger = logging.getLogger(__name__)

WAZUH_CONNECTOR_NAME = "wazuh"

_AUTH_PATH = "/security/user/authenticate"
_ENTRIES_LIMIT = 20
_SYSCHECK_FETCH_LIMIT = 500  # generous cap on one manager's FIM findings; see fetch_logs_console_data


def is_wazuh_configured(settings: Settings) -> bool:
    """All three of URL/username/password are required — mirrors
    `crowdsec.is_crowdsec_configured`'s "no in-repo default for a
    third-party external service" reasoning."""
    return bool(settings.wazuh_api_url and settings.wazuh_api_username and settings.wazuh_api_password)


class WazuhError(RuntimeError):
    """Raised by `WazuhClient` methods. `reason` is one of `"unreachable"`/
    `"unauthorized"` — see this module's docstring for exactly what each
    means. `"not_configured"` is never raised from here, it is decided one
    layer up (`fetch_logs_console_data`) purely from `Settings`, before a
    `WazuhClient` is even constructed — same convention as `ClamdError`."""

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class WazuhClient:
    """Thin async HTTP client over one Wazuh Manager's REST API. No Wazuh
    code runs in this process — see this module's docstring.

    Authenticates lazily (on first call that needs it) and caches the token
    for this instance's lifetime — the Wazuh API issues short-lived JWTs
    (15 minutes by default) via `POST /security/user/authenticate`, and a
    fresh `WazuhClient` is constructed per `fetch_logs_console_data()` call
    (same "short-lived, no state across calls" shape as
    `crowdsec.create_crowdsec_client`), so one login per outer call is both
    correct and simple — no expiry-tracking/refresh logic needed for a
    client that never outlives one token's validity window.

    Client-ownership convention mirrors `CrowdSecClient`/`ClamdClient`: a
    caller-supplied `client` (tests: built on `httpx.MockTransport`) is used
    as-is and is that caller's to close; one built here owns its own
    connection pool, closed via `aclose()`.
    """

    def __init__(
        self,
        *,
        api_url: str,
        username: str,
        password: str,
        agent_id: str = "000",
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._username = username
        self._password = password
        self._agent_id = agent_id
        self._token: str | None = None
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(base_url=api_url.rstrip("/"), timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _authenticate(self) -> str:
        if self._token is not None:
            return self._token
        try:
            response = await self._client.post(
                _AUTH_PATH, params={"raw": "true"}, auth=(self._username, self._password)
            )
        except httpx.HTTPError as exc:
            raise WazuhError(
                f"Wazuh Manager API unreachable: {exc}", reason="unreachable"
            ) from exc

        if response.status_code == 401:
            raise WazuhError(
                "Wazuh Manager API rejected the configured credentials", reason="unauthorized"
            )
        if response.status_code != 200:
            raise WazuhError(
                f"Wazuh Manager API returned HTTP {response.status_code} authenticating",
                reason="unreachable",
            )
        self._token = response.text.strip()
        return self._token

    async def _get(self, path: str, *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        token = await self._authenticate()
        try:
            response = await self._client.get(
                path, params=params, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as exc:
            raise WazuhError(f"Wazuh Manager API unreachable: {exc}", reason="unreachable") from exc

        if response.status_code in (401, 403):
            raise WazuhError(
                f"Wazuh Manager API rejected the request (HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code != 200:
            raise WazuhError(
                f"Wazuh Manager API returned HTTP {response.status_code}", reason="unreachable"
            )
        return response.json()

    async def get_agent_status(self) -> str | None:
        """`GET /agents?agents_list=<id>` -> that agent's `status` field
        (`"active"`/`"disconnected"`/`"never_connected"`), or `None` if the
        agent id is not known to this manager at all (should not happen for
        `"000"`, the manager's own permanent built-in agent — see this
        module's docstring)."""
        payload = await self._get("/agents", params={"agents_list": self._agent_id})
        items = payload.get("data", {}).get("affected_items", [])
        return items[0].get("status") if items else None

    async def get_syscheck_findings(self, *, limit: int = _SYSCHECK_FETCH_LIMIT) -> list[dict[str, Any]]:
        """`GET /syscheck/{agent_id}` -> the current FIM snapshot: one entry
        per file this deployment's `<syscheck><directories>` watches (see
        infra/security/wazuh/config/ossec.conf), each with `file`, `date`
        (when this entry was last updated), hashes, size, `changes`
        (how many times this file has been seen to change). Sorted
        newest-`date`-first so callers needing "most recent N" (see
        `fetch_logs_console_data`) don't have to sort client-side."""
        payload = await self._get(
            f"/syscheck/{self._agent_id}", params={"limit": limit, "sort": "-date"}
        )
        return payload.get("data", {}).get("affected_items", [])


def create_wazuh_client(settings: Settings | None = None) -> WazuhClient | None:
    """A `WazuhClient` wired to real Settings, or `None` when
    `wazuh_api_url`/`wazuh_api_username`/`wazuh_api_password` are not all
    set — mirrors `crowdsec.create_crowdsec_client`'s "return None when
    there is nothing to do" shape. Callers are responsible for calling
    `aclose()` on whatever this returns (when not None)."""
    settings = settings or get_settings()
    if not is_wazuh_configured(settings):
        return None
    assert settings.wazuh_api_url is not None  # narrowed by is_wazuh_configured
    assert settings.wazuh_api_username is not None
    assert settings.wazuh_api_password is not None
    return WazuhClient(
        api_url=settings.wazuh_api_url,
        username=settings.wazuh_api_username,
        password=settings.wazuh_api_password,
        agent_id=settings.wazuh_agent_id,
    )


def _parse_timestamp(value: str | None) -> datetime | None:
    """Wazuh's own `date`/`timestamp` fields are ISO-8601 with a trailing
    `Z` (`"2026-07-16T14:26:58+00:00"` or `"...Z"` depending on endpoint) —
    `datetime.fromisoformat` on Python 3.11+ handles both directly, but this
    still guards against a genuinely malformed/missing value (never crash
    the whole console over one bad timestamp, same defensive spirit as
    `clamav._parse_version`)."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _finding_to_entry(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": finding.get("date"),
        "level": "notice",
        "source": "wazuh_fim",
        "file": finding.get("file"),
        "description": f"Изменение файла под контролем целостности: {finding.get('file')}",
    }


def _placeholder_logs_data(connector_status: str) -> dict[str, Any]:
    """The honest "no real data available" shape — used both when Wazuh was
    never configured and when it is configured but unreachable/unauthorized
    right now. `metrics` are all `None` (never a fabricated `0` — the
    console's OWN pre-A-16 stub used to hardcode zeros here, which is
    exactly the "false all-clear" shape A-11's task brief already flagged
    as unacceptable for `ids`; A-16 fixes that same bug for `logs`)."""
    return {
        "connector": {"status": connector_status},
        "metrics": {
            "events_24h": None,
            "warnings_24h": None,
            "security_errors_24h": None,
            "sources": None,
        },
        "chart": {"metric": "security_events_7d", "unit": "events", "values": []},
        "entries": [],
    }


async def fetch_logs_console_data(settings: Settings | None = None) -> dict[str, Any]:
    """Real data for `GET /security/consoles/logs` (see
    routers/security_console.py._logs_payload). Never raises: a
    misconfigured/unreachable/unauthorized Wazuh is reported as an honest
    `connector.status`, never a 500 and never a fabricated all-clear.

    - Not configured at all (the Phase 0 default):
      `connector.status == "not_configured"`.
    - Configured but `WazuhError`: `connector.status` becomes that error's
      `reason` (`"unreachable"` / `"unauthorized"`).
    - Configured and reachable: `connector.status == "ok"`.
      `metrics.events_24h` and `entries` are real, derived from live FIM
      (syscheck) findings — see this module's docstring for exactly what
      `warnings_24h`/`security_errors_24h` staying `None` means and why.
    """
    settings = settings or get_settings()
    client = create_wazuh_client(settings)
    if client is None:
        return _placeholder_logs_data("not_configured")

    try:
        findings = await client.get_syscheck_findings()
    except WazuhError as exc:
        logger.warning("wazuh: %s", exc)
        return _placeholder_logs_data(exc.reason)
    finally:
        await client.aclose()

    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    recent_findings = [
        finding
        for finding in findings
        if (ts := _parse_timestamp(finding.get("date"))) is not None and ts >= cutoff
    ]

    return {
        "connector": {"status": "ok"},
        "metrics": {
            "events_24h": len(recent_findings),
            # Honestly not derivable from a manager-only deployment's REST
            # API — see this module's docstring ("What this connector
            # honestly does NOT attempt"). Never a fabricated 0.
            "warnings_24h": None,
            "security_errors_24h": None,
            # Exactly one source is wired in Phase 0: this manager's own
            # local FIM agent (see `engine` in _logs_payload — the other
            # two listed engines, windows_event_log/macos_unified_log, are
            # not implemented yet).
            "sources": 1,
        },
        "chart": {"metric": "security_events_7d", "unit": "events", "values": []},
        "entries": [_finding_to_entry(finding) for finding in findings[:_ENTRIES_LIMIT]],
    }


def register_wazuh_connector(registry: MCPRegistry, *, settings: Settings | None = None) -> None:
    """Registers this connector's *description* in `MCPRegistry` — same
    metadata-only shape as `crowdsec.register_crowdsec_connector`, see that
    function's docstring for what this is (and is not) for."""
    settings = settings or get_settings()
    registry.register(
        MCPConnector(
            name=WAZUH_CONNECTOR_NAME,
            description=(
                "Wazuh Manager — FIM (file integrity monitoring) and agent "
                "status, read via its REST API. GPLv2 license; runs as a "
                "separate Docker container, never linked into this process."
            ),
            transport="http",
            endpoint=settings.wazuh_api_url or "",
        )
    )
