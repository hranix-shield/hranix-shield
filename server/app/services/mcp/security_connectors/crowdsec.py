"""A-11: CrowdSec integration — the one real security-stack connector this
task builds (Osquery/Wazuh/ClamAV are explicitly out of scope, see the A-11
task brief's risk note). CrowdSec itself is MIT-licensed and runs as a fully
separate Docker container (see infra/security/crowdsec/docker-compose.yml);
this module never imports/links CrowdSec's own code into this process, it
only ever speaks to its already-running Local API (LAPI) over plain HTTP —
the same "external service reached over the network, never linked in-process"
shape CLAUDE.md's licence gate requires for GPL/AGPL/MIT security tools, and
the same integration style already used for restic (services/backup/
restic_client.py, a subprocess) and SMTP (services/notifications/
smtp_client.py, a network client).

This module is deliberately scoped to exactly what a *bouncer* API key can
see through LAPI — confirmed empirically against a live `crowdsecurity/crowdsec`
container while building this task (see the A-11 task report for the
transcript):

  - `GET /v1/decisions` — every currently *active* decision (ban/captcha)
    CrowdSec knows about right now: `value` (the banned IP/range), `scenario`
    (which detection rule fired — the "vector"), `type` (`ban`/`captcha` —
    the "status"), `duration` (remaining time), `scope`, `origin`, `id`.
  - No creation timestamp is exposed on a decision, and no historical/expired
    decisions are reachable (that lives behind `/v1/alerts`, which requires
    *machine*-level LAPI auth used by `cscli`/the crowdsec agent itself, not
    a bouncer's `X-Api-Key`  — a bouncer key gets HTTP 401 there). The
    `since=`/`until=` query params documented for `/v1/decisions` were also
    tested live and do not filter the plain (non-stream) endpoint at all in
    the deployed version (an obviously-invalid `since=garbage` still returned
    every decision, unchanged) — so this module does not use them, and does
    not derive "banned in the last 24h" or "last event at" from them. Those
    two metrics stay honest `None` (see `fetch_ids_console_data` below), not
    a guessed number.
  - `active_bans`/`scenarios`/`recent_attempts` ARE real, computed from the
    live decisions list — not fabricated.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from app.config import Settings, get_settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry

logger = logging.getLogger(__name__)

CROWDSEC_CONNECTOR_NAME = "crowdsec"

_DECISIONS_PATH = "/v1/decisions"


def is_crowdsec_configured(settings: Settings) -> bool:
    """Both a LAPI URL and a bouncer API key are required — mirrors
    `notifications.smtp_client.is_smtp_configured`'s "no in-repo default for
    a third-party external service" reasoning."""
    return bool(settings.crowdsec_lapi_url and settings.crowdsec_api_key)


class CrowdSecError(RuntimeError):
    """Raised by `CrowdSecClient` methods on any failure to get a good answer
    out of LAPI. `reason` is one of:

      - `"unreachable"`: connection refused/timed out/DNS failure (the
        container is down or misconfigured), or LAPI answered with some
        other unexpected non-2xx status.
      - `"unauthorized"`: LAPI is reachable and answered, but rejected the
        configured API key (HTTP 401/403 — wrong key, or a bouncer that was
        since revoked via `cscli bouncers delete`).

    Kept as a dedicated `reason` field (not just an exception message)
    because the router needs to report a precise `connector.status` to the
    UI, not just "something went wrong" — see `fetch_ids_console_data`.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class CrowdSecClient:
    """Thin async HTTP client over one CrowdSec instance's LAPI, speaking to
    it exactly the way a real bouncer would: a static `X-Api-Key` header,
    read-only `GET /v1/decisions`. No CrowdSec code runs in this process —
    see this module's docstring.

    Client-ownership convention mirrors `OllamaBackend`
    (services/inference/ollama_backend.py): a caller-supplied `client`
    (tests: built on `httpx.MockTransport`) is used as-is and is that
    caller's to close; one built here owns its own connection pool, closed
    via `aclose()`.
    """

    def __init__(
        self,
        *,
        lapi_url: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._api_key = api_key
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(
            base_url=lapi_url.rstrip("/"), timeout=timeout
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def get_decisions(self, **params: str) -> list[dict[str, Any]]:
        """`GET /v1/decisions` — see this module's docstring for exactly
        what is (and is not) derivable from this call.

        CrowdSec's own API answers a JSON `null` body, not `[]`, when there
        are currently no active decisions — that translation happens here
        once so every caller can just iterate the result.
        """
        try:
            response = await self._client.get(
                _DECISIONS_PATH, params=params, headers={"X-Api-Key": self._api_key}
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(
                f"CrowdSec LAPI unreachable: {exc}", reason="unreachable"
            ) from exc

        if response.status_code in (401, 403):
            raise CrowdSecError(
                f"CrowdSec LAPI rejected the configured API key (HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code != 200:
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP {response.status_code}", reason="unreachable"
            )

        payload = response.json()
        return payload or []


def create_crowdsec_client(settings: Settings | None = None) -> CrowdSecClient | None:
    """A `CrowdSecClient` wired to real Settings, or `None` when
    `CROWDSEC_LAPI_URL`/`CROWDSEC_API_KEY` are not both set — mirrors
    `services.backup.wiring.create_default_scheduler`'s "return None when
    there is nothing to do" shape. Callers are responsible for calling
    `aclose()` on whatever this returns (when not None)."""
    settings = settings or get_settings()
    if not is_crowdsec_configured(settings):
        return None
    assert settings.crowdsec_lapi_url is not None  # narrowed by is_crowdsec_configured
    assert settings.crowdsec_api_key is not None
    return CrowdSecClient(lapi_url=settings.crowdsec_lapi_url, api_key=settings.crowdsec_api_key)


def _placeholder_ids_data(connector_status: str) -> dict[str, Any]:
    """The honest "no real data available" shape — used both when CrowdSec
    was never configured and when it is configured but unreachable/
    unauthorized right now. Every metric is `None` (not a fabricated `0`):
    the A-11 task brief is explicit that an unreachable connector must never
    render as "0 incidents", which would read as a false all-clear."""
    return {
        "connector": {"status": connector_status},
        "metrics": {
            "active_bans": None,
            "banned_24h": None,
            "scenarios": None,
            "last_event_at": None,
        },
        "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
        "recent_attempts": [],
    }


async def fetch_ids_console_data(settings: Settings | None = None) -> dict[str, Any]:
    """Real data for `GET /security/consoles/ids` (see
    routers/security_console.py._ids_payload). Never raises: a
    misconfigured/unreachable CrowdSec is reported as an honest
    `connector.status`, not a 500 and not a fabricated "all clear".

    - Not configured at all (`Settings.crowdsec_*` unset — the Phase 0
      default): `connector.status == "not_configured"`.
    - Configured but `CrowdSecError`: `connector.status` becomes that
      error's `reason` (`"unreachable"` / `"unauthorized"`).
    - Configured and reachable: `connector.status == "ok"`, and
      `active_bans`/`scenarios`/`recent_attempts` are real, computed from
      the live decisions list. `banned_24h`/`last_event_at` stay `None`
      even on success — genuinely not derivable from a bouncer's view of
      LAPI, see this module's docstring; this is not a missing feature, it
      is the actual shape of the data bouncers can see.
    """
    settings = settings or get_settings()
    client = create_crowdsec_client(settings)
    if client is None:
        return _placeholder_ids_data("not_configured")

    try:
        decisions = await client.get_decisions()
    except CrowdSecError as exc:
        logger.warning("crowdsec: %s", exc)
        return _placeholder_ids_data(exc.reason)
    finally:
        await client.aclose()

    # Most-recently-created first: CrowdSec assigns `id` in increasing
    # insertion order and exposes no creation timestamp (see module
    # docstring), so `id` descending is the best available "recent first"
    # ordering.
    decisions_by_recency = sorted(decisions, key=lambda d: d.get("id", 0), reverse=True)
    distinct_scenarios = {d["scenario"] for d in decisions if d.get("scenario")}

    return {
        "connector": {"status": "ok"},
        "metrics": {
            "active_bans": len(decisions),
            "banned_24h": None,
            "scenarios": len(distinct_scenarios),
            "last_event_at": None,
        },
        "chart": {"metric": "attempts_7d", "unit": "events", "values": []},
        "recent_attempts": [
            {
                "ip": decision.get("value"),
                "vector": decision.get("scenario"),
                "status": decision.get("type"),
            }
            for decision in decisions_by_recency
        ],
    }


def register_crowdsec_connector(registry: MCPRegistry, *, settings: Settings | None = None) -> None:
    """Registers this task's one real `MCPConnector` *description* (see
    connector.py's own docstring for why that class only holds metadata, not
    a live client — `CrowdSecClient` above is what actually talks to LAPI).
    This entry is what a future "Плагины/MCP-коннекторы" settings screen
    would read back via `MCPRegistry.list_connectors()`.

    `endpoint` is left `""` when unconfigured (same "not wired up yet, not
    an error" convention `MCPConnector.endpoint` documents) rather than some
    placeholder URL.
    """
    settings = settings or get_settings()
    registry.register(
        MCPConnector(
            name=CROWDSEC_CONNECTOR_NAME,
            description=(
                "CrowdSec — IPS/intrusion detection, read via its Local API "
                "(bouncer access). MIT license; runs as a separate Docker "
                "container, never linked into this process."
            ),
            transport="http",
            endpoint=settings.crowdsec_lapi_url or "",
        )
    )
