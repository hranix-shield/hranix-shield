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

A-23 addendum (2026-07-18): a real user reported seeing "16673 active bans"
on the "Обнаружение вторжений" (intrusion detection) console with no
explanation. Investigation found the number itself was real but not what it
looked like: an unfiltered `GET /v1/decisions` returns EVERY decision LAPI
currently knows about, and on the box this was built on 16675 of 16675 were
synced down from CrowdSec's central community blocklist (CAPI — IPs OTHER
CrowdSec users' machines reported), not attempts against this machine.
Confirmed live, against a real bouncer key, before writing the fix below:

  - `?origin=`/`?scope=`/`?type=` query params on `/v1/decisions` were each
    tried live (including an intentionally-bogus `origin=` value as a sanity
    check that the param does anything at all) — none of them filter the
    response: every variant returned the same 16675 decisions, unchanged.
    Same non-finding as the pre-existing `since=`/`until=` note above, so
    this module still does not rely on any query param to narrow this
    endpoint — filtering happens client-side, on the already-fetched list.
  - Each decision's own `origin` field IS populated and does reliably tell
    local and community-list decisions apart: every CAPI-sourced decision
    observed carried `"origin": "CAPI"`; a decision added locally (tested via
    `cscli decisions add --ip ... --reason ...` against the live container,
    then confirmed to show up in `cscli decisions list` *without* `-a`)
    carried `"origin": "cscli"` instead — never `"CAPI"`. So "local" here
    means "any decision whose `origin` is not `CAPI`" (see
    `_is_community_decision` below), matching exactly what `cscli decisions
    list` without `-a` shows a human operator.

A-29 addendum (2026-07-19): "Забанить вручную"/"Разбанить IP" needed real
ban/unban, which the bouncer key above cannot do by CrowdSec's own design
(confirmed again here, deliberately, before writing this: `POST /v1/alerts`
with the bouncer's `X-Api-Key` answers HTTP 401). CrowdSec's *machine*-level
LAPI auth is a second, genuinely separate credential class — provisioned via
`cscli machines add` (see infra/security/crowdsec/docker-compose.yml's
header comment and infra/security/crowdsec/README.md for the exact command
run against this project's own dev container) — that trades a static header
for a short-lived JWT. Everything below was confirmed live against the same
`hranix-crowdsec` container used throughout this file, not assumed from
CrowdSec's docs:

  - `POST /v1/watchers/login` with `{"machine_id": ..., "password": ...}`
    answers `{"code": 200, "expire": "<ISO-8601 'Z' timestamp>", "token":
    "<JWT>"}` on success (observed expiry: exactly 1 hour after login) and
    `{"code": 401, "message": "incorrect Username or Password"}` on a wrong
    password — `CrowdSecClient._login_machine` below caches the token for
    exactly that window (minus a small safety margin), re-logging in once
    it is close to expiring, rather than once per call.
  - `POST /v1/alerts` is genuinely how a ban is created — there is no
    separate "create one decision" endpoint at the LAPI level. Captured the
    *exact* request body `cscli decisions add --ip ... --debug/--trace`
    sends over the wire (via `docker exec ... cscli decisions add --ip
    <test-ip> --duration 5m --reason ... --trace`, then deleted the
    resulting test decision immediately after) and `CrowdSecClient.create_ban`
    below reproduces that same shape verbatim (one alert wrapping one
    decision) rather than guessing at the schema from documentation.
    Success answers HTTP 201 with a JSON array of new alert ids (e.g.
    `["24"]`) — but a request CrowdSec's own alert-schema validation
    accepts (e.g. a scope/value pair its IP parser rejects, tested live with
    `"value": "not-an-ip"`) can still come back 201 with an EMPTY array: no
    decision was actually created, no error either. That is why this
    module's own `create_ban` validates the IP with Python's `ipaddress`
    *before* ever calling LAPI (never rely on LAPI to reject a bad IP for
    us), and additionally treats a 201-with-empty-list as `reason="rejected"`
    rather than silently reporting success.
  - `DELETE /v1/decisions/{id}` (the SAME `id` `GET /v1/decisions` already
    exposes on each flattened decision — confirmed live to be the nested
    per-decision id, e.g. `88500`, not the wrapping alert's own id, e.g.
    `24`, which only appears in `/v1/alerts`' own shape) answers `{
    "nbDeleted": "1"}` (a string, not an int) with HTTP 200 on success.
    Deleting an id that never existed answers **HTTP 500** (not 404) with
    `{"message": "decision with id '<id>' doesn't exist: unable to
    delete"}` — confirmed live against a deliberately-bogus id — so
    `delete_decision` below treats *that specific* 500 shape as
    `reason="not_found"`, not a generic failure.
  - Both write endpoints reject the bouncer's own credential shape
    entirely: no `Authorization: Bearer` header at all answers `{"code":
    401, "message": "cookie token is empty"}` on both — confirmed live —
    which is a third distinct 401 message from the bouncer-key one above,
    all mapped to the same `reason="unauthorized"` regardless (the UI only
    needs to know "rejected", not which of the three exact messages).

`ban_ip`/`unban_decision` (module-level, mirroring `fetch_ids_console_data`'s
"create a short-lived client, use it once, close it" shape) are what
routers/security_console.py's new `/consoles/ids/crowdsec/ban` and
`.../decisions/{id}` endpoints call — see those docstrings for the honest
"not configured" vs "unreachable"/"unauthorized" vs real-failure vocabulary,
same as every other connector in this stack.

A-42 addendum (2026-07-23): the `ids` console's `settings` block
(routers/security_console.py._ids_payload) shipped four hardcoded A-11
placeholders (`ban_threshold: 5`, `ban_duration_hours: 4`,
`whitelist_count: 0`, `rule_source: "crowdsec_hub"`) that were never read
from real CrowdSec and never editable — a user reasonably asked "how do I
change these?". Investigated live against the same `hranix-crowdsec`
container this whole file already targets, before writing the fix below:

  - `GET /v1/allowlists?with_content=true` genuinely IS reachable through
    LAPI and returns real allowlist data (each entry: `name`,
    `allowlist_id`, `description`, `console_managed`, and — because
    `with_content=true` — an inlined `items` array of `{value,
    description, expiration, created_at}`, confirmed against CrowdSec's
    own published `localapi_swagger.yaml`) — but confirmed live that it
    needs the SAME machine-level credential `create_ban`/`delete_decision`
    above use, not the bouncer `X-Api-Key`: a bouncer key sent here gets
    HTTP 401 with `{"message": "cookie token is empty"}`, the identical
    rejection shape `create_ban`'s "A-29 addendum" note already documents
    for the write endpoints. `fetch_allowlists`/`CrowdSecClient.
    get_allowlists` below therefore reuse `create_crowdsec_write_client`
    (A-29's machine credential) rather than inventing a third credential
    class — per this task's own brief.
  - Every write method on `/v1/allowlists*` — `POST`/`PUT`/`PATCH`/
    `DELETE` — was tried live and answers a plain HTTP 405 regardless of
    credentials (confirmed with NO `Authorization`/`X-Api-Key` header at
    all too, so this is LAPI's own route table rejecting the method
    before any auth check runs, not a permissions gate a different
    credential could get past). `cscli allowlists add/create/remove` is a
    direct CLI operation against the container's local database, with no
    HTTP-level equivalent at all — so editing the allowlist from this
    panel is not reachable without `docker exec` into the container (see
    the, AT THE TIME this A-42 task was built, still-disabled "Обновить
    сценарии" button for the same honest-disable pattern this task itself
    used — see this module's own "A-45 addendum" docstring section further
    below for why "Обновить сценарии" itself no longer fits that
    description as of A-45).
    `fetch_allowlists` below is READ-ONLY by construction — there is no
    write function IN THIS `GET /v1/allowlists*`-over-LAPI section of the
    module, on purpose (LAPI genuinely cannot do it, full stop). A-44
    addendum (2026-07-25): this is no longer the end of the story for the
    PANEL as a whole — see the "A-44 addendum" section further below and
    `add_to_allowlist`/`remove_from_allowlist` near the bottom of this
    file, which write via elevated `docker exec cscli allowlists ...`
    instead, the same narrow exception A-43's scenario-threshold section
    already established. `fetch_allowlists` itself is unchanged (still
    LAPI-only, still read-only) and is exactly what those two new
    functions reuse for their own mandatory readback.
  - `GET /v1/scenarios`, `GET /v1/hub`, and `GET /v1/config` — the three
    most plausible places a single "ban threshold"/"ban duration" could
    live — all answer HTTP 404 (confirmed live, with the bouncer key).
    This is not a missing permission: CrowdSec has no such endpoints at
    all, because it has no such single setting — `leakspeed`/`capacity`
    are configured per-scenario, in that scenario's own YAML file inside
    the container, and there is no "one global threshold" concept in
    CrowdSec's data model to read even with full access. The old
    `ban_threshold: 5`/`ban_duration_hours: 4` placeholders were
    therefore not just unread-from-CrowdSec (like `rule_source` still is)
    but described a setting that does not exist — routers/
    security_console.py._ids_payload now sends an honest machine-readable
    marker instead (see that function's own docstring), never a number.

A-43 addendum (2026-07-24): the user asked why `ban_policy`'s
"per_scenario" text can't just be edited from the panel. Per
docs/план-спецификация-фаза-0-порог-сценариев-2026-07-24.md's "Важное
архитектурное решение" (read that document for the full rationale, not
reargued here): a real screen now exists (`read_scenario_thresholds`/
`write_scenario_threshold` below) via a narrow, EXPLICIT exception to this
project's "никогда docker exec" principle — every call is its own one-shot,
never-cached, visible OS admin-password prompt through the SAME
`elevated_run()` primitive `os_firewall.py`'s A-36/A-37 actions already use,
directly mirroring how A-36 itself already narrowed "никогда не повышать
привилегии приложения целиком" without abandoning it. "Обновить сценарии"
(this module's own `fetch_allowlists` docstring above) deliberately does
NOT get this same treatment: `cscli hub update` pulls and runs THIRD-PARTY
code from hub.crowdsec.net on every call (a genuinely bigger, supply-
chain-shaped risk class, not the same kind of decision at all). **REVISED
by A-45 below, not silently reversed** — see this docstring's own "A-45
addendum" section further down: a real, official CrowdSec preview
mechanism (`cscli hub upgrade --dry-run`) was later found that narrows
(does not eliminate) exactly this supply-chain risk enough to enable the
action after all, via a two-step preview-then-apply UX, not a single
one-click "Обновить". This paragraph's own risk analysis was correct at
the time it was written (no such mechanism had been investigated yet), not
a mistake. "Добавить в белый список" was, AT THE TIME A-43 was built,
simply a different, unbuilt feature, not that task's scope — see the
"A-44 addendum" section below for why that changed one task later (A-44
built it, applying this SAME A-43 exception to a second action, not
re-deciding whether the exception itself is safe).

A-44 addendum (2026-07-25): the user asked, immediately after A-43 shipped,
why "Добавить в белый список" couldn't get the exact same treatment —
`cscli allowlists create/add/remove` (see the "A-42 addendum" section
above for why LAPI itself has no HTTP equivalent for these at all) are
direct `cscli` CLI operations, not third-party code and not a YAML file to
hand-edit — a narrower, SIMPLER case than A-43's own sed-based scenario
write (no multi-document file parsing, no `docker compose restart`: see
`add_to_allowlist`/`remove_from_allowlist` near the end of this file for
the full design and the live-confirmed `cscli allowlists create`
non-idempotency this section's own script works around). This is the
SAME exception A-43 already established, applied to a second action —
not a re-opening of whether the exception itself is safe (see
docs/план-спецификация-фаза-0-белый-список-запись-2026-07-25.md's own
"Архитектурное решение — не переоткрывается").

Live-verified against this dev machine's own `hranix-crowdsec` container
(2026-07-24) before writing any of the code below:

  - `/etc/crowdsec/scenarios/*.yaml` are six symlinks into
    `/etc/crowdsec/hub/scenarios/crowdsecurity/...` — confirmed NOT
    bind-mounted from the host (see infra/security/crowdsec/
    docker-compose.yml's own `volumes:` — only a named Docker volume for
    `/var/lib/crowdsec/data`), so a `docker exec` into the container is
    genuinely the only way to read or change them; there is no host-side
    shortcut.
  - The plan document's own table lists 6 scenarios (one row per file) —
    but 3 of those 6 FILES actually hold TWO separate YAML documents each
    (a bare `---` line separates them; CrowdSec packs each scenario's own
    `_user-enum` sibling into the SAME file as its "main" scenario, e.g.
    `ssh-bf.yaml` holds both `crowdsecurity/ssh-bf` AND
    `crowdsecurity/ssh-bf_user-enum`). 9 real, independently-configured
    scenarios exist on disk, not 6 — `_parse_scenario_documents` below
    splits every file on that separator and exposes every document found,
    rather than silently capping the UI at the plan table's 6 (the same
    "never round away real data" discipline this whole project already
    applies elsewhere, e.g. A-23's community/local ban split). This also
    means a NAIVE whole-file `sed` (the plan's own "точечная построчная
    замена" reasoning, written assuming one scenario per file) would
    silently corrupt whichever OTHER scenario shares that file —
    `_scenario_sed_program` below scopes every substitution to the exact
    `name:`-through-next-`---`(-or-EOF) range instead, confirmed live
    against a throwaway `/tmp` file inside the real container (never a
    real scenario file) before this code ever touched one.
  - This container's own `/bin/sed` is BusyBox sed (Alpine, confirmed
    live: `sed --version` answers "This is not GNU sed" — NOT the GNU sed
    every other Linux distro ships), and does honour the
    `/pat1/,/pat2/{...}` range-address syntax this module relies on,
    including the "no closing match -> runs to EOF" case for a document
    with no following `---` (the last document in its file) — confirmed
    live both ways before writing `_scenario_sed_program`.
  - Unlike `os_firewall.py`, this section needs NO per-platform branching
    of its own: `docker`/`docker compose` CLI syntax is identical on
    macOS/Linux/Windows — the only platform difference is HOW
    `elevated_run()` itself pops the OS prompt (osascript/pkexec/UAC),
    already handled entirely inside elevated.py.

A-45 addendum (2026-07-25): a real user, immediately after A-43/A-44
shipped, asked how "Обновить сценарии" (still explicitly disabled by the
"A-43 addendum" paragraph above) could be made safe enough to turn on —
"как сделать удобно с проверкой безопасности?", not "почему нет". This
task's own answer REVISES that paragraph rather than silently overriding
it: `cscli hub update`/`upgrade` genuinely still pulls third-party content
from hub.crowdsec.net, that risk class has not gone away — what changed is
that a real, official CrowdSec mechanism was found that lets an operator
see exactly what would be installed BEFORE it is installed, the same
"apt list --upgradable"/"brew outdated" idea already trusted everywhere
else: `cscli hub upgrade --dry-run` ("Don't install or remove anything;
print the execution plan", CrowdSec's own documented flag).

Confirmed live against this project's own `hranix-crowdsec` container
while building this task (2026-07-25), BEFORE any code below was written:

  - The container's REAL state at the time genuinely had pending upgrades
    (not the "everything already current, only the data-files line" case
    the architect had observed a day earlier while scoping this task) —
    `cscli hub update && cscli hub upgrade --dry-run` printed, on stdout:
    ```
    Action plan:
    📥 download
     collections: crowdsecurity/sshd (0.9 -> 0.9), crowdsecurity/whitelist-good-actors (0.4 -> 0.4)
     scenarios: crowdsecurity/ssh-time-based-bf (0.2 -> 0.3)
     postoverflows: crowdsecurity/rdns (0.3 -> 0.4)
    🔄 check & update data files

    Dry run, no action taken.
    ```
    (the "X is outdated because of Y"/"level=info ... not downloading
    local item" diagnostic noise around it is all on STDERR — confirmed
    live by redirecting each stream separately). After a real, non-dry-run
    `cscli hub upgrade` was then run and the container restarted, the SAME
    dry-run command instead printed the honest empty form:
    ```
    Action plan:
    🔄 check & update data files

    Dry run, no action taken.
    ```
    — confirmed live, both directions, on the SAME container. This
    confirms exactly the distinction this task's own plan document asked
    to be verified rather than assumed: `🔄 check & update data files`
    always appears whether or not there is anything real to install;
    `📥 download` appears ONLY together with real `name (OLD -> NEW)`
    version-bump lines. `_scenario_update_plan_has_upgrades` below keys off
    the literal `" -> "` substring specifically — the one part of this
    text confirmed to be the actual payload, not decoration a future
    CrowdSec release could reword (the `📥` glyph itself is a multi-byte
    emoji, more fragile to encoding/terminal-rendering drift than a plain
    ASCII arrow that only ever appears inside a real version-bump line).
  - `cscli hub list -o json` answers clean, complete JSON on stdout alone
    (confirmed live: piping stdout only through a JSON parser succeeds in
    full; the same diagnostic lines above go to stderr, same split) — every
    item, across every hub category (`collections`/`scenarios`/
    `postoverflows`/`parsers`/`contexts`/`appsec-configs`/`appsec-rules`,
    confirmed live to be the full set of top-level keys), carries its own
    `status` field: `"enabled,update-available"` for an outdated item
    (confirmed live against the real outdated items above, before they
    were upgraded) vs plain `"enabled"` otherwise. This is
    `apply_scenario_updates`'s own mandatory readback signal
    (`_read_hub_outdated_items`/`_parse_hub_list_outdated` below) — a
    SEPARATE elevated read after the write+restart, never trusting the
    restart's own clean exit as proof the new versions are genuinely
    active, the exact same discipline `write_scenario_threshold` (A-43)
    already established for its own sed-based write.
  - `cscli hub update`'s own progress indicator prints plain `\r` (carriage
    return, no following `\n`) between some of its lines (confirmed live:
    a real "Nothing to do, the hub index is up to date." line came back
    this way) — genuinely `cscli`'s own output, not an `elevated_run()`/
    AppleScript artifact (confirmed separately: `read_scenario_thresholds`'s
    own real YAML-file output, over the exact same `elevated_run()`
    mechanism, never contains a bare `\r`). This module's own
    `check_scenario_updates` still returns the plan as one raw string
    (per this task's own "show the real tool output" brief) — app.js's
    `renderScenarioUpdatesPlan` is the one that splits it into rows, and
    does so on `\r\n`/`\r`/`\n` alike (confirmed live to matter: a naive
    `split('\n')` alone collapsed this real output into a single unreadable
    row).
  - The real upgrade above (`crowdsecurity/ssh-time-based-bf` 0.2->0.3,
    `crowdsecurity/rdns` 0.3->0.4, two collection version stamps) WAS
    applied for real while building this task (needed to observe the
    "already current" half of the live comparison above), the container
    WAS restarted, and a fresh `cscli hub list -o json` DID confirm zero
    outdated items afterwards (LAPI's own `/health` also answered 200
    after the restart). Left in place afterwards rather than reverted:
    unlike A-43/A-44's own throwaway test values (an arbitrary capacity/IP
    picked purely to exercise the write path, with an obvious "put the
    original number back" undo), a hub upgrade has no such original value
    to restore — it is CrowdSec's own official newer release of the same
    rule, the actual point of this feature existing, not a side effect of
    testing it; `cscli` itself has no "downgrade to an older hub version"
    operation to undo it with even if that were desired. See this task's
    own report for the full transcript.

**Honest, undiminished remaining risk** (this addendum revises the RISK
ACCEPTANCE, not a claim the risk is gone): if hub.crowdsec.net itself were
ever compromised, it could in principle serve a malicious "plan" during
the CHECK step that differs from what it actually serves moments later
during the real APPLY — no local mechanism, this one included, can rule
that out. This is the same residual trust every package manager (apt/
brew/pip) places in its own upstream index/registry. This task's own
two-step design narrows the risk this project can actually see and act on
(the operator sees the real plan before anything is installed) — it does
not, and cannot, eliminate the supply-chain risk hub.crowdsec.net itself
represents. See infra/security/crowdsec/README.md's section 6.2 for the
same disclosure aimed at an operator reading the ops docs, not just a
developer reading this module.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import shlex
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx

from app.config import REPO_ROOT, Settings, get_settings
from app.services.mcp.connector import MCPConnector
from app.services.mcp.registry import MCPRegistry
from app.services.mcp.security_connectors.elevated import ElevatedRunResult, elevated_run

logger = logging.getLogger(__name__)

CROWDSEC_CONNECTOR_NAME = "crowdsec"

_DECISIONS_PATH = "/v1/decisions"
# A-29: machine-level LAPI auth (see this module's "A-29 addendum"
# docstring section) — a different credential class from the bouncer
# `X-Api-Key` used by `get_decisions` above.
_WATCHERS_LOGIN_PATH = "/v1/watchers/login"
_ALERTS_PATH = "/v1/alerts"
# A-42: same machine-level auth as the two paths above, NOT the bouncer
# `X-Api-Key` `_DECISIONS_PATH` uses — confirmed live, see this module's
# "A-42 addendum" docstring section.
_ALLOWLISTS_PATH = "/v1/allowlists"

# A-29: how long before a cached machine JWT's own `expire` we proactively
# re-login rather than risk sending a request with a token that expires
# mid-flight — CrowdSec's observed token lifetime is a full hour (see "A-29
# addendum" below), so a 30s margin costs nothing in practice.
_TOKEN_REFRESH_MARGIN = timedelta(seconds=30)

# A-29: the `origin` this module stamps on a decision it creates itself via
# `POST /v1/alerts` — distinct from CrowdSec's own `"cscli"` (the admin CLI)
# and `"CAPI"` (community blocklist, see `_CAPI_ORIGIN` below), so a decision
# banned through this panel is traceable back to "the panel's own manual-ban
# button" specifically. Still correctly counted as a *local* decision by
# `_is_community_decision` (anything not `"CAPI"`), exactly like a `cscli`-
# created one.
_MANUAL_BAN_ORIGIN = "hranix-shield"

# A-23: the `origin` value CrowdSec's LAPI uses for community-blocklist
# (CAPI) decisions — confirmed empirically, see this module's "A-23
# addendum" docstring section above for the exact live test performed.
_CAPI_ORIGIN = "CAPI"


def _is_community_decision(decision: dict[str, Any]) -> bool:
    """True for a decision synced down from CrowdSec's central community
    blocklist (CAPI) rather than initiated by/for this machine. See the
    module docstring's "A-23 addendum" for how this was confirmed live."""
    return decision.get("origin") == _CAPI_ORIGIN


def is_crowdsec_configured(settings: Settings) -> bool:
    """Both a LAPI URL and a bouncer API key are required — mirrors
    `notifications.smtp_client.is_smtp_configured`'s "no in-repo default for
    a third-party external service" reasoning."""
    return bool(settings.crowdsec_lapi_url and settings.crowdsec_api_key)


def is_crowdsec_write_configured(settings: Settings) -> bool:
    """A-29: whether the SECOND, write-capable credential (machine-level
    LAPI auth) is configured — independent of `is_crowdsec_configured`
    above, which only covers the read-only bouncer key. A deployment can
    have one, both, or neither configured; ban/unban specifically need this
    one, never the bouncer key (see this module's "A-29 addendum"
    docstring section for why the two are not interchangeable)."""
    return bool(
        settings.crowdsec_lapi_url
        and settings.crowdsec_machine_id
        and settings.crowdsec_machine_password
    )


class CrowdSecError(RuntimeError):
    """Raised by `CrowdSecClient` methods on any failure to get a good answer
    out of LAPI. `reason` is one of:

      - `"unreachable"`: connection refused/timed out/DNS failure (the
        container is down or misconfigured), or LAPI answered with some
        other unexpected non-2xx status.
      - `"unauthorized"`: LAPI is reachable and answered, but rejected the
        configured credential (HTTP 401/403) — a wrong bouncer key/machine
        password, a bouncer since revoked via `cscli bouncers delete`, or a
        machine since removed via `cscli machines delete`.
      - `"invalid_ip"` (A-29, `create_ban` only): the caller-supplied IP
        failed this module's OWN validation (Python's `ipaddress`) before
        any request was even sent to LAPI — never raised by a live LAPI
        response, see "A-29 addendum" above for why LAPI itself cannot be
        trusted to reject a bad IP for us.
      - `"rejected"` (A-29, `create_ban` only): LAPI answered HTTP 201 (no
        error) but created zero decisions — confirmed live to happen for a
        request its alert-schema validation accepts but its own IP
        parsing/allowlist logic silently drops.
      - `"not_found"` (A-29, `delete_decision` only): LAPI's own "decision
        with id '<id>' doesn't exist" HTTP 500 response — see "A-29
        addendum" above for why this is deliberately NOT folded into the
        generic `"unreachable"` bucket (an operator double-clicking "unban"
        should see "already gone", not "something broke").

    Kept as a dedicated `reason` field (not just an exception message)
    because the router needs to report a precise `connector.status` to the
    UI, not just "something went wrong" — see `fetch_ids_console_data`.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class CrowdSecClient:
    """Thin async HTTP client over one CrowdSec instance's LAPI. Speaks two
    unrelated credential shapes over the SAME LAPI, because both are just
    "this one external tool" (kept as one class rather than two, mirroring
    e.g. `WazuhClient` bundling both auth and data calls):

      - a static `X-Api-Key` header (`api_key`) — a real bouncer's own
        read-only view, used by `get_decisions` below.
      - machine-level LAPI auth (`machine_id`/`machine_password`, A-29) — a
        short-lived JWT obtained via `POST /v1/watchers/login` and cached
        for its lifetime, used by `create_ban`/`delete_decision` below. See
        this module's "A-29 addendum" docstring section for exactly what
        was confirmed live about this second credential class.

    Neither credential is required at construction time: a caller that only
    ever calls `get_decisions` can omit `machine_id`/`machine_password`
    (and vice versa) — see `create_crowdsec_client`/
    `create_crowdsec_write_client` below, which build exactly the shape
    each use case needs. No CrowdSec code runs in this process either way —
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
        api_key: str = "",
        machine_id: str | None = None,
        machine_password: str | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._api_key = api_key
        self._machine_id = machine_id
        self._machine_password = machine_password
        self._write_token: str | None = None
        self._write_token_expires_at: datetime | None = None
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

    async def _login_machine(self) -> str:
        """`POST /v1/watchers/login` — obtains (and caches) the machine JWT
        that `create_ban`/`delete_decision` need. See this module's "A-29
        addendum" docstring section for the exact response shape this was
        confirmed against live (`{"code", "expire", "token"}` on success).

        Cached for `_write_token_expires_at` minus `_TOKEN_REFRESH_MARGIN`
        (not re-fetched on every write call): a fresh `CrowdSecClient` is
        typically built per outer call (`ban_ip`/`unban_decision` below,
        same "short-lived, no state across calls" shape as
        `create_crowdsec_client`), so in practice this logs in at most once
        per call anyway — the expiry tracking exists for the one caller
        that does make two write calls off one client (this module's own
        live-verification tooling), not because a longer-lived client is
        expected in the running app.
        """
        now = datetime.now(timezone.utc)
        if (
            self._write_token is not None
            and self._write_token_expires_at is not None
            and now < self._write_token_expires_at - _TOKEN_REFRESH_MARGIN
        ):
            return self._write_token

        try:
            response = await self._client.post(
                _WATCHERS_LOGIN_PATH,
                json={"machine_id": self._machine_id, "password": self._machine_password},
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(
                f"CrowdSec LAPI unreachable during machine login: {exc}", reason="unreachable"
            ) from exc

        if response.status_code in (401, 403):
            raise CrowdSecError(
                f"CrowdSec LAPI rejected the configured machine credentials "
                f"(HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code != 200:
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP {response.status_code} during machine login",
                reason="unreachable",
            )

        payload = response.json()
        token = payload.get("token")
        if not token:
            raise CrowdSecError(
                "CrowdSec LAPI machine login response had no token", reason="unreachable"
            )
        self._write_token = token
        self._write_token_expires_at = _parse_expire(payload.get("expire"))
        return token

    async def create_ban(
        self,
        ip: str,
        *,
        duration: str = "4h",
        reason: str = "hranix-shield: manual ban via admin console",
    ) -> list[str]:
        """`POST /v1/alerts` — creates one ban decision for `ip`. See this
        module's "A-29 addendum" docstring section for exactly how the
        request body below was derived (captured verbatim from a real
        `cscli decisions add --trace` run, not guessed from documentation)
        and why the IP is validated here rather than left to LAPI.

        Returns the new alert id(s) LAPI answered with (e.g. `["24"]`) —
        informational only, callers don't need to track it: the ban itself
        is what `GET /v1/decisions` (and this console's `recent_attempts`)
        will reflect on the next fetch.
        """
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise CrowdSecError(f"'{ip}' is not a valid IP address", reason="invalid_ip") from exc

        token = await self._login_machine()
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        body = [
            {
                "capacity": 0,
                "created_at": now_iso,
                "decisions": [
                    {
                        "duration": duration,
                        "origin": _MANUAL_BAN_ORIGIN,
                        "scenario": reason,
                        "scope": "Ip",
                        "type": "ban",
                        "value": ip,
                    }
                ],
                "events": [],
                "events_count": 1,
                "kind": _MANUAL_BAN_ORIGIN,
                "labels": None,
                "leakspeed": "0",
                "message": reason,
                "remediation": True,
                "scenario": reason,
                "scenario_hash": "",
                "scenario_version": "",
                "simulated": False,
                "source": {"ip": ip, "scope": "Ip", "value": ip},
                "start_at": now_iso,
                "stop_at": now_iso,
            }
        ]
        try:
            response = await self._client.post(
                _ALERTS_PATH, json=body, headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(
                f"CrowdSec LAPI unreachable creating a ban: {exc}", reason="unreachable"
            ) from exc

        if response.status_code in (401, 403):
            raise CrowdSecError(
                f"CrowdSec LAPI rejected the ban request (HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code != 201:
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP {response.status_code} creating a ban",
                reason="unreachable",
            )

        alert_ids = response.json() or []
        if not alert_ids:
            raise CrowdSecError(
                f"CrowdSec LAPI accepted the ban request but created no decision for '{ip}'",
                reason="rejected",
            )
        return alert_ids

    async def delete_decision(self, decision_id: int) -> int:
        """`DELETE /v1/decisions/{id}` — removes one active decision (an
        unban). `decision_id` is the SAME id `get_decisions()` already
        exposes on each entry (see this module's "A-29 addendum" docstring
        section for why that is the nested per-decision id, not the
        wrapping alert's id). Returns the number of decisions actually
        removed (CrowdSec answers `{"nbDeleted": "1"}` — a string — on
        success; parsed to `int` here so callers get a real number)."""
        token = await self._login_machine()
        try:
            response = await self._client.delete(
                f"{_DECISIONS_PATH}/{decision_id}", headers={"Authorization": f"Bearer {token}"}
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(
                f"CrowdSec LAPI unreachable deleting decision {decision_id}: {exc}",
                reason="unreachable",
            ) from exc

        if response.status_code in (401, 403):
            raise CrowdSecError(
                f"CrowdSec LAPI rejected the unban request (HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code == 500:
            try:
                message = response.json().get("message", "")
            except ValueError:
                message = ""
            if "doesn't exist" in message:
                raise CrowdSecError(
                    f"CrowdSec LAPI has no decision with id {decision_id}", reason="not_found"
                )
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP 500 deleting decision {decision_id}: {message}",
                reason="unreachable",
            )
        if response.status_code != 200:
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP {response.status_code} deleting decision "
                f"{decision_id}",
                reason="unreachable",
            )

        payload = response.json()
        return int(payload.get("nbDeleted", 0))

    async def get_allowlists(self) -> list[dict[str, Any]]:
        """`GET /v1/allowlists?with_content=true` — every allowlist CrowdSec
        currently knows about, each with its own `items` (the actual
        whitelisted values, one `{value, description, expiration,
        created_at}` per entry, per CrowdSec's published
        `localapi_swagger.yaml`) inlined because `with_content=true` is
        always passed here. See this module's "A-42 addendum" docstring
        section for why this READ needs the same machine-level
        `Authorization: Bearer` token `create_ban`/`delete_decision` above
        use, not the bouncer `X-Api-Key` `get_decisions` uses (confirmed
        live: a bouncer key gets the identical HTTP 401 "cookie token is
        empty" rejection the write endpoints give).

        No write counterpart exists on this class on purpose — every
        `POST`/`PUT`/`PATCH`/`DELETE` on this same path answers a plain
        HTTP 405 regardless of credentials (confirmed live, see "A-42
        addendum"), so there is nothing a write method here could ever do.

        CrowdSec answers a JSON `null` body, not `[]`, when there are no
        allowlists at all — same translation as `get_decisions` above.
        """
        token = await self._login_machine()
        try:
            response = await self._client.get(
                _ALLOWLISTS_PATH,
                params={"with_content": "true"},
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as exc:
            raise CrowdSecError(
                f"CrowdSec LAPI unreachable listing allowlists: {exc}", reason="unreachable"
            ) from exc

        if response.status_code in (401, 403):
            raise CrowdSecError(
                f"CrowdSec LAPI rejected the allowlists request (HTTP {response.status_code})",
                reason="unauthorized",
            )
        if response.status_code != 200:
            raise CrowdSecError(
                f"CrowdSec LAPI returned HTTP {response.status_code} listing allowlists",
                reason="unreachable",
            )

        payload = response.json()
        return payload or []


def _parse_expire(value: str | None) -> datetime | None:
    """Parses `/v1/watchers/login`'s `expire` field (`"2026-07-18T21:24:46Z"`
    — confirmed live, see this module's "A-29 addendum" docstring section).
    Same defensive "never crash the whole console over one bad timestamp"
    spirit, and same `Z`-suffix handling, as
    `wazuh._parse_timestamp`."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def create_crowdsec_client(settings: Settings | None = None) -> CrowdSecClient | None:
    """A read-only `CrowdSecClient` (bouncer key) wired to real Settings, or
    `None` when `CROWDSEC_LAPI_URL`/`CROWDSEC_API_KEY` are not both set —
    mirrors `services.backup.wiring.create_default_scheduler`'s "return
    None when there is nothing to do" shape. Callers are responsible for
    calling `aclose()` on whatever this returns (when not None).

    A-29: deliberately does NOT also attach `crowdsec_machine_id`/
    `crowdsec_machine_password` even when they happen to be set too — this
    factory is `fetch_ids_console_data`'s read path, which has no reason to
    ever touch the write credential. See `create_crowdsec_write_client`
    below for the write-capable counterpart.
    """
    settings = settings or get_settings()
    if not is_crowdsec_configured(settings):
        return None
    assert settings.crowdsec_lapi_url is not None  # narrowed by is_crowdsec_configured
    assert settings.crowdsec_api_key is not None
    return CrowdSecClient(lapi_url=settings.crowdsec_lapi_url, api_key=settings.crowdsec_api_key)


def create_crowdsec_write_client(settings: Settings | None = None) -> CrowdSecClient | None:
    """A-29: the write-capable counterpart to `create_crowdsec_client`
    above — a `CrowdSecClient` wired with machine-level credentials
    (`crowdsec_machine_id`/`crowdsec_machine_password`), or `None` when
    those (plus `crowdsec_lapi_url`) are not all set. Never reads
    `crowdsec_api_key`: the bouncer key plays no part in `create_ban`/
    `delete_decision`, see this module's "A-29 addendum" docstring
    section. Callers are responsible for calling `aclose()` on whatever
    this returns (when not None)."""
    settings = settings or get_settings()
    if not is_crowdsec_write_configured(settings):
        return None
    assert settings.crowdsec_lapi_url is not None  # narrowed by is_crowdsec_write_configured
    assert settings.crowdsec_machine_id is not None
    assert settings.crowdsec_machine_password is not None
    return CrowdSecClient(
        lapi_url=settings.crowdsec_lapi_url,
        machine_id=settings.crowdsec_machine_id,
        machine_password=settings.crowdsec_machine_password,
    )


class CrowdSecNotConfiguredError(RuntimeError):
    """Raised by `ban_ip`/`unban_decision` below when
    `Settings.crowdsec_machine_id`/`crowdsec_machine_password` are not both
    set — mirrors `ClamAvNotConfiguredError`'s shape (services/mcp/
    security_connectors/clamav.py). Deliberately a DIFFERENT exception from
    however a caller checks read-side configuration
    (`is_crowdsec_configured`): a deployment can have a working bouncer key
    (reads fine) with no machine credential at all (writes not configured),
    which is in fact the Phase-0-default-until-now state this whole task
    exists to change."""


async def ban_ip(
    ip: str,
    *,
    duration: str = "4h",
    reason: str = "hranix-shield: manual ban via admin console",
    settings: Settings | None = None,
) -> list[str]:
    """A-29: real ban — used by `POST /security/consoles/ids/crowdsec/ban`
    (routers/security_console.py). Builds a short-lived write-capable
    client, uses it once, closes it — same shape as
    `fetch_ids_console_data`'s read-side client lifecycle. Raises
    `CrowdSecNotConfiguredError` when the machine credential is not set,
    `CrowdSecError` (see its own docstring for `.reason`) on any live
    failure — the router translates both into the console's honest error
    vocabulary, never a silent no-op."""
    settings = settings or get_settings()
    client = create_crowdsec_write_client(settings)
    if client is None:
        raise CrowdSecNotConfiguredError()
    try:
        return await client.create_ban(ip, duration=duration, reason=reason)
    finally:
        await client.aclose()


async def unban_decision(decision_id: int, *, settings: Settings | None = None) -> int:
    """A-29: real unban — used by `DELETE
    /security/consoles/ids/crowdsec/decisions/{decision_id}`
    (routers/security_console.py). Same client lifecycle/error-propagation
    shape as `ban_ip` above."""
    settings = settings or get_settings()
    client = create_crowdsec_write_client(settings)
    if client is None:
        raise CrowdSecNotConfiguredError()
    try:
        return await client.delete_decision(decision_id)
    finally:
        await client.aclose()


# A-42: confirmed live (see this module's own research while building this
# task) — an allowlist entry added WITHOUT `cscli allowlists add -e ...`
# (i.e. "never expires", the common case for a genuinely permanent trust
# entry) comes back from LAPI with a literal `"0001-01-01T00:00:00.000Z"`
# `expiration` — Go's zero `time.Time` value serialised, not `null`/absent.
# Passing that through as-is would have `app.js`'s `formatTimestamp` render
# it as a real-looking (but meaningless) date ("01.01, 02:30") instead of
# "бессрочно"/"no expiry" — a fabricated-looking value out of a technically-
# real-but-empty field, the same class of honesty bug this project's own
# `country_centroid()` (A-41) deliberately avoids by never defaulting to
# `(0.0, 0.0)`. Normalised to a real `None` here, at the source, so every
# downstream consumer (today: app.js's renderIdsAllowlist) can keep its
# simple `expiration ? ... : "no expiry"` check honest without needing its
# own copy of this Go-specific knowledge.
_GO_ZERO_TIME_PREFIX = "0001-01-01T00:00:00"


def _flatten_allowlist_items(allowlists: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """A-42: `GET /v1/allowlists?with_content=true` groups entries by named
    allowlist (`cscli allowlists create <name>` — a deployment can have
    several); Phase 0's UI shows one flat «Белый список» section, not
    per-named-allowlist grouping (see app.js's renderIdsAllowlist), so this
    flattens every allowlist's `items` into a single list. Each row keeps
    `allowlist_name` (which named list it came from) so that context is not
    lost even though it is not used as a grouping key today — cheap to keep,
    would need re-fetching to add back later. `comment` is this project's own
    name for the item's `description` field (CrowdSec's own naming) —
    `description` is reserved at the allowlist level too in the same raw
    payload, so renaming here avoids the two colliding once flattened."""
    items: list[dict[str, Any]] = []
    for allowlist in allowlists:
        name = allowlist.get("name")
        for item in allowlist.get("items") or []:
            expiration = item.get("expiration")
            if expiration and expiration.startswith(_GO_ZERO_TIME_PREFIX):
                expiration = None
            items.append(
                {
                    "allowlist_name": name,
                    "value": item.get("value"),
                    "comment": item.get("description"),
                    "expiration": expiration,
                    "created_at": item.get("created_at"),
                }
            )
    return items


async def fetch_allowlists(settings: Settings | None = None) -> dict[str, Any]:
    """A-42: real data for the `ids` console's «Белый список» section (see
    routers/security_console.py._ids_payload) — replaces A-11's hardcoded
    `settings.whitelist_count: 0`, which never reflected anything real.
    Never raises: mirrors `fetch_ids_console_data`'s three-state honesty
    (`not_configured` / CrowdSecError's own `.reason` / `ok`) so an
    unreachable/misconfigured CrowdSec renders as an explained empty state,
    never a 500 and never a silently-empty list indistinguishable from "no
    allowlist entries exist".

    Deliberately built on `create_crowdsec_write_client` — the SAME
    machine-level credential `ban_ip`/`unban_decision` already use (A-29),
    not a third credential class — because `CrowdSecClient.get_allowlists`
    genuinely needs it (confirmed live, see that method's own docstring and
    this module's "A-42 addendum" section): the bouncer key `ids`'s own
    `connector.status` is backed by cannot read this endpoint at all. This
    means `connector.status` returned here can legitimately differ from
    `fetch_ids_console_data`'s own `connector.status` on the very same
    deployment — a bouncer-only setup (the A-11/A-29 default until a machine
    login is also provisioned) reads decisions fine while this reports
    `not_configured`, which is the accurate state, not a bug: see
    infra/security/crowdsec/README.md's "Два разных, независимых учётных
    данных" table for why CrowdSec itself draws this line.

    An allowlist with no items, or LAPI answering no allowlists at all, both
    come back as `allowlists: []` here — the same honest "really is empty"
    signal `fetch_ids_console_data`'s `recent_attempts: []` already uses,
    left for `app.js`'s renderIdsAllowlist to phrase as "Белый список пуст"
    only when `connector.status == "ok"` (never when it could not actually
    be checked).
    """
    settings = settings or get_settings()
    client = create_crowdsec_write_client(settings)
    if client is None:
        return {"connector": {"status": "not_configured"}, "allowlists": []}

    try:
        raw_allowlists = await client.get_allowlists()
    except CrowdSecError as exc:
        logger.warning("crowdsec (allowlists): %s", exc)
        return {"connector": {"status": exc.reason}, "allowlists": []}
    finally:
        await client.aclose()

    return {"connector": {"status": "ok"}, "allowlists": _flatten_allowlist_items(raw_allowlists)}


def _placeholder_ids_data(connector_status: str) -> dict[str, Any]:
    """The honest "no real data available" shape — used both when CrowdSec
    was never configured and when it is configured but unreachable/
    unauthorized right now. Every metric is `None` (not a fabricated `0`):
    the A-11 task brief is explicit that an unreachable connector must never
    render as "0 incidents", which would read as a false all-clear.

    A-26: no `chart` key here anymore — this connector has no DB session to
    query real history from (by design, see this module's docstring: it is
    a pure external-tool HTTP client), and the field used to be a hardcoded
    `[]` that nothing downstream could ever have turned into a real trend.
    `routers/security_console.py`'s `_ids_payload`/`_perimeter_payload` now
    build their own `chart` from `services/metrics/chart.chart_values_7d()`
    (real last-7-days history, sampled by `services/metrics/sampler.py`),
    independent of this dict entirely.
    """
    return {
        "connector": {"status": connector_status},
        "metrics": {
            # A-23: `active_bans` stays as the sum of the two fields below —
            # kept (not removed) purely for backward compatibility, because
            # `_perimeter_payload` (routers/security_console.py) still reads
            # this single field as `crowdsec_active_bans` (grep-confirmed;
            # that console is out of A-23's scope and, separately,
            # grep-confirmed that `app.js` never renders that particular
            # field today, so no "unexplained number" regression there).
            "active_bans": None,
            "active_bans_local": None,
            "active_bans_community": None,
            "banned_24h": None,
            "scenarios": None,
            "last_event_at": None,
        },
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
      `active_bans_local`/`active_bans_community`/`scenarios`/
      `recent_attempts` are real, computed from the live decisions list.
      `active_bans` is kept too, as the sum of the two — see
      `_placeholder_ids_data`'s comment for exactly why it was not removed.
      `banned_24h`/`last_event_at` stay `None` even on success — genuinely
      not derivable from a bouncer's view of LAPI, see this module's
      docstring; this is not a missing feature, it is the actual shape of
      the data bouncers can see.

    A-23: `GET /v1/decisions` returns local and CAPI/community-blocklist
    decisions mixed together with no server-side way to ask for one or the
    other (see this module's "A-23 addendum" docstring section) — so this
    function fetches the list exactly once, same as before, and splits it
    client-side by each decision's own `origin` field
    (`_is_community_decision`). `recent_attempts` is restricted to LOCAL
    decisions only: a list of thousands of community-blocklist IPs is
    neither useful nor readable as "recent attempts against this machine",
    and would reintroduce the exact same "real but misleading" problem this
    task exists to fix.

    A-29: each `recent_attempts` entry now also carries the decision's own
    `id` — the same value `CrowdSecClient.delete_decision` expects (see
    this module's "A-29 addendum" docstring section) — so the console's
    "Разбанить IP" button on a given row has something real to call. `None`
    would only happen if CrowdSec itself ever omitted `id` from a decision,
    never observed live; kept as `.get("id")` (not `["id"]`) purely as the
    same defensive style already used for `value`/`scenario`/`type` above,
    not because this is expected to actually happen.
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

    local_decisions = [d for d in decisions_by_recency if not _is_community_decision(d)]
    community_count = sum(1 for d in decisions if _is_community_decision(d))

    return {
        "connector": {"status": "ok"},
        "metrics": {
            "active_bans": len(decisions),
            "active_bans_local": len(local_decisions),
            "active_bans_community": community_count,
            "banned_24h": None,
            "scenarios": len(distinct_scenarios),
            "last_event_at": None,
        },
        "recent_attempts": [
            {
                "id": decision.get("id"),
                "ip": decision.get("value"),
                "vector": decision.get("scenario"),
                "status": decision.get("type"),
            }
            for decision in local_decisions
        ],
    }


async def fetch_active_decision_values(settings: Settings | None = None) -> dict[str, Any]:
    """A-40: real data for the `network` console's reputation cross-
    reference (`security_console.py._network_payload`, via
    `ip_matches_any_decision` below) — reuses the exact same read path
    `fetch_ids_console_data` above already established (`create_crowdsec_client`
    + `get_decisions()`), never a second/new integration with CrowdSec, per
    the A-40 task brief's explicit instruction.

    Deliberately returns the RAW `value` strings off every currently active
    decision (both local and CAPI/community-blocklist — see this module's
    "A-23 addendum" for why `fetch_ids_console_data` splits those but this
    function does not: a community-blocklisted IP connecting to THIS
    machine is still a real reason to flag a row "подозрительный", the
    local/community split only matters for `ids`'s own "attempts against
    this machine" framing, not for "is this remote host bad") rather than
    a `set[str]` of bare IPs: `scope="Range"` decisions carry a CIDR block
    in `value` (e.g. `"203.0.113.0/24"`), not a single address — flattening
    that into a set of individual IP strings would either miss every
    address in the range or require enumerating a whole (possibly huge)
    CIDR block up front. `ip_matches_any_decision` below does the
    IP-vs-(IP-or-CIDR) comparison per lookup instead.

    Never raises: mirrors `fetch_ids_console_data`'s three-state honesty
    (`not_configured` / CrowdSecError's own `.reason` / `ok`) so
    `_network_payload` can tell "checked, no match" apart from "never
    checked at all" — see that function's own docstring for why
    `metrics.suspicious_connections` must stay `None`, not a fabricated
    `0`, in the non-`ok` cases.
    """
    settings = settings or get_settings()
    client = create_crowdsec_client(settings)
    if client is None:
        return {"connector": {"status": "not_configured"}, "values": []}

    try:
        decisions = await client.get_decisions()
    except CrowdSecError as exc:
        logger.warning("crowdsec (network reputation): %s", exc)
        return {"connector": {"status": exc.reason}, "values": []}
    finally:
        await client.aclose()

    return {
        "connector": {"status": "ok"},
        "values": [decision["value"] for decision in decisions if decision.get("value")],
    }


def ip_matches_any_decision(ip: str | None, decision_values: list[str]) -> bool:
    """A-40: True iff `ip` is covered by at least one of `decision_values`
    (the raw `value` field off each active CrowdSec decision, see
    `fetch_active_decision_values` above) — either an exact match
    (`scope="Ip"`, a bare address) or containment inside a CIDR block
    (`scope="Range"`, e.g. `"203.0.113.0/24"` — distinguished here purely
    by the presence of a `"/"`, the same signal `ipaddress.ip_network`
    itself parses on).

    Never raises: `ip` or any one `value` failing to parse (should not
    happen with real CrowdSec/osquery data, but this function never trusts
    an external service's strings to always be well-formed) is treated as
    "this one comparison doesn't match", not a crash that would take the
    whole `network` console down over one bad row — same defensive spirit
    as every other connector in this stack.
    """
    if not ip:
        return False
    try:
        candidate = ipaddress.ip_address(ip)
    except ValueError:
        return False

    for value in decision_values:
        if not value:
            continue
        try:
            if "/" in value:
                if candidate in ipaddress.ip_network(value, strict=False):
                    return True
            elif candidate == ipaddress.ip_address(value):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# A-43: scenario capacity/leakspeed ("порог") — elevated docker-exec read +
# write. See this module's own "A-43 addendum" docstring section above for
# the full architectural rationale and the live-verification findings this
# section's design is built on (multi-document files, BusyBox sed, no
# per-platform branching needed).
# ---------------------------------------------------------------------------

CROWDSEC_CONTAINER_NAME = "hranix-crowdsec"
_SCENARIOS_DIR = "/etc/crowdsec/scenarios"

_SCENARIO_FILE_MARKER_RE = re.compile(r"^===HRANIX-SCENARIO-FILE:(.+)===$")
_SCENARIO_FIELD_RE = re.compile(r"^(name|type|capacity|leakspeed):\s*(.*)$")
_SCENARIO_DOC_SEPARATOR_RE = re.compile(r"(?m)^---\s*$")
_SCENARIO_LEAKSPEED_RE = re.compile(r"^\d+[smh]$")

_SCENARIO_READ_REASON_RU = "Hranix Shield: прочитать пороги сценариев CrowdSec"
_SCENARIO_READ_REASON_EN = "Hranix Shield: read CrowdSec scenario thresholds"
_SCENARIO_WRITE_REASON_RU = "Hranix Shield: изменить порог сценария {name}"
_SCENARIO_WRITE_REASON_EN = "Hranix Shield: change threshold for scenario {name}"

# infra/security/crowdsec/docker-compose.yml's own real path, resolved
# against REPO_ROOT (app/config.py's own convention, e.g. Settings.
# database_url/log_file) rather than the process's current working
# directory — `elevated_run`'s underlying `do shell script .../pkexec/UAC`
# mechanisms do not run with this app's own CWD, see elevated.py.
_CROWDSEC_COMPOSE_FILE = REPO_ROOT / "infra" / "security" / "crowdsec" / "docker-compose.yml"

_WRITE_MARKER_OK = "HRANIX_SCENARIO_WRITE_OK"
_WRITE_MARKER_NOT_FOUND = "HRANIX_SCENARIO_NOT_FOUND"
_WRITE_MARKER_NO_THRESHOLD = "HRANIX_SCENARIO_NO_THRESHOLD"


class CrowdSecScenarioError(RuntimeError):
    """Raised by `read_scenario_thresholds`/`write_scenario_threshold`
    below. `reason` is one of:

      - `"elevation_cancelled"` / `"elevation_failed"`: the SAME two
        `elevated_run()` outcomes `os_firewall.OSFirewallError` already
        uses (see elevated.py's own docstring for their exact meaning) —
        kept on a DEDICATED exception class here (not a reuse of
        `OSFirewallError` itself) because every other reason below is
        CrowdSec-scenario-specific, not firewall-specific;
        `security_console.py`'s own error-status mapping still assigns
        these two the identical HTTP codes (409/502)
        `_raise_for_os_firewall_error` already does, per this task's own
        brief ("коды ошибок зеркалят уже существующие").
      - `"invalid_capacity"` / `"invalid_leakspeed"`: the caller-supplied
        value failed THIS module's OWN validation (`_validate_capacity`/
        `_validate_leakspeed`) before any elevated command was ever
        attempted — never raised from a live result, same "don't send a
        request already known to be bad" discipline `create_ban`'s own IP
        validation above already uses.
      - `"scenario_not_found"`: no scenario file under `_SCENARIOS_DIR`
        contains a `name:` line matching the requested scenario (a typo,
        or a scenario since removed/renamed by a hub update) — never
        silently treated as success.
      - `"scenario_has_no_threshold"`: the requested scenario's own
        `type:` is `trigger` — CrowdSec's trigger scenarios have no
        `capacity`/`leakspeed` fields at all (see this module's "A-43
        addendum" docstring section) — there is nothing to write.
      - `"readback_mismatch"`: the write script itself reported success
        and the container restarted without error, but a FRESH, separate
        elevated read afterwards shows a DIFFERENT value than what was
        written — never conflated with a clean success, the same "a
        restart exiting zero is not proof the change applied" discipline
        `os_firewall.py`'s own A-36/A-37 actions already follow.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _raise_for_scenario_elevated_result(result: ElevatedRunResult) -> None:
    """Shared translation from `elevated_run()`'s own three-way `status`
    into `CrowdSecScenarioError` — mirrors os_firewall.py's
    `_raise_for_elevated_result`, kept as this module's own copy rather
    than importing that one (its exception type is `OSFirewallError`, not
    this module's `CrowdSecScenarioError` — see this class's own
    docstring for why the two stay separate)."""
    if result.status == "cancelled":
        raise CrowdSecScenarioError("the user declined the elevation prompt", reason="elevation_cancelled")
    raise CrowdSecScenarioError(
        f"elevated command failed: {result.stderr.strip() or result.stdout.strip()}",
        reason="elevation_failed",
    )


def _resolve_docker_binary() -> str:
    """Resolves `docker`'s absolute path from THIS (unprivileged) process's
    own PATH before ever building an elevated command — `osascript ... with
    administrator privileges`'s own default PATH (confirmed live while
    building A-36, see elevated.py's docstring) does not include
    `/usr/local/bin`, where Docker Desktop's own CLI actually lives on this
    dev machine (`/usr/local/bin/docker`, confirmed live) — the same
    "absolute paths, never rely on the elevated environment's own PATH"
    discipline os_firewall.py's `_SOCKETFILTERFW`/`/sbin/pfctl` constants
    already follow. Falls back to the bare `"docker"` name only if this
    process's own (unprivileged) PATH genuinely has no `docker` on it
    either — an honest last resort, not expected to actually happen in a
    deployment where the CrowdSec container (this whole module's own
    subject) is already running."""
    return shutil.which("docker") or "docker"


def _parse_scenario_document(text: str) -> dict[str, Any] | None:
    """Extracts `name`/`type`/`capacity`/`leakspeed` from ONE YAML document
    (already split out of its file by `_parse_scenario_documents` below)
    via simple start-of-line field matching — no PyYAML dependency (this
    project's "минимум зависимостей" convention, CLAUDE.md's licence/
    dependency gate) and no need for one: every field this module cares
    about is a plain, unindented `key: value` line in every real scenario
    YAML confirmed live (see this module's "A-43 addendum" docstring
    section) — CrowdSec's own multi-line `condition: |` blocks (e.g.
    `ssh-time-based-bf`'s) are always indented, so they never match this
    function's start-of-line-anchored field regex.

    Returns `None` for a document with no `name:` line at all — should not
    happen for any real scenario document, but an empty trailing chunk
    after a file's last `---` separator must never become a fake
    all-`None` scenario row."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        match = _SCENARIO_FIELD_RE.match(line)
        if match and match.group(1) not in fields:
            fields[match.group(1)] = match.group(2).strip()

    name = fields.get("name")
    if not name:
        return None

    scenario_type = fields.get("type")
    is_trigger = scenario_type == "trigger"
    capacity: int | None = None
    leakspeed: str | None = None
    if not is_trigger:
        raw_capacity = fields.get("capacity")
        if raw_capacity is not None:
            try:
                capacity = int(raw_capacity)
            except ValueError:
                capacity = None
        raw_leakspeed = fields.get("leakspeed")
        if raw_leakspeed is not None:
            leakspeed = raw_leakspeed.strip('"').strip("'")

    return {"name": name, "type": scenario_type, "capacity": capacity, "leakspeed": leakspeed}


def _parse_scenario_documents(file_path: str, file_content: str) -> list[dict[str, Any]]:
    """Splits ONE file's raw content on a bare `---` document-separator
    line (confirmed live: exactly 3 of the 6 real scenario files hold TWO
    documents each this way, see this module's "A-43 addendum" docstring
    section) and parses each into its own scenario row, tagging each with
    the `file_path` it came from — `write_scenario_threshold` below needs
    that to know WHICH file's `*.yaml` glob entry genuinely holds a given
    scenario name (never assumed from the scenario's own name, e.g. never
    a strip-the-`_user-enum`-suffix guess)."""
    documents = _SCENARIO_DOC_SEPARATOR_RE.split(file_content)
    parsed: list[dict[str, Any]] = []
    for document in documents:
        entry = _parse_scenario_document(document)
        if entry is not None:
            entry["file"] = file_path
            parsed.append(entry)
    return parsed


def _parse_scenario_files_output(raw_output: str) -> list[dict[str, Any]]:
    """Parses the FULL stdout of `_build_read_all_scenarios_script` below
    (every scenario file's content, each preceded by its own
    `===HRANIX-SCENARIO-FILE:<path>===` marker line that same script
    prints) into a flat list of scenario rows — whatever order the shell's
    own glob/cat loop produced, no extra sort applied (mirrors
    `fetch_allowlists`'s own "whatever order the source already returns"
    choice)."""
    scenarios: list[dict[str, Any]] = []
    current_file: str | None = None
    current_lines: list[str] = []
    for line in raw_output.splitlines():
        marker = _SCENARIO_FILE_MARKER_RE.match(line)
        if marker:
            if current_file is not None:
                scenarios.extend(_parse_scenario_documents(current_file, "\n".join(current_lines)))
            current_file = marker.group(1)
            current_lines = []
            continue
        if current_file is not None:
            current_lines.append(line)
    if current_file is not None:
        scenarios.extend(_parse_scenario_documents(current_file, "\n".join(current_lines)))
    return scenarios


def _build_read_all_scenarios_script() -> str:
    """The INNER `sh -c` payload run inside the container — ONE `docker
    exec` (never one elevated call per file, this task's own brief) that
    concatenates every `*.yaml` scenario file's content, each preceded by
    a marker line `_parse_scenario_files_output` above splits back apart
    on."""
    return f'for f in {_SCENARIOS_DIR}/*.yaml; do echo "===HRANIX-SCENARIO-FILE:$f==="; cat "$f"; done'


async def read_scenario_thresholds() -> dict[str, Any]:
    """A-43: ONE elevated `docker exec hranix-crowdsec sh -c '...'` call
    reading every installed SSH scenario's `/etc/crowdsec/scenarios/*.yaml`
    content at once, parsed into `{name, type, capacity, leakspeed, file}`
    rows (`capacity`/`leakspeed` honestly `None` for a `type: trigger`
    scenario — it has no such fields at all, see this module's "A-43
    addendum" docstring section, never a fabricated `0`).

    Raises `CrowdSecScenarioError` (`elevation_cancelled`/
    `elevation_failed`) on anything other than a clean `ok` — same
    raise-on-non-ok contract `os_firewall.read_firewall_rules` already
    established for the equivalent one-shot elevated read."""
    docker_binary = _resolve_docker_binary()
    result = await elevated_run(
        [docker_binary, "exec", CROWDSEC_CONTAINER_NAME, "sh", "-c", _build_read_all_scenarios_script()],
        reason_ru=_SCENARIO_READ_REASON_RU,
        reason_en=_SCENARIO_READ_REASON_EN,
    )
    if result.status != "ok":
        _raise_for_scenario_elevated_result(result)
    return {"status": "ok", "scenarios": _parse_scenario_files_output(result.stdout)}


def _validate_capacity(capacity: int) -> None:
    """Plan document's own grammar: a positive integer, or the literal
    `-1` (CrowdSec's own "unlimited" sentinel — confirmed live,
    `crowdsecurity/ssh-time-based-bf`'s real `capacity: -1`, see this
    module's "A-43 addendum" docstring section)."""
    if capacity != -1 and capacity < 1:
        raise CrowdSecScenarioError(
            f"invalid capacity: {capacity} (must be a positive integer or -1)", reason="invalid_capacity"
        )


def _validate_leakspeed(leakspeed: str) -> None:
    """Plan document's own grammar: `\\d+(s|m|h)` — a bare count plus a
    single Go-duration unit letter, matching every real `leakspeed` value
    confirmed live (`"10s"`, `"180s"`, `"60s"`, `2h`)."""
    if not _SCENARIO_LEAKSPEED_RE.match(leakspeed):
        raise CrowdSecScenarioError(
            f"invalid leakspeed: {leakspeed!r} (expected e.g. '10s'/'2h')", reason="invalid_leakspeed"
        )


def _scenario_sed_program(scenario_name: str, *, capacity: int, leakspeed: str) -> str:
    """A single sed `-i` PROGRAM (not yet the full shell command) scoped to
    the EXACT YAML document range `/^name: <scenario_name>$/,/^---$/` — see
    this module's "A-43 addendum" docstring section for why a whole-file
    substitution would be unsafe for the 3 real files holding two
    scenarios each, and that same section for the live confirmation
    (against a throwaway container `/tmp` file, never a real scenario
    file) that this container's own BusyBox `sed` honours this range
    syntax, including when the range's closing `---` is absent (the LAST
    document in a file — sed's own documented behaviour: an unmatched
    closing address runs the substitution to EOF, exactly what is wanted
    there).

    `scenario_name` always contains a literal `/` (every real scenario is
    `crowdsecurity/<name>`) — escaped for sed's own default `/`-delimited
    addressing, the same escaping already proven live in this module's own
    verification (not worked around by picking a different delimiter)."""
    escaped_name = scenario_name.replace("/", "\\/")
    return (
        f"/^name: {escaped_name}$/,/^---$/{{"
        f"s/^capacity: .*/capacity: {capacity}/; "
        f's/^leakspeed: .*/leakspeed: "{leakspeed}"/'
        f"}}"
    )


def _build_write_scenario_script(
    scenario_name: str, *, capacity: int, leakspeed: str, docker_binary: str
) -> str:
    """The full HOST-side bash script `write_scenario_threshold` runs via
    ONE `elevated_run(["/bin/bash", <this script's path>], ...)` call —
    the same "one script file, one elevation prompt for a whole multi-step
    sequence" shape `os_firewall._run_elevated_firewall_script` already
    established, not a new pattern.

    Three real, independent steps, in order:
      1. An INNER `docker exec ... sh -c '...'` (single-quoted via
         `shlex.quote`, run INSIDE the container — this module's target
         files are NOT bind-mounted onto the host, see this module's "A-43
         addendum" docstring section) loops every scenario file, applying
         `_scenario_sed_program`'s range-scoped substitution to WHICHEVER
         file actually contains the target `name:` line (sed's own address
         range is simply a no-op on every other file — no separate `grep`
         pre-filter needed to pick the right file). Before ever touching a
         file, that same inner script also checks the target document's
         own `type:` line — a `trigger` match short-circuits to the
         `HRANIX_SCENARIO_NO_THRESHOLD` marker (no sed, no restart below);
         no `name:` match found AT ALL short-circuits to
         `HRANIX_SCENARIO_NOT_FOUND`. Exactly one of the three markers is
         always printed, on stdout's own last line — the ONLY thing
         `write_scenario_threshold` below parses back out of this step.
      2. Only on a genuine write (`HRANIX_SCENARIO_WRITE_OK`): `docker
         compose -f <this repo's own infra/security/crowdsec/
         docker-compose.yml, absolute path> restart crowdsec` — CrowdSec
         only re-reads scenario YAML at startup, per this whole feature's
         own reason for existing (see the plan document).
      3. Nothing else — the caller does its own SEPARATE elevated readback
         afterwards (`read_scenario_thresholds()`, a second elevation
         prompt), never trusting this restart's own clean exit as proof
         the new value is really in effect (this task's own brief).

    No single-quote characters ever appear inside the inner `sh -c`
    payload (scenario names are always `crowdsecurity/<name>`, `capacity`
    is always a Python `int`, `leakspeed` is always pre-validated
    `\\d+[smh]` — see `_validate_capacity`/`_validate_leakspeed`, both
    called BEFORE this function ever runs, in `write_scenario_threshold`)
    — `shlex.quote` is still used throughout rather than hand-rolled
    quoting, the same "don't hand-roll what shlex already does correctly"
    discipline `elevated.py`'s own `_elevated_run_macos` follows.

    HONEST DISCLOSURE, confirmed live against the real container while
    building this task (see this task's own report for the full transcript
    — a real `capacity` 5->7 change, confirmed applied, reverted back to
    5 afterwards): `_scenario_sed_program`'s own `leakspeed: "{leakspeed}"`
    literally contains a `"` pair, but by the time it is embedded here
    inside `sed -i "{sed_program}"` (itself inside THIS function's
    single-quoted inner `sh -c '...'` payload), the inner `sh`'s own
    standard word-splitting rule — an unquoted segment glued directly onto
    an adjacent double-quoted segment concatenates into ONE argument, no
    space needed — means the `"` characters around the leakspeed VALUE
    (not the sed program's own outer quoting, which stays intact) are
    consumed as quote syntax rather than written to disk: the real,
    on-disk result is the unquoted `leakspeed: 15s`, not `leakspeed:
    "15s"`. This is harmless and was confirmed correct live, not a bug:
    CrowdSec's own real scenario files already mix both styles (e.g.
    `ssh-bf.yaml`'s `leakspeed: "10s"` vs `ssh-bf_user-enum`'s own
    unquoted `leakspeed: 10s`, in the SAME file), and
    `_parse_scenario_document` above strips either style identically via
    `.strip('"').strip("'")` — so a value written by this function reads
    back correctly regardless of which quoting style ends up on disk."""
    escaped_name = scenario_name.replace("/", "\\/")
    sed_program = _scenario_sed_program(scenario_name, capacity=capacity, leakspeed=leakspeed)
    inner_script = (
        "FOUND=0; NO_THRESHOLD=0; "
        f"for f in {_SCENARIOS_DIR}/*.yaml; do "
        f'if grep -q "^name: {escaped_name}$" "$f"; then FOUND=1; '
        f'if sed -n "/^name: {escaped_name}$/,/^---$/p" "$f" | grep -q "^type: trigger$"; then '
        "NO_THRESHOLD=1; else "
        f'sed -i "{sed_program}" "$f"; fi; fi; done; '
        f'if [ "$FOUND" = "0" ]; then echo {_WRITE_MARKER_NOT_FOUND}; '
        f'elif [ "$NO_THRESHOLD" = "1" ]; then echo {_WRITE_MARKER_NO_THRESHOLD}; '
        f"else echo {_WRITE_MARKER_OK}; fi"
    )
    docker_quoted = shlex.quote(docker_binary)
    compose_quoted = shlex.quote(str(_CROWDSEC_COMPOSE_FILE))
    lines = [
        "#!/bin/bash",
        "set -e",
        f"OUTPUT=$({docker_quoted} exec {CROWDSEC_CONTAINER_NAME} sh -c {shlex.quote(inner_script)})",
        'echo "$OUTPUT"',
        f'if [ "$OUTPUT" = "{_WRITE_MARKER_OK}" ]; then',
        f"  {docker_quoted} compose -f {compose_quoted} restart crowdsec",
        "fi",
        "",
    ]
    return "\n".join(lines)


async def write_scenario_threshold(scenario_name: str, *, capacity: int, leakspeed: str) -> dict[str, Any]:
    """A-43: the elevated WRITE half of this section — see
    `_build_write_scenario_script`'s own docstring for the exact 3-step
    script this runs via ONE elevation prompt, and this function's own
    mandatory SEPARATE readback below (a second, independent elevation
    prompt — never trusting the write script's own clean exit as proof
    the new value is genuinely in effect, this task's own brief).

    `capacity`/`leakspeed` are validated HERE, before any elevated command
    is ever attempted (`CrowdSecScenarioError` with `invalid_capacity`/
    `invalid_leakspeed` — never sent to `elevated_run` at all, matching
    this task's own brief: "не отправлять заведомо ломающее YAML
    значение")."""
    _validate_capacity(capacity)
    _validate_leakspeed(leakspeed)

    docker_binary = _resolve_docker_binary()
    script = _build_write_scenario_script(
        scenario_name, capacity=capacity, leakspeed=leakspeed, docker_binary=docker_binary
    )
    reason_ru = _SCENARIO_WRITE_REASON_RU.format(name=scenario_name)
    reason_en = _SCENARIO_WRITE_REASON_EN.format(name=scenario_name)

    with tempfile.TemporaryDirectory(prefix="hranix-crowdsec-scenario-") as tmp:
        script_path = Path(tmp) / "hranix-scenario-write.sh"
        script_path.write_text(script, encoding="utf-8")
        result = await elevated_run(["/bin/bash", str(script_path)], reason_ru=reason_ru, reason_en=reason_en)

    if result.status != "ok":
        _raise_for_scenario_elevated_result(result)

    stripped_stdout = result.stdout.strip()
    marker = stripped_stdout.splitlines()[-1] if stripped_stdout else ""
    if marker == _WRITE_MARKER_NOT_FOUND:
        raise CrowdSecScenarioError(f"no scenario file contains '{scenario_name}'", reason="scenario_not_found")
    if marker == _WRITE_MARKER_NO_THRESHOLD:
        raise CrowdSecScenarioError(
            f"'{scenario_name}' is a trigger scenario — it has no capacity/leakspeed to set",
            reason="scenario_has_no_threshold",
        )
    if marker != _WRITE_MARKER_OK:
        raise CrowdSecScenarioError(
            f"unexpected output from the scenario-write script: {result.stdout!r}", reason="elevation_failed"
        )

    # A-43: mandatory readback — a SEPARATE elevated call (its own OS
    # prompt), never trusting the restart's own clean exit above as proof
    # the new value is genuinely in effect now (this task's own brief,
    # same discipline as os_firewall.py's A-36/A-37 actions).
    readback = await read_scenario_thresholds()
    updated = next((s for s in readback["scenarios"] if s["name"] == scenario_name), None)
    if updated is None or updated["capacity"] != capacity or updated["leakspeed"] != leakspeed:
        raise CrowdSecScenarioError(
            f"scenario '{scenario_name}' restarted but readback shows {updated!r}, expected "
            f"capacity={capacity} leakspeed={leakspeed!r}",
            reason="readback_mismatch",
        )
    return {"status": "ok", "scenario": updated}


# ---------------------------------------------------------------------------
# A-45: "Проверить обновления"/"Применить обновления" — REVISES the "A-43
# addendum" docstring section's own "Обновить сценарии ... deliberately does
# NOT get this same treatment" paragraph above (not a silent reversal — see
# this module's own "A-45 addendum" docstring section for the full
# rationale, and docs/план-спецификация-фаза-0-обновление-сценариев-
# 2026-07-25.md's own "Пересмотр решения A-43" for why this is a considered
# revision, not scope creep). Two independent elevated actions, each its own
# `elevated_run()` prompt:
#
#   1. `check_scenario_updates()` — `cscli hub update && cscli hub upgrade
#      --dry-run`, LOW content risk (only downloads `.index.json`, installs
#      nothing — confirmed live, see "A-45 addendum"). Returns the raw
#      combined output as `plan` (A-36's own "show the real tool output,
#      don't reinvent structured parsing" discipline, same as
#      os_firewall.read_firewall_rules/app.js's renderFirewallRulesList) and
#      an honestly-computed `has_upgrades` flag.
#   2. `apply_scenario_updates()` — the SAME class of write A-43's own
#      `write_scenario_threshold` above already established (`cscli hub
#      upgrade` touches the exact same `/etc/crowdsec/scenarios/*.yaml`
#      files that section's sed-based write does — see this module's "A-43
#      addendum" docstring section — so it needs the SAME `docker compose
#      restart crowdsec` + mandatory SEPARATE readback, never trusting a
#      clean exit alone).
# ---------------------------------------------------------------------------

_SCENARIO_UPDATES_CHECK_REASON_RU = "Hranix Shield: проверить обновления сценариев CrowdSec"
_SCENARIO_UPDATES_CHECK_REASON_EN = "Hranix Shield: check CrowdSec scenario updates"
_SCENARIO_UPDATES_APPLY_REASON_RU = "Hranix Shield: применить обновления сценариев CrowdSec"
_SCENARIO_UPDATES_APPLY_REASON_EN = "Hranix Shield: apply CrowdSec scenario updates"
_HUB_LIST_READ_REASON_RU = "Hranix Shield: прочитать список установленных сценариев CrowdSec"
_HUB_LIST_READ_REASON_EN = "Hranix Shield: read the list of installed CrowdSec scenarios"

# Post-merge review fix: `elevated_run`'s own default timeout (120s) was
# sized around purely LOCAL actions (docker exec/pf/netsh on the same
# machine) plus human password-entry time — every other elevated call in
# this module fits that budget. `check_scenario_updates`/
# `apply_scenario_updates` are the first ones that also perform a REAL
# network fetch against hub.crowdsec.net (`cscli hub update`/`hub upgrade`),
# on top of the same human reaction time, so they get a longer budget here
# rather than risking a slow-connection `elevation_failed` that would
# misleadingly read as "the OS elevation itself failed."
_SCENARIO_UPDATES_ELEVATED_TIMEOUT = 300.0

# Confirmed live both ways on the same container (see this module's "A-45
# addendum" docstring section): `cscli hub upgrade --dry-run`'s own "Action
# plan:" section always prints a `🔄 check & update data files` line
# regardless of whether there is anything real to install — that line is
# NOT itself a "nothing to do" signal. What DOES reliably distinguish "real
# upgrades queued" from "already current" is the `📥 download` section,
# which only ever appears together with one or more `name (OLD -> NEW)`
# version-bump lines. Checked via the literal `" -> "` substring rather than
# the `📥` glyph itself (a multi-byte emoji, more fragile to encoding/
# terminal-rendering drift) or a section-header string match (CrowdSec could
# reword "download"/"check & update data files" in a future release without
# touching the one part of this text that is the actual payload: a real
# version bump).
#
# Known imprecision (post-merge review finding, accepted as-is): this
# module's own test fixture contains a same-version resync line —
# `collections: crowdsecurity/sshd (0.9 -> 0.9)` — which still matches this
# substring even though old/new versions are identical (e.g. a hub
# re-publish that only touches metadata, or restoring a locally-tainted
# file). That means `has_upgrades`/`applied` can read `True` for a
# "install" that changes nothing meaningful, showing the "Apply" button or
# reporting `applied: true` slightly too eagerly. This is a UI-precision
# issue, not a safety one: `apply_scenario_updates` now always restarts
# regardless of this heuristic (see `_build_apply_scenario_updates_script`),
# so a false-positive match here can, at worst, prompt an unnecessary-but-
# harmless "Apply" click — never a missed real upgrade.
_SCENARIO_UPDATE_ARROW = " -> "


def _scenario_update_plan_has_upgrades(plan_text: str) -> bool:
    """True iff `plan_text` (raw `cscli hub upgrade --dry-run` output, see
    `check_scenario_updates` below) shows at least one real version bump
    queued — see `_SCENARIO_UPDATE_ARROW`'s own comment for exactly how this
    was confirmed live, both the "real upgrades" and "already current" case,
    on the same container."""
    return _SCENARIO_UPDATE_ARROW in plan_text


def _build_check_scenario_updates_script() -> str:
    """The INNER `sh -c` payload run inside the container for
    `check_scenario_updates` below — `cscli hub update` (refreshes the local
    `.index.json` catalogue only, confirmed live to install nothing, see
    this module's "A-45 addendum" docstring section) THEN, only if that
    succeeded, `cscli hub upgrade --dry-run` (confirmed live to be
    CrowdSec's own real, official flag — "print the execution plan" —
    installs nothing either). Each command's own stderr is folded into ITS
    OWN stdout (`2>&1` on each individually, not once at the very end) so a
    `cscli hub update` failure (e.g. hub.crowdsec.net unreachable) still
    shows its own real diagnostic text rather than the `&&` short-circuit
    silently discarding it."""
    return "cscli hub update 2>&1 && cscli hub upgrade --dry-run 2>&1"


async def check_scenario_updates() -> dict[str, Any]:
    """A-45: "Проверить обновления" — ONE elevated `docker exec` (the SAME
    one-shot, never-cached, visible OS admin-password prompt every other
    action in this module already uses) running
    `_build_check_scenario_updates_script()`'s two-step read. Returns the
    RAW combined output as `plan` — never reformatted/re-parsed into a
    structured shape, the same "show the real tool output" discipline A-36's
    `read_firewall_rules`/app.js's `renderFirewallRulesList` already
    established — plus an honestly-computed `has_upgrades` (see
    `_scenario_update_plan_has_upgrades`), which is ALL the frontend needs
    to decide whether to show the "Применить обновления" button at all.

    Raises `CrowdSecScenarioError` (`elevation_cancelled`/
    `elevation_failed`) on anything other than a clean `ok` — same
    raise-on-non-ok contract `read_scenario_thresholds` above already
    established."""
    docker_binary = _resolve_docker_binary()
    result = await elevated_run(
        [docker_binary, "exec", CROWDSEC_CONTAINER_NAME, "sh", "-c", _build_check_scenario_updates_script()],
        reason_ru=_SCENARIO_UPDATES_CHECK_REASON_RU,
        reason_en=_SCENARIO_UPDATES_CHECK_REASON_EN,
        timeout=_SCENARIO_UPDATES_ELEVATED_TIMEOUT,
    )
    if result.status != "ok":
        _raise_for_scenario_elevated_result(result)
    plan = result.stdout
    return {"status": "ok", "plan": plan, "has_upgrades": _scenario_update_plan_has_upgrades(plan)}


def _parse_hub_list_outdated(raw_stdout: str) -> list[str]:
    """Parses `cscli hub list -o json`'s stdout (confirmed live: clean,
    complete JSON on stdout alone — the diagnostic "X is outdated because of
    Y"/"Loaded: .../Unmanaged items: ..." lines cscli also prints go to
    STDERR, same split confirmed for `check_scenario_updates` above) into
    the list of every currently-outdated item's `name`, across EVERY hub
    category (`collections`/`scenarios`/`postoverflows`/`parsers`/
    `contexts`/`appsec-configs`/`appsec-rules` — CrowdSec's own top-level
    keys, confirmed live) — any item whose own `status` field contains
    CrowdSec's exact `"update-available"` marker (confirmed live against the
    real outdated items this task's own research produced, see this
    module's "A-45 addendum" docstring section). An empty list is the
    honest "everything genuinely current" signal `apply_scenario_updates`'s
    own mandatory readback checks for — never assumed from a clean restart
    alone."""
    try:
        payload = json.loads(raw_stdout)
    except (ValueError, TypeError):
        return ["<unparseable `cscli hub list -o json` output>"]
    if not isinstance(payload, dict):
        return ["<unexpected `cscli hub list -o json` shape>"]
    outdated: list[str] = []
    for items in payload.values():
        if not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and "update-available" in (item.get("status") or ""):
                outdated.append(item.get("name") or "?")
    return outdated


async def _read_hub_outdated_items() -> list[str]:
    """ONE elevated `docker exec ... cscli hub list -o json` call — see
    `_parse_hub_list_outdated` above for exactly what "outdated" means here.
    This is `apply_scenario_updates`'s own MANDATORY, SEPARATE readback (a
    second, independent elevation prompt) — never trusting `cscli hub
    upgrade`'s own clean exit plus a successful container restart as proof
    the new versions are genuinely active, the exact same "a restart exiting
    zero is not proof the change applied" discipline `write_scenario_
    threshold` (A-43) already established for its own sed-based write."""
    docker_binary = _resolve_docker_binary()
    result = await elevated_run(
        [docker_binary, "exec", CROWDSEC_CONTAINER_NAME, "sh", "-c", "cscli hub list -o json"],
        reason_ru=_HUB_LIST_READ_REASON_RU,
        reason_en=_HUB_LIST_READ_REASON_EN,
    )
    if result.status != "ok":
        _raise_for_scenario_elevated_result(result)
    return _parse_hub_list_outdated(result.stdout)


_APPLY_MARKER_UPGRADED = "HRANIX_SCENARIO_UPDATES_APPLIED"
_APPLY_MARKER_NOOP = "HRANIX_SCENARIO_UPDATES_NOOP"


def _build_apply_scenario_updates_script(docker_binary: str) -> str:
    """The full HOST-side bash script `apply_scenario_updates` below runs
    via ONE `elevated_run(["/bin/bash", <this script's path>], ...)` call —
    the same "one script file, one elevation prompt for a whole multi-step
    sequence" shape `_build_write_scenario_script` (A-43) already
    established.

    Two real steps, in order:
      1. INNER `docker exec ... cscli hub upgrade` (no `--dry-run` — a REAL
         install this time), output captured combined (`2>&1`, same as
         `_build_check_scenario_updates_script`'s own dry-run capture).
      2. UNCONDITIONAL `docker compose -f <this repo's own
         infra/security/crowdsec/docker-compose.yml, absolute path> restart
         crowdsec` — this restart is NOT gated on step 1's own text output
         matching `_SCENARIO_UPDATE_ARROW` (post-merge review finding: only
         the DRY-RUN form of `cscli hub upgrade`'s stdout was ever
         confirmed live against this exact arrow heuristic — see the "A-45
         addendum" — the REAL, non-dry-run command's own stdout format was
         never independently verified to match it). Gating the restart on
         that same heuristic risked a silent bug: `cscli hub upgrade`
         writes new scenario YAML to disk regardless of what its own text
         happens to say, but CrowdSec only re-reads that YAML on container
         start — a missed restart would leave the running engine silently
         enforcing stale, pre-upgrade rules, and the mandatory readback
         below (`cscli hub list -o json`) would not even catch it, since
         hub-list metadata reflects what's on disk, not what the running
         process has loaded. Restarting when nothing actually changed is a
         harmless few-seconds LAPI blip; skipping a restart that was really
         needed is a silent correctness bug — so this always restarts.
         `_SCENARIO_UPDATE_ARROW` is still checked here, but ONLY to decide
         which marker to report (see `_APPLY_MARKER_UPGRADED`/`_NOOP`
         below) — a purely informational "did it look like something was
         installed" signal for the response's `applied` field, never a gate
         on whether to restart.

    Nothing else — `apply_scenario_updates` below does its own SEPARATE
    elevated readback (`_read_hub_outdated_items`) afterwards, never
    trusting this restart's own clean exit as proof the new scenario
    versions are genuinely active now (same discipline as A-43's own write
    path). Because the restart above is now unconditional, that readback's
    own `readback_mismatch` error (worded as "the container restarted
    without error, but...") is truthful in every code path that can reach
    it — there is no longer a distinct "restart was skipped" branch to
    mislabel."""
    docker_quoted = shlex.quote(docker_binary)
    compose_quoted = shlex.quote(str(_CROWDSEC_COMPOSE_FILE))
    inner_quoted = shlex.quote("cscli hub upgrade 2>&1")
    arrow_quoted = shlex.quote(_SCENARIO_UPDATE_ARROW)
    lines = [
        "#!/bin/bash",
        "set -e",
        f"OUTPUT=$({docker_quoted} exec {CROWDSEC_CONTAINER_NAME} sh -c {inner_quoted})",
        'echo "$OUTPUT"',
        f"{docker_quoted} compose -f {compose_quoted} restart crowdsec >/dev/null 2>&1",
        f'if echo "$OUTPUT" | grep -qF -- {arrow_quoted}; then',
        f'  echo "{_APPLY_MARKER_UPGRADED}"',
        "else",
        f'  echo "{_APPLY_MARKER_NOOP}"',
        "fi",
        "",
    ]
    return "\n".join(lines)


async def apply_scenario_updates() -> dict[str, Any]:
    """A-45: "Применить обновления" — the elevated APPLY half, meant to be
    called after the frontend already showed the operator a real plan via
    `check_scenario_updates` above (the router does not itself enforce that
    ordering — see this module's own "A-45 addendum" docstring section for
    why: CrowdSec's own state can change between the two calls, e.g. another
    operator/process already applied the same upgrade in the meantime,
    which is why `applied` below can honestly come back `False` without
    that being an error).

    Raises `CrowdSecScenarioError` — `elevation_cancelled`/`elevation_failed`
    same as every other elevated action in this module, plus
    `readback_mismatch` (REUSED verbatim from A-43's own
    `write_scenario_threshold`, not a new sibling code: the underlying claim
    is identical — "the container restarted without error, but a fresh read
    still shows something not current" — just for a hub-upgrade write
    instead of a sed write. This wording is truthful here in every reachable
    branch precisely because `_build_apply_scenario_updates_script` restarts
    UNCONDITIONALLY — see that function's own docstring)."""
    docker_binary = _resolve_docker_binary()
    script = _build_apply_scenario_updates_script(docker_binary)

    with tempfile.TemporaryDirectory(prefix="hranix-crowdsec-scenario-updates-") as tmp:
        script_path = Path(tmp) / "hranix-scenario-updates-apply.sh"
        script_path.write_text(script, encoding="utf-8")
        result = await elevated_run(
            ["/bin/bash", str(script_path)],
            reason_ru=_SCENARIO_UPDATES_APPLY_REASON_RU,
            reason_en=_SCENARIO_UPDATES_APPLY_REASON_EN,
            timeout=_SCENARIO_UPDATES_ELEVATED_TIMEOUT,
        )
    if result.status != "ok":
        _raise_for_scenario_elevated_result(result)

    stripped_stdout = result.stdout.strip()
    output_lines = stripped_stdout.splitlines()
    marker = output_lines[-1] if output_lines else ""
    if marker not in (_APPLY_MARKER_UPGRADED, _APPLY_MARKER_NOOP):
        raise CrowdSecScenarioError(
            f"unexpected output from the scenario-updates apply script: {result.stdout!r}",
            reason="elevation_failed",
        )
    applied = marker == _APPLY_MARKER_UPGRADED
    # Post-merge review fix: `output_lines` still ends with this module's
    # own internal sentinel marker line — that's bookkeeping for this
    # function, not real `cscli`/`docker` output, so it must never leak into
    # the "plan" text the operator sees (app.js's renderScenarioUpdatesPlan
    # renders every line of `plan` verbatim).
    plan_text = "\n".join(output_lines[:-1])

    # A-45: mandatory readback — a SEPARATE elevated call (its own OS
    # prompt), never trusting the restart's own clean exit above as proof
    # the new versions are genuinely active now (same discipline as A-43's
    # write_scenario_threshold).
    outdated_after = await _read_hub_outdated_items()
    if outdated_after:
        raise CrowdSecScenarioError(
            f"cscli hub upgrade reported {marker!r} but a fresh readback still shows outdated items: "
            f"{outdated_after!r}",
            reason="readback_mismatch",
        )
    return {"status": "ok", "applied": applied, "plan": plan_text}


# ---------------------------------------------------------------------------
# A-44: allowlist write ("Добавить в белый список"/"Удалить") — elevated
# docker-exec, applying A-43's already-established narrow exception to
# "никогда docker exec" to a SECOND action. Per
# docs/план-спецификация-фаза-0-белый-список-запись-2026-07-25.md's own
# "Архитектурное решение — не переоткрывается": this section does NOT
# re-argue why a one-shot, never-cached elevated_run() prompt is an
# acceptable narrow exception — see this module's own "A-43 addendum"
# docstring section above for that (not reargued a second time here).
#
# Genuinely SIMPLER than A-43's scenario-threshold section above: `cscli
# allowlists create/add/remove` are direct CLI operations against
# CrowdSec's own allowlist feature (a runtime concept CrowdSec re-reads on
# every LAPI request), not hand-edited YAML — no sed, no multi-document
# file parsing, and critically no `docker compose restart` (unlike
# scenario capacity/leakspeed, which IS only loaded at container startup —
# see the "A-43 addendum" section above).
#
# Real data confirmed live by the architect before writing this task's plan
# document (see docs/план-спецификация-фаза-0-белый-список-запись-
# 2026-07-25.md): `cscli allowlists create <name>` is NOT idempotent on its
# own — a second call on an existing name answers `Error: cscli allowlists
# create: allowlist '<name>' already exists` (exit 1) —
# `_ALLOWLIST_ALREADY_EXISTS_TEXT` below is that exact text, matched inside
# the elevated script itself (a shell `case` pattern, not a second Python-
# side elevated round trip) so "already exists" is honestly treated as "the
# allowlist is ready", never as a failure.
#
# UI note (per the plan document's own "проще UX" reasoning): Phase 0's
# panel shows ONE flat «Белый список» (A-42's `_flatten_allowlist_items`),
# not per-named-allowlist grouping — so this section manages exactly ONE
# named allowlist, `_ALLOWLIST_NAME` below, created lazily on first use
# rather than asking the operator to name/pick one.
# ---------------------------------------------------------------------------

_ALLOWLIST_NAME = "hranix_manual"
_ALLOWLIST_DESCRIPTION = "Hranix Shield: entries added manually via the admin console"
# cscli's own exact wording (see this section's docstring above) — matched
# as a shell `case` glob (`*"already exists"*`), not a Python-side string
# check, because the whole create-if-needed+add sequence is ONE elevated
# call (never a second elevation prompt just to find out whether the first
# one needs a `create` at all).
_ALLOWLIST_ALREADY_EXISTS_TEXT = "already exists"

_ALLOWLIST_ADD_REASON_RU = "Hranix Shield: добавить {value} в белый список CrowdSec"
_ALLOWLIST_ADD_REASON_EN = "Hranix Shield: add {value} to CrowdSec's allowlist"
_ALLOWLIST_REMOVE_REASON_RU = "Hranix Shield: удалить {value} из белого списка CrowdSec"
_ALLOWLIST_REMOVE_REASON_EN = "Hranix Shield: remove {value} from CrowdSec's allowlist"

# Markers the INNER `sh -c` scripts below print as the FIRST line of their
# own stdout (any further lines are raw `cscli` output, kept only as
# diagnostic detail for an exception message — never parsed) — same
# "elevated_run's own clean exit is not enough, parse a marker this
# module's own script controls" discipline as A-43's `_WRITE_MARKER_*`
# above, just first-line instead of last-line (this section's scripts may
# legitimately emit multi-line `cscli` error text AFTER the marker, unlike
# A-43's single-line marker-only stdout).
_ALLOWLIST_CREATE_FAILED_MARKER = "HRANIX_ALLOWLIST_CREATE_FAILED"
_ALLOWLIST_ADD_OK_MARKER = "HRANIX_ALLOWLIST_ADD_OK"
_ALLOWLIST_ADD_FAILED_MARKER = "HRANIX_ALLOWLIST_ADD_FAILED"
_ALLOWLIST_REMOVE_OK_MARKER = "HRANIX_ALLOWLIST_REMOVE_OK"
_ALLOWLIST_REMOVE_FAILED_MARKER = "HRANIX_ALLOWLIST_REMOVE_FAILED"


class CrowdSecAllowlistError(RuntimeError):
    """Raised by `add_to_allowlist`/`remove_from_allowlist` below. `reason`
    is one of:

      - `"elevation_cancelled"` / `"elevation_failed"`: the SAME two
        `elevated_run()` outcomes `CrowdSecScenarioError` above already
        uses (same mechanism, see that class's own docstring) — kept on
        THIS dedicated exception class (not a reuse of
        `CrowdSecScenarioError` itself) because every other reason below is
        allowlist-specific, not scenario-specific; `security_console.py`'s
        own error-status mapping still assigns these two the identical
        409/502 every other elevated action in this module already uses.
      - `"invalid_value"`: the caller-supplied `value` failed THIS module's
        OWN validation (`ipaddress.ip_network(value, strict=False)`)
        before any elevated command was ever attempted — never raised from
        a live result, same "don't send a request already known to be bad"
        discipline `create_ban`'s own IP validation uses.
      - `"allowlist_write_failed"`: the elevated `cscli allowlists create`/
        `add`/`remove` command itself reported a real failure — NOT
        "already exists" on create (that is honestly treated as success,
        see this section's own docstring), and NOT a `remove` that merely
        found nothing to remove (that is left to the mandatory readback
        below to judge honestly, since "already absent" is exactly the
        caller's own desired end state).
      - `"allowlist_readback_mismatch"`: the elevated command itself
        reported success (or, for `remove`, ran without a `write_failed`-
        worthy error) and a FRESH, separate `fetch_allowlists()` call
        still does not show the expected end state (added: value present;
        removed: value absent) — never conflated with a clean success,
        the same "a clean exit is not proof it applied" discipline A-43's
        `write_scenario_threshold` already established. Deliberately a
        DIFFERENT machine code from A-43's own `readback_mismatch` (never
        reused verbatim here): that code's user-facing text explicitly
        says "the container restarted" — true for A-43's mechanism, FALSE
        for this one (allowlist writes never restart anything, see this
        section's own docstring) — reusing it here would be exactly the
        kind of "real but misleading" text this project's own honesty
        discipline exists to prevent.
      - `"allowlist_readback_unavailable"`: the write step itself ran (and
        may well have succeeded), but the mandatory follow-up
        `fetch_allowlists()` came back with a non-`"ok"` `connector.status`
        (CrowdSec became unreachable/unauthorized between the write and
        the read) — genuinely different from `allowlist_readback_mismatch`
        above (that means "checked, and it disagrees"; this means "could
        not check at all"), same "never conflate 'not checked' with
        'checked, wrong'" honesty rule this project applies everywhere
        else (e.g. crowdsec.py's own `_placeholder_ids_data`).
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


def _raise_for_allowlist_elevated_result(result: ElevatedRunResult) -> None:
    """Shared translation from `elevated_run()`'s own three-way `status`
    into `CrowdSecAllowlistError` — mirrors `_raise_for_scenario_elevated_
    result` above (kept as this section's own copy for the same reason
    that one is its own copy of os_firewall.py's version: a different
    exception type)."""
    if result.status == "cancelled":
        raise CrowdSecAllowlistError("the user declined the elevation prompt", reason="elevation_cancelled")
    raise CrowdSecAllowlistError(
        f"elevated command failed: {result.stderr.strip() or result.stdout.strip()}",
        reason="elevation_failed",
    )


def _validate_allowlist_value(value: str) -> None:
    """Plan document's own grammar: a real IP address or CIDR block,
    checked via Python's `ipaddress` BEFORE any elevated command is ever
    attempted — the exact same "never send a request already known to be
    bad" discipline `create_ban`'s own IP validation (module docstring's
    "A-29 addendum") and A-43's `_validate_capacity`/`_validate_leakspeed`
    already use. `strict=False` (not the default `strict=True`) so a host
    address with non-zero host bits inside a `/24` etc. is still accepted —
    CrowdSec's own allowlist accepts both bare IPs and CIDR ranges, never
    requires the CIDR's own network-address form."""
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise CrowdSecAllowlistError(
            f"'{value}' is not a valid IP address or CIDR block", reason="invalid_value"
        ) from exc


def _allowlist_values_match(a: str, b: str) -> bool:
    """True iff `a`/`b` denote the SAME IP/CIDR, compared via `ipaddress`
    (not raw string equality) — deliberately defensive against CrowdSec
    normalising a value's on-disk/API representation differently from what
    the caller originally typed (e.g. host-bits handling), the same
    "never trust two external strings to already be byte-identical"
    caution `ip_matches_any_decision` above already applies to comparing
    CrowdSec decision values against a live connection's IP. Falls back to
    plain string equality if either side fails to parse (should not happen
    — both are expected to already be validated/CrowdSec-supplied — but
    must never crash a readback comparison over one malformed string)."""
    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return a == b


def _find_allowlist_item(flattened_items: list[dict[str, Any]], value: str) -> dict[str, Any] | None:
    """Looks up `value` inside `fetch_allowlists()`'s own already-flattened
    `allowlists` list (see `_flatten_allowlist_items` above) — shared by
    both `add_to_allowlist`'s "is it really there now" check and
    `remove_from_allowlist`'s "is it really gone now" check."""
    for item in flattened_items:
        item_value = item.get("value")
        if item_value and _allowlist_values_match(item_value, value):
            return item
    return None


def _build_allowlist_add_script(value: str, *, comment: str | None) -> str:
    """The INNER `sh -c` payload run inside the container — ONE `docker
    exec` doing BOTH `cscli allowlists create` (idempotent-by-hand, see
    this section's own docstring for the exact live-confirmed "already
    exists" text) and `cscli allowlists add`, never two separate elevation
    prompts for what is conceptually one operation from the operator's own
    point of view ("add this value to my allowlist").

    `value`/`comment` are embedded via `shlex.join` (never hand-rolled
    string interpolation) — the same "don't hand-roll what shlex already
    does correctly" discipline A-43's `_build_write_scenario_script`
    already documents; `comment` in particular is genuinely free-form
    operator text (arbitrary spaces/quotes/unicode), unlike `value` (already
    passed `_validate_allowlist_value` by the time this runs, so its own
    character set is inherently shell-safe, but still quoted the same way
    for consistency, not because it strictly needs it).
    """
    create_cmd = shlex.join(["cscli", "allowlists", "create", _ALLOWLIST_NAME, "-d", _ALLOWLIST_DESCRIPTION])
    add_argv = ["cscli", "allowlists", "add", _ALLOWLIST_NAME, value]
    if comment:
        add_argv += ["-d", comment]
    add_cmd = shlex.join(add_argv)
    return (
        f'CREATE_OUT=$({create_cmd} 2>&1); CREATE_RC=$?\n'
        f'if [ "$CREATE_RC" -ne 0 ]; then\n'
        f'  case "$CREATE_OUT" in\n'
        f'    *"{_ALLOWLIST_ALREADY_EXISTS_TEXT}"*) : ;;\n'
        f'    *) echo "{_ALLOWLIST_CREATE_FAILED_MARKER}"; echo "$CREATE_OUT"; exit 0 ;;\n'
        f'  esac\n'
        f'fi\n'
        f'ADD_OUT=$({add_cmd} 2>&1); ADD_RC=$?\n'
        f'if [ "$ADD_RC" -ne 0 ]; then\n'
        f'  echo "{_ALLOWLIST_ADD_FAILED_MARKER}"; echo "$ADD_OUT"; exit 0\n'
        f'fi\n'
        f'echo "{_ALLOWLIST_ADD_OK_MARKER}"; echo "$ADD_OUT"\n'
    )


def _build_allowlist_remove_script(value: str) -> str:
    """The INNER `sh -c` payload for `remove_from_allowlist` below — a
    single `cscli allowlists remove` call. Deliberately does NOT special-
    case any particular "not in the list"/"list does not exist" error text
    the way `_build_allowlist_add_script` special-cases "already exists"
    (no such exact wording was empirically confirmed for `remove`, unlike
    `create`'s) — instead `remove_from_allowlist`'s own mandatory readback
    is the sole arbiter of success, so a `remove` that "fails" only because
    the value was somehow already gone still correctly reports success
    (idempotent from the operator's point of view: the goal — this value
    is not in the allowlist — already holds)."""
    remove_cmd = shlex.join(["cscli", "allowlists", "remove", _ALLOWLIST_NAME, value])
    return (
        f'OUT=$({remove_cmd} 2>&1); RC=$?\n'
        f'if [ "$RC" -ne 0 ]; then\n'
        f'  echo "{_ALLOWLIST_REMOVE_FAILED_MARKER}"; echo "$OUT"; exit 0\n'
        f'fi\n'
        f'echo "{_ALLOWLIST_REMOVE_OK_MARKER}"; echo "$OUT"\n'
    )


def _parse_allowlist_marker(stdout: str) -> tuple[str, str]:
    """Splits an elevated allowlist script's stdout into `(marker, detail)`
    — `marker` is always the FIRST line (see `_ALLOWLIST_*_MARKER`
    constants' own docstring for why first, not last, unlike A-43's
    single-line convention), `detail` is whatever raw `cscli` output
    followed it (joined back with newlines), used only for a human-
    readable exception message, never parsed further."""
    lines = stdout.strip().splitlines()
    marker = lines[0] if lines else ""
    detail = "\n".join(lines[1:]) if len(lines) > 1 else ""
    return marker, detail


async def add_to_allowlist(
    value: str, *, comment: str | None = None, settings: Settings | None = None
) -> dict[str, Any]:
    """A-44: "Добавить в белый список" — ONE elevated `docker exec` running
    `_build_allowlist_add_script`'s create-if-needed-then-add sequence,
    followed by a MANDATORY, SEPARATE, non-elevated readback via
    `fetch_allowlists()` (A-42's own read path, reused verbatim, not
    duplicated) — never trusting the write script's own marker as proof
    the value is genuinely in the allowlist now, the same discipline A-43's
    `write_scenario_threshold` already established for its own write path.

    The readback is unconditional even when the write script's own `ADD_OK`
    marker was NOT seen (i.e. even after an `ADD_FAILED` marker) EXCEPT for
    `CREATE_FAILED` (nothing could possibly have been written yet, so
    there is nothing useful a readback could confirm) — because `cscli
    allowlists add` can itself fail for a value that is already present
    (an idempotent no-op from the operator's own point of view: the value
    ending up in the allowlist IS the actual goal, regardless of what
    `cscli`'s own exit code says about a second attempt), and only a fresh
    read can honestly tell that apart from a genuine failure.

    Raises `CrowdSecAllowlistError` — see that class's own docstring for
    every `.reason` this can produce."""
    _validate_allowlist_value(value)
    settings = settings or get_settings()

    docker_binary = _resolve_docker_binary()
    script = _build_allowlist_add_script(value, comment=comment)
    result = await elevated_run(
        [docker_binary, "exec", CROWDSEC_CONTAINER_NAME, "sh", "-c", script],
        reason_ru=_ALLOWLIST_ADD_REASON_RU.format(value=value),
        reason_en=_ALLOWLIST_ADD_REASON_EN.format(value=value),
    )
    if result.status != "ok":
        _raise_for_allowlist_elevated_result(result)

    marker, detail = _parse_allowlist_marker(result.stdout)
    if marker == _ALLOWLIST_CREATE_FAILED_MARKER:
        raise CrowdSecAllowlistError(
            f"failed to create allowlist '{_ALLOWLIST_NAME}': {detail}", reason="allowlist_write_failed"
        )

    readback = await fetch_allowlists(settings)
    if readback["connector"]["status"] != "ok":
        raise CrowdSecAllowlistError(
            f"added '{value}' but the follow-up readback could not run "
            f"(connector status: {readback['connector']['status']})",
            reason="allowlist_readback_unavailable",
        )
    item = _find_allowlist_item(readback["allowlists"], value)
    if item is None:
        raise CrowdSecAllowlistError(
            f"cscli allowlists add reported {marker!r} ({detail}) but '{value}' is not present in a "
            "fresh readback",
            reason="allowlist_readback_mismatch",
        )
    return {"status": "ok", "item": item}


async def remove_from_allowlist(value: str, *, settings: Settings | None = None) -> dict[str, Any]:
    """A-44: "Удалить" (per allowlist row) — the mirror of `add_to_allowlist`
    above: ONE elevated `docker exec cscli allowlists remove`, followed by
    the SAME mandatory, separate `fetch_allowlists()` readback — see that
    function's docstring and `_build_allowlist_remove_script`'s own
    docstring for why THIS function never special-cases a "not found"-style
    `cscli` error text the way `add_to_allowlist` special-cases "already
    exists": the readback alone decides success, unconditionally.

    Raises `CrowdSecAllowlistError` — see that class's own docstring for
    every `.reason` this can produce."""
    _validate_allowlist_value(value)
    settings = settings or get_settings()

    docker_binary = _resolve_docker_binary()
    script = _build_allowlist_remove_script(value)
    result = await elevated_run(
        [docker_binary, "exec", CROWDSEC_CONTAINER_NAME, "sh", "-c", script],
        reason_ru=_ALLOWLIST_REMOVE_REASON_RU.format(value=value),
        reason_en=_ALLOWLIST_REMOVE_REASON_EN.format(value=value),
    )
    if result.status != "ok":
        _raise_for_allowlist_elevated_result(result)

    marker, detail = _parse_allowlist_marker(result.stdout)

    readback = await fetch_allowlists(settings)
    if readback["connector"]["status"] != "ok":
        raise CrowdSecAllowlistError(
            f"removed '{value}' but the follow-up readback could not run "
            f"(connector status: {readback['connector']['status']})",
            reason="allowlist_readback_unavailable",
        )
    item = _find_allowlist_item(readback["allowlists"], value)
    if item is not None:
        raise CrowdSecAllowlistError(
            f"cscli allowlists remove reported {marker!r} ({detail}) but '{value}' is still present in "
            "a fresh readback",
            reason="allowlist_readback_mismatch",
        )
    return {"status": "ok", "value": value}


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
