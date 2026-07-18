from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MCPConnector:
    """A registered *description* of one external MCP server this platform
    knows about — not a live connection to it.

    This is deliberately not a real MCP client: it does not spawn a process,
    open a socket, or speak the MCP JSON-RPC handshake. Real connectors
    (mail/calendar/CRM/IDS/search, the CrowdSec/Osquery/Wazuh/ClamAV stack of
    a later phase, see A-11) live in `mcp-servers/` at the repo root, as
    *external* processes/services this platform's core never links into
    itself (CLAUDE.md: "новая функция = новый MCP-сервер, ядро не трогаем" —
    also the same GPL/AGPL-isolation gate A-11's task brief calls out). What
    this class holds is just enough metadata for `MCPRegistry` (registry.py)
    to track that a connector exists and how it says it should eventually be
    reached, once some future task actually implements the wire protocol:

      - `name`: the string key a connector is registered and looked up
        under (mirrors `Tool.name` in `agent/tool.py`).
      - `description`: free-form human-readable text — what this connector
        is for, most likely surfaced verbatim in a future "Плагины/
        MCP-коннекторы" settings screen (see A-9 task brief).
      - `transport`: a plain string placeholder for how a future real client
        would reach this server — e.g. `"stdio"` for a spawned local
        process, `"http"`/`"sse"` for a networked one, per the MCP spec's own
        transport kinds. Deliberately a plain `str`, not an enum: nothing in
        this codebase branches on this value yet (nothing here speaks the
        wire protocol), so encoding a closed set of "known" transports now
        would be guessing at a shape this task has no caller to validate
        against. A future task that actually implements a transport can
        tighten this into an enum once it knows what it needs.
      - `endpoint`: a plain string placeholder for *where* — a command line
        for a stdio server, a URL for an HTTP/SSE one. Optional (defaults to
        `""`) because at registration time a connector's location may not be
        decided yet (e.g. a security-stack connector registered before its
        target service's address is configured); an empty value simply
        means "not wired up yet", not an error.

    No `func`/`parameters`/tool-calling shape here (contrast `Tool` in
    `agent/tool.py`): a connector is not one callable capability, it is a
    whole external server that a later phase's real MCP client would
    introspect (via MCP's own `tools/list`) to discover *its* callable tools
    — that discovery mechanism is out of scope for this task.
    """

    name: str
    description: str
    transport: str
    endpoint: str = ""
