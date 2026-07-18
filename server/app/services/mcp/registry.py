from __future__ import annotations

from collections.abc import Iterable

from fastapi import Request

from app.services.mcp.connector import MCPConnector


class MCPConnectorNotFoundError(Exception):
    """Raised by `MCPRegistry.get` when no connector is registered under the
    given name — a dedicated type rather than a bare `KeyError`, same
    reasoning as `agent/orchestrator.py`'s `ToolNotFoundError`: a future
    caller (a settings UI resolving a connector by name, A-11's security
    connectors looking up a sibling connector) can catch precisely this
    failure mode without also swallowing unrelated `KeyError`s."""

    def __init__(self, name: str, known_names: Iterable[str]) -> None:
        known = ", ".join(sorted(known_names)) or "(no connectors registered)"
        super().__init__(
            f"No MCP connector registered under name {name!r}. Known connectors: {known}."
        )
        self.name = name


class MCPRegistry:
    """Extensible registry of `MCPConnector` descriptions — the "point of
    registration" CLAUDE.md's MCP extensibility invariant calls for, not a
    running MCP client (see connector.py's module docstring for why real
    wire-protocol handling is explicitly out of scope here).

    A future connector (A-11's CrowdSec/Osquery/Wazuh/ClamAV security-stack
    connectors, and later phases' mail/calendar/CRM/IDS/search connectors)
    registers itself once via `register(connector)` — this file does not
    need another edit for that, the same open-ended-registry shape as
    `HealthRegistry.register` (health/registry.py) or
    `AgentOrchestrator.register_tool` (agent/orchestrator.py). A future
    "Плагины/MCP-коннекторы" settings screen reads the registry back via
    `list_connectors()`.

    One instance is expected per owner (an app instance, a test), not a
    module-level singleton — same reasoning as `EventBus`/`HealthRegistry`/
    `AgentOrchestrator`: per-instance registrations must never leak between
    app instances or tests.

    Updated by A-11: wired into `app_factory.create_app()` /
    `app.state.mcp_registry` now that a first real connector exists
    (`security_connectors.register_default_security_connectors` registers
    CrowdSec here at startup) — no longer the zero-connectors abstraction
    A-7/A-8/A-9 originally laid down.
    """

    def __init__(self) -> None:
        self._connectors: dict[str, MCPConnector] = {}

    def register(self, connector: MCPConnector) -> None:
        self._connectors[connector.name] = connector

    def get(self, name: str) -> MCPConnector:
        try:
            return self._connectors[name]
        except KeyError:
            raise MCPConnectorNotFoundError(name, self._connectors.keys()) from None

    def list_connectors(self) -> list[MCPConnector]:
        """All registered connectors, in registration order (insertion order
        of the underlying dict) — the order a settings screen would most
        naturally list them in, and stable enough for tests to assert on
        directly without needing to sort first."""
        return list(self._connectors.values())


def get_mcp_registry(request: Request) -> MCPRegistry:
    """FastAPI dependency: the registry instance attached to this app (see
    app_factory.create_app -> app.state.mcp_registry), mirrors
    health.registry.get_health_registry / security_console.get_security_console_registry.
    No router depends on this yet in A-11 — added for the same reason those
    two exist: a future "Плагины/MCP-коннекторы" settings screen resolves it
    this way rather than reaching into `request.app.state` directly.
    """
    return request.app.state.mcp_registry
