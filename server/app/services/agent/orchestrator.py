from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from pydantic import ValidationError

from app.services.agent.tool import Tool

logger = logging.getLogger(__name__)


class ToolNotFoundError(Exception):
    """Raised by `AgentOrchestrator.call_tool` (and `get_tool`) when no tool
    is registered under the given name — a dedicated type rather than a bare
    `KeyError` so a future caller (an LLM tool-calling loop, a router) can
    catch precisely this failure mode without also swallowing unrelated
    `KeyError`s raised from inside a tool's own implementation."""

    def __init__(self, name: str, known_names: Iterable[str]) -> None:
        known = ", ".join(sorted(known_names)) or "(no tools registered)"
        super().__init__(f"No tool registered under name {name!r}. Known tools: {known}.")
        self.name = name


class ToolArgumentError(Exception):
    """Raised by `AgentOrchestrator.call_tool` when the given arguments fail
    validation against the tool's `parameters` model — surfaced *before* the
    tool's own `func` runs, so a bad call never reaches (and never has to
    guard against bad input inside) the tool's implementation. Wraps the
    underlying pydantic `ValidationError` (available as `.validation_error`)
    rather than re-deriving field-level detail, since pydantic already
    produces a precise, structured error."""

    def __init__(self, name: str, error: ValidationError) -> None:
        super().__init__(f"Invalid arguments for tool {name!r}: {error}")
        self.name = name
        self.validation_error = error


class AgentOrchestrator:
    """Extensible registry + invoker of `Tool`s — the tool-calling mechanism
    itself, deliberately with no opinion on *how* a name+arguments pair is
    decided (that is an LLM/agent-loop concern for a later phase, see A-8
    task brief and tool.py's module docstring).

    A caller registers a tool once via `register_tool(tool)` — future phases
    (Phase 2 RAG search, Phase 3 avatar actions, Phases 4-7 tasks/calendar/
    CRM/email via MCP connectors, see A-9) each add their own tools through
    this same call; this file does not need another edit for that, the same
    open-ended-registry shape as A-6's `HealthRegistry.register` or A-4's
    topic set.

    `call_tool(name, arguments)` takes `arguments` as a plain
    `dict[str, Any]` (a JSON object) rather than `**kwargs` at the call site:
    a future LLM function-calling response is naturally a JSON object of
    arguments, and every realistic caller of this orchestrator (an agent
    loop parsing a model's tool-call response, a test) already has the
    arguments as a dict rather than as literal Python keyword arguments — a
    `dict` parameter matches that shape directly instead of asking every
    caller to unpack one first.

    One instance is expected per owner (an agent loop, a test) rather than a
    module-level singleton, same reasoning as `EventBus`/`HealthRegistry`:
    per-instance registrations must never leak between app instances or
    tests.

    Not wired into `app_factory.create_app()` / `app.state` — see A-8 task
    brief: like A-7's `InferenceBackend`, this is a laid-down abstraction
    with zero real tools registered anywhere yet, not a running subsystem.
    """

    def __init__(self) -> None:
        self._tools: dict[str, Tool] = {}

    def register_tool(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Tool:
        try:
            return self._tools[name]
        except KeyError:
            raise ToolNotFoundError(name, self._tools.keys()) from None

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """Look up the tool registered as `name`, validate `arguments`
        against its `parameters` model, then call it.

        Raises `ToolNotFoundError` if `name` is not registered, or
        `ToolArgumentError` if `arguments` fails validation — in both cases
        before the tool's own `func` ever runs. Any exception `func` itself
        raises propagates unchanged: this orchestrator does not decide how a
        tool failure should be handled by whatever calls it.
        """
        tool = self.get_tool(name)
        try:
            validated = tool.parameters.model_validate(arguments or {})
        except ValidationError as exc:
            raise ToolArgumentError(name, exc) from exc
        return await tool.func(**validated.model_dump())
