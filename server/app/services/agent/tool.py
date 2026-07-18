from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel


ToolFunc = Callable[..., Awaitable[Any]]


@dataclass(frozen=True)
class Tool:
    """One capability the `AgentOrchestrator` (orchestrator.py) can invoke by
    name — the unit future phases register (Phase 2 RAG search, Phase 3
    avatar actions, Phases 4-7 tasks/calendar/CRM/email via MCP servers, see
    A-9) without this file or orchestrator.py needing another edit.

    Nothing in this codebase calls a `Tool` yet — Phase 0 ships zero real
    tools (see A-8 task spec) — same "abstraction laid down, not wired up"
    status as A-7's `InferenceBackend`. In particular this class does not
    assume or encode any specific LLM function-calling wire format (OpenAI's
    `tools`/`tool_calls`, Anthropic's `tool_use`, etc.) — how a model decides
    which tool to call and how its response is parsed into a name+arguments
    pair is explicitly out of scope here per the task brief; that belongs to
    whatever chat/agent-loop layer a later phase builds on top of the plain
    "call a tool by name with a dict of arguments" mechanism this module and
    orchestrator.py provide.

    Fields:
      - `name`: the string key tools are registered and looked up under
        (`AgentOrchestrator.call_tool` matches on this, not on `func`'s
        Python identity).
      - `description`: free-form text for whatever later consumes it — most
        likely fed to an LLM as part of a future function-calling prompt/
        schema, but this field makes no assumption about that shape; it is
        plain text, nothing more.
      - `parameters`: a pydantic `BaseModel` subclass declaring the tool's
        argument names, types, and required/optional-ness. Chosen over a
        hand-rolled schema (e.g. a dict of field-name -> type) because
        pydantic is already a first-class dependency of this project (every
        router/config already validates through it — see `app/config.py`),
        so this reuses a validation engine already proven here rather than
        adding a second one; it also gives a `model_json_schema()` for free,
        which a later phase can hand to an LLM's function-calling API
        without this module needing to grow schema-generation code of its
        own. `call_tool` validates a raw `dict[str, Any]` of arguments
        against this model *before* calling `func` (see orchestrator.py) —
        malformed input never reaches the tool's own code.
      - `func`: the actual implementation. Async-only, matching every other
        callable contract already established in this codebase
        (`InferenceBackend.generate`, A-6's `HealthCheck`, A-4's event
        subscribers) — a synchronous tool can simply be an `async def` that
        does its (non-blocking) work directly, per the same reasoning
        `inference/base.py` gives for its own async-only methods. `func` is
        called with the validated arguments unpacked as keyword arguments
        (`func(**validated.model_dump())`), so a tool author writes an
        ordinary typed function — e.g. `async def echo(text: str) -> str` —
        whose parameter names line up with `parameters`'s fields, rather
        than having to unpack a pydantic instance by hand inside every tool.
        The one-time cost is that `parameters`'s field names and `func`'s
        parameter names must agree; a mismatch surfaces immediately as a
        `TypeError` from the `**kwargs` call (a tool-author bug caught the
        first time the tool is exercised, not a silent divergence).
    """

    name: str
    description: str
    parameters: type[BaseModel]
    func: ToolFunc
