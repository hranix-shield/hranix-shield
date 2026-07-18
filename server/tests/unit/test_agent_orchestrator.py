import pytest
from pydantic import BaseModel

from app.services.agent.orchestrator import (
    AgentOrchestrator,
    ToolArgumentError,
    ToolNotFoundError,
)
from app.services.agent.tool import Tool


class EchoParams(BaseModel):
    text: str


async def _echo(text: str) -> str:
    return text


def _echo_tool() -> Tool:
    return Tool(
        name="echo",
        description="Echoes back the given text.",
        parameters=EchoParams,
        func=_echo,
    )


@pytest.mark.unit
async def test_call_tool_returns_the_registered_functions_result():
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    result = await orchestrator.call_tool("echo", {"text": "hello"})

    assert result == "hello"


@pytest.mark.unit
async def test_call_tool_with_no_arguments_validates_against_an_empty_dict():
    orchestrator = AgentOrchestrator()

    class NoArgsParams(BaseModel):
        pass

    async def ping() -> str:
        return "pong"

    orchestrator.register_tool(
        Tool(name="ping", description="Health ping.", parameters=NoArgsParams, func=ping)
    )

    assert await orchestrator.call_tool("ping") == "pong"


@pytest.mark.unit
async def test_get_tool_returns_the_registered_tool():
    orchestrator = AgentOrchestrator()
    tool = _echo_tool()
    orchestrator.register_tool(tool)

    assert orchestrator.get_tool("echo") is tool


@pytest.mark.unit
async def test_registering_a_second_tool_under_the_same_name_replaces_the_first():
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    async def shout(text: str) -> str:
        return text.upper()

    orchestrator.register_tool(
        Tool(
            name="echo",
            description="Shouts back the given text.",
            parameters=EchoParams,
            func=shout,
        )
    )

    assert await orchestrator.call_tool("echo", {"text": "hi"}) == "HI"


@pytest.mark.unit
async def test_call_tool_raises_tool_not_found_error_for_an_unregistered_name():
    orchestrator = AgentOrchestrator()

    with pytest.raises(ToolNotFoundError) as excinfo:
        await orchestrator.call_tool("does_not_exist", {})

    assert "does_not_exist" in str(excinfo.value)
    assert excinfo.value.name == "does_not_exist"


@pytest.mark.unit
async def test_call_tool_error_lists_known_tool_names():
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    with pytest.raises(ToolNotFoundError) as excinfo:
        await orchestrator.call_tool("missing")

    assert "echo" in str(excinfo.value)


@pytest.mark.unit
def test_get_tool_raises_tool_not_found_error_for_an_unregistered_name():
    orchestrator = AgentOrchestrator()

    with pytest.raises(ToolNotFoundError):
        orchestrator.get_tool("nope")


@pytest.mark.unit
async def test_call_tool_with_missing_required_argument_raises_tool_argument_error():
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    with pytest.raises(ToolArgumentError) as excinfo:
        await orchestrator.call_tool("echo", {})

    assert excinfo.value.name == "echo"


@pytest.mark.unit
async def test_call_tool_with_wrong_argument_type_raises_tool_argument_error():
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    with pytest.raises(ToolArgumentError):
        await orchestrator.call_tool("echo", {"text": {"not": "a string or int-like value"}})


@pytest.mark.unit
async def test_invalid_arguments_never_reach_the_tool_function():
    orchestrator = AgentOrchestrator()
    called = False

    async def should_not_run(text: str) -> str:
        nonlocal called
        called = True
        return text

    orchestrator.register_tool(
        Tool(name="echo", description="Echo.", parameters=EchoParams, func=should_not_run)
    )

    with pytest.raises(ToolArgumentError):
        await orchestrator.call_tool("echo", {})

    assert called is False


@pytest.mark.unit
async def test_call_tool_ignores_unexpected_extra_arguments_per_pydantic_default():
    """Documents current behavior rather than prescribing it: pydantic's
    default `model_config` ignores fields not declared on the model, so an
    extra key in `arguments` is silently dropped, not rejected. If a later
    phase needs strict rejection of unknown arguments, that is a
    `model_config = ConfigDict(extra="forbid")` on the specific tool's
    parameters model, not a behavior change here."""
    orchestrator = AgentOrchestrator()
    orchestrator.register_tool(_echo_tool())

    result = await orchestrator.call_tool("echo", {"text": "hi", "unexpected": "ignored"})

    assert result == "hi"


@pytest.mark.unit
async def test_a_tools_own_exception_propagates_out_of_call_tool():
    orchestrator = AgentOrchestrator()

    async def broken(text: str) -> str:
        raise RuntimeError("tool blew up")

    orchestrator.register_tool(
        Tool(name="broken", description="Always fails.", parameters=EchoParams, func=broken)
    )

    with pytest.raises(RuntimeError, match="tool blew up"):
        await orchestrator.call_tool("broken", {"text": "irrelevant"})
