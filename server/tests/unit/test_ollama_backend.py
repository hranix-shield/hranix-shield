import json

import httpx
import pytest

from app.config import Settings
from app.services.inference.ollama_backend import OllamaBackend


def _client_with_handler(handler) -> httpx.AsyncClient:
    """An httpx.AsyncClient wired to a fake transport instead of a real
    socket — httpx's own built-in test seam (`MockTransport`), so no extra
    HTTP-mocking dependency is needed just for this one backend (see
    ollama_backend.py's module docstring for the full rationale)."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://ollama.test")


@pytest.mark.unit
async def test_generate_returns_the_response_text_from_ollama():
    captured_request: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured_request["method"] = request.method
        captured_request["url"] = str(request.url)
        return httpx.Response(200, json={"response": "hello from gemma", "done": True})

    backend = OllamaBackend(
        host="http://ollama.test",
        model="gemma4:e4b",
        client=_client_with_handler(handler),
    )

    result = await backend.generate("say hi", temperature=0.2, max_tokens=64)

    assert result == "hello from gemma"
    assert captured_request["method"] == "POST"
    assert captured_request["url"] == "http://ollama.test/api/generate"


@pytest.mark.unit
async def test_generate_sends_model_prompt_and_options_in_the_request_body():
    seen_payload: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen_payload.update(json.loads(request.content))
        return httpx.Response(200, json={"response": "ok"})

    backend = OllamaBackend(
        host="http://ollama.test",
        model="gemma4:e4b",
        client=_client_with_handler(handler),
    )

    await backend.generate("what is 2+2?", temperature=0.5, max_tokens=128)

    assert seen_payload["model"] == "gemma4:e4b"
    assert seen_payload["prompt"] == "what is 2+2?"
    assert seen_payload["stream"] is False
    assert seen_payload["options"] == {"temperature": 0.5, "num_predict": 128}


@pytest.mark.unit
async def test_generate_raises_on_a_non_2xx_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "model not found"})

    backend = OllamaBackend(host="http://ollama.test", client=_client_with_handler(handler))

    with pytest.raises(httpx.HTTPStatusError):
        await backend.generate("hi")


@pytest.mark.unit
async def test_is_available_true_when_ollama_responds_ok():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/tags"
        return httpx.Response(200, json={"models": []})

    backend = OllamaBackend(host="http://ollama.test", client=_client_with_handler(handler))

    assert await backend.is_available() is True


@pytest.mark.unit
async def test_is_available_false_when_ollama_is_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    backend = OllamaBackend(host="http://ollama.test", client=_client_with_handler(handler))

    assert await backend.is_available() is False


@pytest.mark.unit
async def test_is_available_false_on_a_non_2xx_response():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    backend = OllamaBackend(host="http://ollama.test", client=_client_with_handler(handler))

    assert await backend.is_available() is False


@pytest.mark.unit
def test_defaults_come_from_settings_when_not_overridden():
    settings = Settings(ollama_host="http://custom-host:1234", llm_model="qwen:7b")

    backend = OllamaBackend(settings=settings)

    assert backend._host == "http://custom-host:1234"
    assert backend._model == "qwen:7b"


@pytest.mark.unit
async def test_aclose_closes_a_client_it_created_itself():
    backend = OllamaBackend(host="http://ollama.test")

    await backend.aclose()

    assert backend._client.is_closed


@pytest.mark.unit
async def test_aclose_does_not_close_a_caller_supplied_client():
    external_client = _client_with_handler(lambda request: httpx.Response(200, json={}))
    backend = OllamaBackend(host="http://ollama.test", client=external_client)

    await backend.aclose()

    assert external_client.is_closed is False
    await external_client.aclose()
