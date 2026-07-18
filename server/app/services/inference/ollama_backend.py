from __future__ import annotations

import logging

import httpx

from app.config import Settings, get_settings
from app.services.inference.base import InferenceBackend

logger = logging.getLogger(__name__)


class OllamaBackend(InferenceBackend):
    """`InferenceBackend` implementation talking to a local Ollama server
    over HTTP (`OLLAMA_HOST`, default `http://localhost:11434`).

    Uses `httpx.AsyncClient` rather than the `ollama` package already listed
    in requirements.txt: this codebase has no other HTTP-client dependency,
    the task brief asks not to add a new one, and `httpx` ships a built-in
    `httpx.MockTransport` that lets tests fake Ollama's responses without a
    real server or an extra mocking library (see
    tests/unit/test_ollama_backend.py) — a second client library would only
    buy a nicer request-building API at the cost of a second thing to mock.

    Not wired into any router/health check — see A-7 task brief: this class
    exists so a later phase can construct and use it, nothing in Phase 0
    does.
    """

    def __init__(
        self,
        *,
        host: str | None = None,
        model: str | None = None,
        settings: Settings | None = None,
        client: httpx.AsyncClient | None = None,
        timeout: float = 60.0,
    ) -> None:
        settings = settings or get_settings()
        self._host = (host or settings.ollama_host).rstrip("/")
        self._model = model or settings.llm_model
        # A caller-supplied client (tests: one built on httpx.MockTransport)
        # is used as-is and is that caller's to close; one built here owns
        # its own connection pool and is closed by `aclose()` below.
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(base_url=self._host, timeout=timeout)

    async def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> str:
        response = await self._client.post(
            "/api/generate",
            json={
                "model": self._model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
        )
        response.raise_for_status()
        return response.json()["response"]

    async def is_available(self) -> bool:
        try:
            response = await self._client.get("/api/tags")
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.warning("inference: ollama availability check failed: %s", exc)
            return False
        return True

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
