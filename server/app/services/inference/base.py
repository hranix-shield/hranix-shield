from __future__ import annotations

from abc import ABC, abstractmethod


class InferenceBackend(ABC):
    """Abstraction over a local LLM inference runtime (CLAUDE.md architectural
    invariant: the platform must never hard-wire itself to one runtime).

    Nothing in this codebase calls an `InferenceBackend` yet — Phase 0 ships
    the AI turned off (see A-7 task spec) — but future phases build on this
    same interface without editing it: Phase 2's RAG summarization and
    Phase 3's avatar/agent both generate text through whichever backend is
    configured (`OllamaBackend` today; `llamacpp`/`mlx` implementations of
    this same class later, per `INFERENCE_BACKEND` in .env.example), never by
    importing a concrete backend class directly.

    Shape chosen deliberately narrow for this task:
      - `generate()` is non-streaming — it awaits the full completion and
        returns one `str`. A streaming (async-iterator) method is left out on
        purpose: nothing in Phase 0 consumes generated text at all, so there
        is no caller yet to tell us whether token-by-token delivery actually
        matters; adding it speculatively risks guessing wrong about the
        shape a real streaming consumer (a chat UI in a later phase) will
        need. Non-streaming is also the easier contract to mock in tests and
        to satisfy from any backend (a streaming backend can always buffer
        into one string; the reverse — synthesizing a stream from a backend
        that only ever returns a full string — is not possible). Widening
        this into a streaming method (or adding one alongside it) is for
        whichever future task first needs it.
      - Only `temperature` and `max_tokens` are exposed as generation
        parameters — the two knobs that apply to *any* single-prompt
        completion regardless of backend. Chat-shaped concerns (message
        history/roles, system prompts, tool/function-calling schemas) are
        deliberately out of scope here per the task brief; those belong to
        whatever chat/agent layer is designed on top of this in a later
        phase (A-8), not baked into the base inference contract now.
      - `is_available()` reports whether the backend can currently serve
        requests (server reachable, etc.) as a plain bool. It exists so a
        future task can register it as an A-6 `HealthCheck` without needing
        to touch this class again — but registering it is explicitly out of
        scope for A-7 (see task brief: "НЕ подключай сейчас к health").
    """

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: int = 512,
    ) -> str:
        """Generate a complete text response for `prompt`.

        `temperature` controls sampling randomness (0 = deterministic,
        higher = more random); `max_tokens` caps the length of the
        generated completion. Raises on backend failure (network error, bad
        response, model missing, etc.) — callers decide how to handle that,
        this method does not swallow errors into a sentinel return value.
        """
        raise NotImplementedError

    @abstractmethod
    async def is_available(self) -> bool:
        """Whether this backend can currently serve `generate()` requests.

        Never raises: a backend that cannot be reached is exactly the
        "not available" case, reported as `False`, not an exception.
        """
        raise NotImplementedError
