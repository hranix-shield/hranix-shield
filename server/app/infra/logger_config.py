"""Structured (JSON) logging with write-time PII/secret masking.

Ported from the *idea* proven in AI-Tutor-Gemma4n/logger_config.py (a JSON
formatter + a `logging.Filter` that runs before any handler writes a record),
not from its code: that project is a multi-user tutoring service with a
different sensitive-field set (student/parent data). This module's field list
is scoped to what this project's auth/security panel actually handles today
(A-1..A-4) plus the patterns A-6+ is expected to introduce (secrets/tokens
under new field names).

Design (see docs/план-спецификация-фаза-0-2026-07-14.md, A-5):
- No new dependency: the JSON encoding uses the stdlib `json` module only,
  same approach as the AI-Tutor reference. A dedicated JSON-logging library
  (e.g. python-json-logger, structlog) would be OSI-friendly too, but this
  formatter is ~30 lines and the whole point of A-5 is controlling exactly
  when/how masking happens before serialization — pulling in a library here
  buys nothing this project needs yet.
- Masking happens in a `logging.Filter` (`SensitiveDataFilter`), not in the
  formatter. Filters run before `Handler.emit()` calls the formatter, so by
  the time *any* handler (console, file, or a future one) formats the
  record, the mutated `record.msg`/`record.args`/extra attributes/`exc_text`
  already contain only masked values — masking-at-write, not
  clean-then-hide-at-read.
- Two independent masking strategies, chosen per field:
    1. Key-name based full redaction, for fields whose VALUE has no
       detectable shape (a password looks like any other string) — the key
       name is the only signal available. Covers exact names
       (`password`, `hashed_password`, `authorization`, ...) *and* substring
       patterns (`*secret*`, `*token*`, `*credential*`) so a brand new field
       introduced by a later task (A-6+) is masked without this file needing
       an edit, as long as its name contains one of those words.
    2. Value-shape based partial redaction, for data with a recognizable
       pattern regardless of which key it's stored under (or if it shows up
       inside free-text message content or a traceback): JWTs, `Bearer ...`
       headers, email addresses, IPv4 addresses. Applied to every string
       value this filter sees, not just ones under a matching key name.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import re
from pathlib import Path
from typing import Any

MASK = "***MASKED***"
MASK_JWT = "***MASKED_JWT***"

# --- Key-name based full redaction ------------------------------------------
#
# Exact (case-insensitive) key names this project's A-1..A-4 code already
# deals with, or that A-6+ (email/calendar/CRM, per CLAUDE.md) is likely to
# introduce under an unambiguous name.
_SENSITIVE_KEY_NAMES = frozenset(
    {
        "password",
        "hashed_password",
        "current_password",
        "new_password",
        "confirm_password",
        "credentials",
        "authorization",
        "access_token",
        "refresh_token",
        "id_token",
        "jwt",
        "jwt_secret",
        "secret",
        "api_key",
        "apikey",
        "client_secret",
        "webhook_secret",
        "session_token",
    }
)

# Case-insensitive substrings on the key NAME that force full redaction even
# for a field not explicitly listed above — this is what lets a future field
# like `crm_client_secret` or `mcp_session_token` (A-6+) get masked without
# ever touching this file. Deliberately does NOT include a bare "key" (would
# false-positive on primary_key/foreign_key-style fields that aren't secret).
_SENSITIVE_KEY_PATTERNS = ("password", "secret", "token", "credential", "authorization")

# Keys treated as "this holds an email address" for the partial email mask
# below, independent of whether the value happens to match the email regex.
_EMAIL_KEY_PATTERNS = ("email",)

# Keys treated as "this holds an IP address" — whole-token match only (split
# on non-alphanumeric), not a bare substring. A substring check on "ip" would
# false-positive on ordinary field names like "recipient" or "description".
_IP_KEY_TOKENS = frozenset({"ip", "addr", "address"})
_IP_KEY_EXACT_NAMES = frozenset(
    {"client_ip", "remote_addr", "remote_ip", "source_ip", "peer_ip", "x_forwarded_for"}
)


def _is_fully_redacted_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _SENSITIVE_KEY_NAMES:
        return True
    return any(pattern in lowered for pattern in _SENSITIVE_KEY_PATTERNS)


def _is_email_key(key: str) -> bool:
    lowered = key.lower()
    return any(pattern in lowered for pattern in _EMAIL_KEY_PATTERNS)


def _is_ip_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in _IP_KEY_EXACT_NAMES:
        return True
    tokens = [t for t in re.split(r"[^a-z0-9]+", lowered) if t]
    return any(t in _IP_KEY_TOKENS for t in tokens)


# --- Value-shape based partial redaction ------------------------------------
#
# JWT: three base64url segments separated by dots; the header segment always
# decodes to a JSON object, so it always starts with "eyJ" once base64url
# encoded. Matches a bare token wherever it appears (a field value, or
# embedded in a free-text message/traceback).
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# "Authorization: Bearer <token>" / "Bearer <token>" anywhere in a string —
# covers non-JWT-shaped bearer tokens too (opaque tokens), not just JWTs.
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]+")

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# IPv4 only (dotted-quad); good enough for this phase — see report re: IPv6.
# Deliberately NOT part of `_mask_value_patterns` below (unlike JWT/email):
# a dotted-quad shape is common in perfectly ordinary operational text (bind
# addresses, "Uvicorn running on http://127.0.0.1:8080", version strings),
# so scanning every message/exception string for it produces false positives
# that corrupt legitimate log content — caught live when this exact thing
# mangled uvicorn's own startup banner during A-5's E2E verification run
# (see report). IP masking is therefore key-name gated (`_is_ip_key`) only:
# applied to a field the caller explicitly identified as an address, never
# to free-text message content.
_IPV4_RE = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")


def _mask_email_match(match: re.Match[str]) -> str:
    domain = match.group(0).split("@", 1)[1]
    return f"***@{domain}"


def _mask_ipv4_match(match: re.Match[str]) -> str:
    # Partial mask: keep the /24 subnet, redact the host octet. A security
    # panel's whole point is showing "same network vs. a stranger" for
    # failed-login/lockout events — zeroing the full address would throw
    # away exactly the signal this product exists to show. See report for
    # the full reasoning (this is a judgment call, flagged for review).
    a, b, c, _d = match.groups()
    return f"{a}.{b}.{c}.0/24"


def _mask_value_patterns(text: str) -> str:
    """Shape-based masking safe to apply to ANY string unconditionally
    (message text, exception tracebacks, arbitrary field values): JWTs and
    email addresses essentially never appear coincidentally in ordinary
    operational log text. IPv4 is intentionally excluded — see `_IPV4_RE`."""
    text = _BEARER_RE.sub(f"Bearer {MASK_JWT}", text)
    text = _JWT_RE.sub(MASK_JWT, text)
    text = _EMAIL_RE.sub(_mask_email_match, text)
    return text


def _mask_value(key: str | None, value: Any) -> Any:
    """Mask a single (key, value) pair. `key=None` means "no key context"
    (e.g. a list element) — only value-shape based masking applies then."""
    if key is not None and _is_fully_redacted_key(key):
        return MASK

    if isinstance(value, str):
        if key is not None and _is_email_key(key) and "@" not in value:
            # Named an email field but doesn't look like one — redact fully
            # rather than silently pass through unmasked.
            return MASK
        masked = _mask_value_patterns(value)
        if key is not None and _is_ip_key(key):
            masked = _IPV4_RE.sub(_mask_ipv4_match, masked)
        return masked
    if isinstance(value, dict):
        return {k: _mask_value(k, v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_mask_value(None, v) for v in value)
    return value


# --- The record-mutating filter ---------------------------------------------

# Marker attribute set on a record once it has been masked. Needed because
# `configure_logging()` attaches a *separate* `SensitiveDataFilter` instance
# to each handler (console + file), but Python's `Logger.callHandlers`
# passes every handler the *same* LogRecord object — so without this guard,
# a record reaching N handlers gets masked N times. Most masks are
# idempotent (re-masking an already-masked value is a no-op), but not all:
# caught live during A-5's E2E verification, where a `client_ip` value was
# masked to "203.0.113.0/24" by the console handler's filter, then the file
# handler's filter matched the still-dotted-quad-shaped "203.0.113.0" inside
# that *already-masked* string and masked it again, producing the corrupted
# "203.0.113.0/24/24". Masking once per record (not once per handler) fixes
# this at the source rather than trying to make every mask idempotent.
_ALREADY_MASKED_MARK = "_hranix_shield_masked"

# Attribute names a plain `logging.LogRecord` always has. Anything else found
# on a record was added via `logger.x(..., extra={...})` and is fair game for
# masking. Computed from a real LogRecord (not hardcoded) so it stays correct
# across Python versions (e.g. 3.12 added `taskName`).
_DEFAULT_RECORD_ATTRS = frozenset(
    vars(logging.LogRecord("_probe", logging.INFO, __file__, 0, "", (), None)).keys()
) | {"message", _ALREADY_MASKED_MARK}


def _safe_get_message(record: logging.LogRecord) -> str:
    try:
        return record.getMessage()
    except Exception:
        return str(record.msg)


class SensitiveDataFilter(logging.Filter):
    """Mutates a LogRecord in place so every handler downstream only ever
    sees already-masked data. Never drops a record (always returns True) —
    this is a masker, not a level/content filter."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, _ALREADY_MASKED_MARK, False):
            return True

        rendered = _safe_get_message(record)
        record.msg = _mask_value_patterns(rendered)
        record.args = ()

        for key in list(vars(record).keys()):
            if key in _DEFAULT_RECORD_ATTRS:
                continue
            setattr(record, key, _mask_value(key, getattr(record, key)))

        if record.exc_info:
            raw_traceback = logging.Formatter().formatException(record.exc_info)
            record.exc_text = _mask_value_patterns(raw_traceback)

        setattr(record, _ALREADY_MASKED_MARK, True)
        return True


# --- JSON formatter ----------------------------------------------------------


class JsonFormatter(logging.Formatter):
    """Serializes an already-masked LogRecord to one JSON line.

    Does not itself mask anything — by the time a record reaches a
    formatter, `SensitiveDataFilter` (attached to the handler) has already
    run. `default=str` covers any non-JSON-serializable extra value (e.g. a
    Path or an Enum) instead of raising and losing the whole log line.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": str(record.msg),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        for key, value in vars(record).items():
            if key in _DEFAULT_RECORD_ATTRS or key in payload:
                continue
            payload[key] = value

        if record.exc_info:
            payload["exception"] = record.exc_text or self.formatException(record.exc_info)

        return json.dumps(payload, default=str, ensure_ascii=False)


# --- Wiring: root logger + uvicorn loggers ----------------------------------

_MANAGED_MARK = "_hranix_shield_managed_handler"


def _remove_managed_handlers(logger: logging.Logger) -> None:
    """Removes only handlers this module previously added, not handlers
    something else (e.g. pytest's caplog) attached to the same logger — so
    calling `configure_logging()` repeatedly (once per `create_app()` call,
    including in tests) is safe and idempotent."""
    for handler in list(logger.handlers):
        if getattr(handler, _MANAGED_MARK, False):
            logger.removeHandler(handler)


def _resolve_log_level(level_name: str) -> int:
    return logging.getLevelNamesMapping().get(level_name.upper(), logging.INFO)


def configure_logging(settings: Any | None = None) -> None:
    """Wires masked, JSON-formatted logging onto the root logger, and
    re-points uvicorn's own loggers at it.

    Called from `app_factory.create_app()` so every code path that starts
    the app (prod entrypoint, or any test calling `create_app()`) gets it —
    including `app.services.event_bus`'s `logger.error(..., exc_info=True)`
    from A-4, which uses the plain stdlib `logging.getLogger(__name__)` and
    therefore flows through whatever the root logger is configured with.

    uvicorn note: `uvicorn.run()` builds its own logging config (dictConfig)
    inside `Config.__init__`, which runs *before* it imports the ASGI app
    (see `Config.load()`) — i.e. before this function ever runs. That config
    gives "uvicorn"/"uvicorn.error"/"uvicorn.access" their own handlers with
    `propagate=False`, which would silently bypass our root handlers. Since
    this function always runs afterwards (triggered by importing `app.main`
    while the app is loaded), it explicitly strips those loggers' own
    handlers and re-enables propagation so their records flow into the same
    masked root handlers as everything else.
    """
    from app.config import get_settings  # local import: avoid a hard import-time cycle

    settings = settings or get_settings()
    level = _resolve_log_level(settings.log_level)

    root_logger = logging.getLogger()
    _remove_managed_handlers(root_logger)
    root_logger.setLevel(level)

    formatter = JsonFormatter()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveDataFilter())
    setattr(console_handler, _MANAGED_MARK, True)
    root_logger.addHandler(console_handler)

    log_file = settings.resolved_log_file
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            filename=str(log_path),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(SensitiveDataFilter())
        setattr(file_handler, _MANAGED_MARK, True)
        root_logger.addHandler(file_handler)

    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uvicorn_logger = logging.getLogger(uvicorn_logger_name)
        uvicorn_logger.handlers = []
        uvicorn_logger.propagate = True
