"""A-5 unit coverage: masking is exercised through a real logger + real
`SensitiveDataFilter` + real `JsonFormatter` + real `StreamHandler` writing to
an in-memory stream — not by calling a masking function in isolation. Each
significant category (email, JWT/Bearer, password, key-name pattern, IP,
exception traceback) gets its own test, per the A-5 DoD.
"""

from __future__ import annotations

import io
import json
import logging
from uuid import uuid4

import pytest

from app.infra.logger_config import MASK, JsonFormatter, SensitiveDataFilter


def _capturing_logger() -> tuple[logging.Logger, io.StringIO]:
    """A logger with a unique name per call (uuid) so tests never share
    handler state, wired exactly like `configure_logging()` wires the root
    logger: StreamHandler -> SensitiveDataFilter -> JsonFormatter."""
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(SensitiveDataFilter())

    logger = logging.getLogger(f"test.logger_config.{uuid4().hex}")
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    logger.handlers = [handler]
    return logger, stream


def _last_record(stream: io.StringIO) -> dict:
    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert lines, "no log line was written"
    return json.loads(lines[-1])


@pytest.mark.unit
def test_password_field_is_masked_in_real_log_output():
    logger, stream = _capturing_logger()

    logger.info("login attempt", extra={"username": "alice", "password": "hunter2"})

    record = _last_record(stream)
    assert record["password"] == MASK
    assert record["username"] == "alice"
    assert "hunter2" not in stream.getvalue()


@pytest.mark.unit
def test_hashed_password_field_is_masked_in_real_log_output():
    logger, stream = _capturing_logger()
    bcrypt_like = "$2b$12$KIXQ6Z8n0y5r7q2p1c3d4eQ7v8s9t0u1v2w3x4y5z6A7B8C9D0E1F"

    logger.info("user row loaded", extra={"hashed_password": bcrypt_like})

    record = _last_record(stream)
    assert record["hashed_password"] == MASK
    assert bcrypt_like not in stream.getvalue()


@pytest.mark.unit
def test_email_field_is_partially_masked_preserving_domain():
    logger, stream = _capturing_logger()

    logger.info("bootstrap admin created", extra={"email": "alice@example.com"})

    record = _last_record(stream)
    assert record["email"] == "***@example.com"
    assert "alice@example.com" not in stream.getvalue()


@pytest.mark.unit
def test_email_pattern_embedded_in_free_text_message_is_masked():
    logger, stream = _capturing_logger()

    logger.info("failed login for alice@example.com from unknown source")

    record = _last_record(stream)
    assert "alice@example.com" not in stream.getvalue()
    assert "***@example.com" in record["message"]


@pytest.mark.unit
def test_authorization_header_value_is_fully_masked_by_key_name():
    logger, stream = _capturing_logger()
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"

    logger.info("incoming request", extra={"authorization": f"Bearer {fake_jwt}"})

    record = _last_record(stream)
    assert record["authorization"] == MASK
    assert fake_jwt not in stream.getvalue()


@pytest.mark.unit
def test_bare_jwt_shaped_value_in_message_is_masked_by_value_shape():
    """No sensitive key involved at all — a JWT embedded directly in a
    free-text message must still be caught, by its shape."""
    logger, stream = _capturing_logger()
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"

    logger.error(f"token decode failed for {fake_jwt}")

    record = _last_record(stream)
    assert fake_jwt not in stream.getvalue()
    assert "***MASKED_JWT***" in record["message"]


@pytest.mark.unit
def test_key_pattern_matches_a_brand_new_secret_field_not_in_the_explicit_list():
    """`*secret*` substring match — proves a future field (e.g. A-6+ adding
    an MCP connector config) is masked without editing this module."""
    logger, stream = _capturing_logger()

    logger.info("webhook configured", extra={"webhook_secret": "sk_live_abcdef123456"})

    record = _last_record(stream)
    assert record["webhook_secret"] == MASK
    assert "sk_live_abcdef123456" not in stream.getvalue()


@pytest.mark.unit
def test_key_pattern_matches_a_brand_new_token_field_not_in_the_explicit_list():
    """`*token*` substring match on a field name never explicitly listed."""
    logger, stream = _capturing_logger()

    logger.info("mcp connector registered", extra={"vault_session_token": "vlt.xyz987"})

    record = _last_record(stream)
    assert record["vault_session_token"] == MASK
    assert "vlt.xyz987" not in stream.getvalue()


@pytest.mark.unit
def test_ipv4_address_is_partially_masked_preserving_subnet():
    logger, stream = _capturing_logger()

    logger.warning("failed login attempt", extra={"client_ip": "203.0.113.42"})

    record = _last_record(stream)
    assert record["client_ip"] == "203.0.113.0/24"
    assert "203.0.113.42" not in stream.getvalue()


@pytest.mark.unit
def test_exception_traceback_containing_a_secret_is_masked():
    logger, stream = _capturing_logger()
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"

    try:
        raise ValueError(f"invalid token: {fake_jwt}")
    except ValueError:
        logger.error("token validation failed", exc_info=True)

    record = _last_record(stream)
    assert fake_jwt not in stream.getvalue()
    assert "***MASKED_JWT***" in record["exception"]


@pytest.mark.unit
def test_ip_shaped_text_in_an_ordinary_message_is_left_untouched():
    """Regression for a real bug caught during A-5's live E2E run: an
    earlier version of this filter scanned every message string for IPv4
    shapes unconditionally, which mangled uvicorn's own startup banner
    ("Uvicorn running on http://127.0.0.1:8765" became
    ".../127.0.0.0/24:8765"). IP masking must only fire for a field the
    caller explicitly identified as an address (see the `client_ip` test
    above), never for incidental dotted-quad shapes in free text.
    """
    logger, stream = _capturing_logger()

    logger.info("Uvicorn running on http://127.0.0.1:8765 (Press CTRL+C to quit)")

    record = _last_record(stream)
    assert record["message"] == "Uvicorn running on http://127.0.0.1:8765 (Press CTRL+C to quit)"


@pytest.mark.unit
def test_a_record_reaching_two_handlers_is_masked_only_once():
    """Regression for a real bug caught during A-5's live E2E run:
    `configure_logging()` attaches a separate `SensitiveDataFilter` instance
    to each handler (console + file), but `Logger.callHandlers` passes every
    handler the *same* LogRecord object. A `client_ip` value got masked by
    the first handler's filter ("...42" -> "...0/24"), then re-masked by the
    second handler's filter (which still saw a dotted-quad shape in
    "...0/24" and masked it again), producing the corrupted
    "203.0.113.0/24/24". One record must only ever be masked once, no
    matter how many handlers it reaches.
    """
    name = f"test.logger_config.{uuid4().hex}"
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    stream_a, stream_b = io.StringIO(), io.StringIO()
    for stream in (stream_a, stream_b):
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(SensitiveDataFilter())  # a distinct instance each time
        logger.addHandler(handler)

    logger.warning("failed login attempt", extra={"client_ip": "203.0.113.42"})

    for stream in (stream_a, stream_b):
        record = _last_record(stream)
        assert record["client_ip"] == "203.0.113.0/24"


@pytest.mark.unit
def test_non_sensitive_fields_pass_through_unmasked():
    """Regression against over-masking: fields with no PII/secret signal
    must remain readable, otherwise the log is useless for debugging."""
    logger, stream = _capturing_logger()

    logger.info(
        "account locked",
        extra={"reason": "account_locked", "username": "carol", "attempt_count": 5},
    )

    record = _last_record(stream)
    assert record["reason"] == "account_locked"
    assert record["username"] == "carol"
    assert record["attempt_count"] == 5
