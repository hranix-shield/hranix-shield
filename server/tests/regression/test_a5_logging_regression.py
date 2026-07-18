"""A-5 regression anchor.

Per docs/инструкция-разработка-фаза-0-2026-07-14.md, every task adds at least
one regression test that must stay green through the rest of the phase (and
beyond). This pins the core A-5 contract later tasks (A-6 diagnostics bundle,
A-13 notification channels, ...) must not break: password/JWT/email values
never reach a real log line in plaintext, and `create_app()` keeps wiring
this masking globally without it needing to be redone per-router.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.app_factory import create_app
from app.config import Settings
from app.infra.logger_config import MASK, configure_logging


@pytest.mark.integration
def test_password_and_jwt_still_never_reach_a_real_log_line_in_plaintext(tmp_path):
    log_file = tmp_path / "regression.log"
    configure_logging(Settings(_env_file=None, log_file=str(log_file)))
    try:
        logger = logging.getLogger("app.regression_test")
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"

        logger.info(
            "login attempt",
            extra={
                "username": "alice",
                "password": "correct horse battery staple",
                "authorization": f"Bearer {fake_jwt}",
                "email": "alice@example.com",
            },
        )
    finally:
        configure_logging(Settings(_env_file=None))

    raw = log_file.read_text()
    assert "correct horse battery staple" not in raw
    assert fake_jwt not in raw
    assert "alice@example.com" not in raw

    record = json.loads([line for line in raw.splitlines() if line.strip()][-1])
    assert record["password"] == MASK
    assert record["authorization"] == MASK
    assert record["email"] == "***@example.com"
    assert record["username"] == "alice"


@pytest.mark.integration
def test_create_app_still_wires_masked_logging_without_per_router_setup():
    """Nothing in app/routers/*.py or app/services/event_bus.py configures
    logging itself — `create_app()` alone must be sufficient."""
    create_app()

    root_logger = logging.getLogger()
    assert any(
        any(isinstance(f, logging.Filter) and type(f).__name__ == "SensitiveDataFilter" for f in h.filters)
        for h in root_logger.handlers
    )
