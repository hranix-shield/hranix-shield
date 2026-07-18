"""Integration coverage for A-5's global wiring: `create_app()` must connect
every logger under app/ — including A-4's `app.services.event_bus`, which
uses a plain `logging.getLogger(__name__)` — to the masked JSON pipeline,
and repeated `create_app()` calls (as the test suite does dozens of times)
must not accumulate duplicate handlers on the root logger.
"""

from __future__ import annotations

import json
import logging

import pytest

from app.app_factory import create_app
from app.config import Settings
from app.infra.logger_config import JsonFormatter, SensitiveDataFilter, configure_logging


def _managed_handlers(logger: logging.Logger) -> list[logging.Handler]:
    return [h for h in logger.handlers if isinstance(h.formatter, JsonFormatter)]


@pytest.mark.integration
def test_create_app_wires_masked_json_logging_on_root_logger():
    create_app()

    root_logger = logging.getLogger()
    handlers = _managed_handlers(root_logger)

    assert handlers, "create_app() must attach a JsonFormatter-based handler to the root logger"
    assert any(
        isinstance(f, SensitiveDataFilter) for handler in handlers for f in handler.filters
    )


@pytest.mark.integration
def test_repeated_create_app_calls_do_not_accumulate_duplicate_handlers():
    create_app()
    first_count = len(_managed_handlers(logging.getLogger()))

    create_app()
    create_app()
    second_count = len(_managed_handlers(logging.getLogger()))

    assert first_count > 0
    assert second_count == first_count


@pytest.mark.integration
def test_event_bus_logger_errors_flow_through_the_masked_root_pipeline(tmp_path):
    """Exercises the real `configure_logging()` wiring function (not a
    hand-rolled logger) with an isolated log file, then logs through
    `app.services.event_bus`'s own logger name exactly like A-4's
    `EventBus.publish()` does on a failing subscriber — including a secret
    in the simulated failure's message, to prove the traceback gets masked
    too when it flows through the globally-configured pipeline.
    """
    log_file = tmp_path / "wiring.log"
    settings = Settings(_env_file=None, log_level="DEBUG", log_file=str(log_file))

    configure_logging(settings)
    try:
        event_bus_logger = logging.getLogger("app.services.event_bus")
        fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.deadbeefsignature"

        try:
            raise RuntimeError(f"subscriber failed while holding token {fake_jwt}")
        except RuntimeError:
            event_bus_logger.error(
                "event_bus: subscriber %r failed for topic=%r",
                "some_handler",
                "security.alert",
                exc_info=True,
            )
    finally:
        # Restore a clean root logger for whatever test runs next.
        configure_logging(Settings(_env_file=None))

    lines = [line for line in log_file.read_text().splitlines() if line.strip()]
    assert lines
    record = json.loads(lines[-1])

    assert record["logger"] == "app.services.event_bus"
    assert fake_jwt not in log_file.read_text()
    assert "***MASKED_JWT***" in record["exception"]
