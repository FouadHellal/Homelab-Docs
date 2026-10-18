"""Structured logging with redaction as the last processor before rendering (ADR-009)."""

import logging
from collections.abc import MutableMapping
from typing import Any

import structlog

from homelab_atlas.redact import redact_data


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Redact every value, including rendered tracebacks (`exception` key)."""
    redacted: MutableMapping[str, Any] = redact_data(dict(event_dict))
    return redacted


def configure_logging(level: str = "INFO", *, json: bool = True) -> None:
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            redact_processor,
            structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level)),
        cache_logger_on_first_use=False,
    )
