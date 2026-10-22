"""Structured logging with redaction as the last processor before rendering (ADR-009)."""

import logging
import sys
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


class _Stderr:
    """Whatever sys.stderr is at write time (tests and tools swap it after configuration)."""

    def write(self, text: str) -> int:
        return sys.stderr.write(text)

    def flush(self) -> None:
        sys.stderr.flush()


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
        # stderr, never stdout: `atlas mcp` speaks the MCP protocol on stdout (ADR-036).
        logger_factory=structlog.PrintLoggerFactory(file=_Stderr()),  # type: ignore[arg-type]
        cache_logger_on_first_use=False,
    )
