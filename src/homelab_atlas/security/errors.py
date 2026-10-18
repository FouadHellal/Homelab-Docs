"""Security-layer exceptions.

`SecurityRefusal` means a guard said no. It is never retried and is always audited.
Messages must never include secret values or raw target output.
"""

from enum import StrEnum


class RefusalReason(StrEnum):
    NOT_ALLOWLISTED = "not_allowlisted"
    BAD_TYPE = "bad_type"
    METHOD_FORBIDDEN = "method_forbidden"
    PATH_INVALID = "path_invalid"
    PATH_DENIED = "path_denied"
    QUERY_INVALID = "query_invalid"
    BODY_INVALID = "body_invalid"
    REDIRECT = "redirect"
    TLS_POLICY = "tls_policy"
    TLS_PIN_MISMATCH = "tls_pin_mismatch"
    HOST_KEY = "host_key"
    CLIENT_KEY = "client_key"
    OUTPUT_TOO_LARGE = "output_too_large"
    SECRET_NAME = "secret_name"
    SECRET_PERMISSIONS = "secret_permissions"
    CONFIG = "config"


class SecurityRefusal(Exception):
    """A security guard refused an operation."""

    def __init__(self, reason: RefusalReason, detail: str) -> None:
        super().__init__(f"{reason.value}: {detail}")
        self.reason = reason
        self.detail = detail


class TransportError(Exception):
    """The target could not be reached or the transport failed (retryable)."""


class TargetTimeout(TransportError):
    """Connect, handshake or command exceeded its time budget."""


class HttpStatusError(TransportError):
    """Non-2xx response. Carries the status only, never the body."""

    def __init__(self, status: int, op: str) -> None:
        super().__init__(f"HTTP {status} for {op}")
        self.status = status
        self.op = op


class SecretError(Exception):
    """A secret could not be resolved. Never contains the value."""
