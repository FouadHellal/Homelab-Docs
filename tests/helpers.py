"""Shared test helpers (importable as `tests.helpers`)."""

from homelab_atlas.security.audit import AuditEvent


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    @property
    def outcomes(self) -> list[str]:
        return [e.outcome for e in self.events]
