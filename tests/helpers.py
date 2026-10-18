"""Shared test helpers (importable as `tests.helpers`)."""

from pathlib import Path
from typing import TYPE_CHECKING

from homelab_atlas.security.audit import AuditEvent

if TYPE_CHECKING:
    from homelab_atlas.runtime import Runtime


class MemoryAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    @property
    def outcomes(self) -> list[str]:
        return [e.outcome for e in self.events]


def scanned_lab(data_dir: Path) -> "Runtime":
    """A runtime whose DB holds demo-lab scans A then B (replayed, no network)."""
    import asyncio  # noqa: PLC0415

    from homelab_atlas.lab import load_api_recordings, load_lab  # noqa: PLC0415
    from homelab_atlas.runtime import Inputs, Runtime, replay_http  # noqa: PLC0415

    lab = Path(__file__).resolve().parents[1] / "fixtures" / "demo-lab"
    rt = Runtime.open(data_dir, mode="demo")
    for state in ("A", "B"):
        inv, ssh = load_lab(state, lab)
        engine = rt.scan_engine(Inputs(inv, ssh, replay_http(load_api_recordings(state, lab)), lab))
        asyncio.run(engine.run())
    return rt
