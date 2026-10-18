"""Collector plugin contract (SPEC §6)."""

from dataclasses import dataclass, field
from typing import Literal, Protocol

from pydantic import BaseModel

from homelab_atlas.inventory.hosts import HostEntry, Inventory
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.ssh import SshRunner

RunStatus = Literal["ok", "partial", "failed", "refused"]


@dataclass(slots=True)
class CollectorResult:
    collector: str
    target: str
    status: RunStatus
    kind: str
    entity_key: str | None = None
    display_name: str = ""
    model: BaseModel | None = None
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0


@dataclass(frozen=True, slots=True)
class CollectContext:
    inventory: Inventory
    ssh: SshRunner


class Collector(Protocol):
    name: str
    kind: str
    #: Probe sections this collector may run; enforced by SshRunner via SshTarget.sections
    #: and used by `atlas targets render` / `atlas doctor`.
    requires: frozenset[ProbeSection]

    async def collect(self, host: HostEntry, ctx: CollectContext) -> CollectorResult: ...
