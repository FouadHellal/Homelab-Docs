"""Collector plugin contract (SPEC §6)."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol

from pydantic import BaseModel

from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory, TlsSettings
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.http import ReadOnlyHttpClient
from homelab_atlas.security.ssh import SshRunner

RunStatus = Literal["ok", "partial", "failed", "refused"]
AuthScheme = Literal["pve-token", "x-api-key"]


@dataclass(slots=True)
class FacetResult:
    """One entity reported by a collector run.

    `model=None` registers the entity (e.g. a container, for annotations and search) without
    its own snapshot: its changes are diffed as part of the parent facet.
    """

    entity_key: str
    kind: str
    display_name: str
    model: BaseModel | None = None
    parent_key: str | None = None


@dataclass(slots=True)
class CollectorResult:
    collector: str
    target: str
    status: RunStatus
    facets: list[FacetResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_ms: int = 0
    #: True when `facets` is the complete set for this target, so anything previously
    #: reported and now absent is gone (a deleted VM, a removed container).
    complete: bool = False

    @property
    def primary_key(self) -> str | None:
        return self.facets[0].entity_key if self.facets else None


@dataclass(frozen=True, slots=True)
class ApiSource:
    name: str
    url: str
    credential: str
    tls: TlsSettings
    auth: AuthScheme


class HttpFactory(Protocol):
    """Build a read-only client for an API source (live: TLS + secrets; demo: replay)."""

    def __call__(self, source: ApiSource, endpoints: Iterable[Endpoint]) -> ReadOnlyHttpClient: ...


@dataclass(frozen=True, slots=True)
class CollectContext:
    inventory: Inventory
    ssh: SshRunner
    http: HttpFactory | None = None
    #: Directory holding owner files referenced by config (manual/*.yaml, CA anchors).
    config_dir: Path | None = None


class Collector(Protocol):
    name: str
    #: Probe sections (SSH collectors) or endpoints (API collectors) this collector may use.
    #: Enforced by the transports; also drives `atlas targets render` and `atlas doctor`.
    requires: frozenset[ProbeSection]
    endpoints: frozenset[Endpoint]

    def targets(self, inventory: Inventory) -> list[str]: ...

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult: ...

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]: ...
