"""ScanEngine robustness: one bad target or a shared fact must not sink the whole scan."""

import asyncio
from pathlib import Path

from sqlalchemy import select

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.engine.reconcile import build_index
from homelab_atlas.engine.scan import ScanEngine
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.proxmox import PveNodeFacts
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.ssh import ReplayTransport, SshRunner
from homelab_atlas.store.facets import PVE_SSH_PEER, FacetView
from homelab_atlas.store.tables import CollectorRun, Facet, Scan
from tests.helpers import MemoryAudit

PEER = "pve:node:cl/pve3"


class FakeCollector:
    """Targets a, b both report pve3 as a cluster peer; c crashes; d is refused."""

    name = "linux-ssh"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints: frozenset[Endpoint] = frozenset()

    def targets(self, inventory: Inventory) -> list[str]:
        return ["a", "b", "c", "d"]

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        if target == "c":
            raise ValueError("unexpected payload")
        if target == "d":
            raise SecurityRefusal(RefusalReason.NOT_ALLOWLISTED, "not enabled")
        own = FacetResult(
            f"host:{target}", "linux-host", target, PveNodeFacts(name=target, online=True)
        )
        peer = FacetResult(
            PEER, "pve-node", "pve3 (PVE node)", PveNodeFacts(name="pve3", online=True),
            store_as=PVE_SSH_PEER,
        )  # fmt: skip
        return CollectorResult(self.name, target, "ok", facets=[own, peer], complete=True)

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return []


def _engine(rt: Runtime, tmp_path: Path) -> ScanEngine:
    return ScanEngine(
        sessions=rt.sessions,
        ctx=CollectContext(
            inventory=Inventory(version=1),
            ssh=SshRunner(transport=ReplayTransport({}), audit=MemoryAudit()),
        ),
        collectors=[FakeCollector()],
        redactor=rt.redactor,
        lock_path=tmp_path / "scan.lock",
        mode="demo",
    )


def test_shared_peer_fact_and_crashing_collector_do_not_abort_the_scan(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path / "data", mode="demo")
    engine = _engine(rt, tmp_path)
    for _ in range(2):  # the second scan diffs against the first
        summary = asyncio.run(engine.run())
        assert {(r.target, r.status) for r in summary.runs} == {
            ("a", "ok"),
            ("b", "ok"),
            ("c", "failed"),
            ("d", "refused"),
        }
    crashed = next(r for r in summary.runs if r.target == "c")
    assert crashed.errors == ["crashed: ValueError"]
    with rt.sessions() as s:
        assert all(sc.status == "done" for sc in s.scalars(select(Scan)))
        assert len(s.scalars(select(CollectorRun)).all()) == 8
        assert s.get(Facet, (PEER, PVE_SSH_PEER)) is not None


def test_index_explains_api_only_pve_node_ips() -> None:
    node = FacetView(
        entity_key="pve:node:cl/pve3",
        collector="proxmox",
        target="homelab",
        scan_id=1,
        data={"name": "pve3", "online": True, "ip": "10.0.10.13"},
        source="proxmox",
    )
    guest = FacetView(
        entity_key="pve:vm:cl/101",
        collector="proxmox",
        target="homelab",
        scan_id=1,
        data={"vmid": 101, "ips": [{"address": "10.0.20.11/24"}], "nics": []},
        source="proxmox",
    )
    idx = build_index([node, guest], None, {})
    assert {"10.0.10.13", "10.0.20.11"} <= idx.ips
