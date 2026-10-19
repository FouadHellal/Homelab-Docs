"""proxmox collector: read-only PVE API token (PVEAuditor, privsep), GET endpoints only."""

import asyncio
import time
from collections.abc import Mapping
from typing import Any

from homelab_atlas.collectors.base import (
    ApiSource,
    CollectContext,
    CollectorResult,
    FacetResult,
)
from homelab_atlas.collectors.proxmox import endpoints as ep
from homelab_atlas.collectors.proxmox import parse
from homelab_atlas.collectors.proxmox.events import proxmox_events
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.proxmox import PveClusterFacts, PveGuestFacts, PveNodeFacts, Storage
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import (
    HttpStatusError,
    SecurityRefusal,
    TransportError,
)
from homelab_atlas.security.http import ReadOnlyHttpClient

PER_GUEST_CONCURRENCY = 4
NO_VISIBILITY = (
    "the token works but sees no nodes or guests: give the TOKEN itself the PVEAuditor role "
    "on / (Datacenter > Permissions > Add > API Token Permission), or untick privilege "
    "separation"
)


class ProxmoxCollector:
    name = "proxmox"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints = ep.COLLECT

    def targets(self, inventory: Inventory) -> list[str]:
        return [s.name for s in inventory.sources.proxmox]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return proxmox_events(key, name, changes)

    @staticmethod
    def source(inventory: Inventory, name: str) -> ApiSource:
        src = next(s for s in inventory.sources.proxmox if s.name == name)
        return ApiSource(src.name, src.url, src.credential, src.tls, "pve-token")

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        result = CollectorResult(self.name, target, "failed")
        if ctx.http is None:
            result.errors = ["no HTTP factory configured"]
            return result
        try:
            client = ctx.http(self.source(ctx.inventory, target), self.endpoints)
        except SecurityRefusal as exc:
            result.status, result.errors = "refused", [f"refused: {exc.reason.value}: {exc.detail}"]
            return result
        try:
            async with client:
                await _Run(client, result).collect()
        except SecurityRefusal as exc:
            result.status, result.facets = "refused", []
            result.errors.append(f"refused: {exc.reason.value}: {exc.detail}")
        except (TransportError, HttpStatusError) as exc:
            result.status, result.facets = "failed", []
            result.errors.append(f"unreachable: {exc}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result


class _Run:
    """One collection pass. Fatal: the first call fails. Everything else degrades."""

    def __init__(self, client: ReadOnlyHttpClient, result: CollectorResult) -> None:
        self.c = client
        self.r = result
        self.sem = asyncio.Semaphore(PER_GUEST_CONCURRENCY)

    async def get(self, endpoint: Endpoint, vars_: Mapping[str, str] | None = None) -> Any:
        return (await self.c.get(endpoint, vars_)).json()

    async def soft(
        self, label: str, endpoint: Endpoint, vars_: Mapping[str, str] | None = None
    ) -> Any:
        """A non-fatal call: failures become run errors (or guest notes) and return None."""
        try:
            async with self.sem:
                return await self.get(endpoint, vars_)
        except HttpStatusError as exc:
            self.r.errors.append(f"{label}: HTTP {exc.status}")
        except (TransportError, SecurityRefusal) as exc:
            self.r.errors.append(f"{label}: {type(exc).__name__}")
        except ValueError:
            self.r.errors.append(f"{label}: invalid JSON")
        return None

    async def collect(self) -> None:
        version = parse.data(await self.get(ep.VERSION)) or {}
        status = parse.data(await self.get(ep.CLUSTER_STATUS)) or []
        resources = parse.data(await self.get(ep.RESOURCES)) or []
        cluster_row = next(
            (x for x in status if isinstance(x, dict) and x.get("type") == "cluster"), None
        )
        node_rows = {x["name"]: x for x in status if isinstance(x, dict) and x.get("type") == "node"
                     and isinstance(x.get("name"), str)}  # fmt: skip
        standalone = cluster_row is None
        cname = str(cluster_row["name"]) if cluster_row else next(iter(node_rows), self.r.target)
        ckey = f"pve:cluster:{cname}"

        jobs_p, nbu_p, ha_p = await asyncio.gather(
            self.soft("backup jobs", ep.BACKUP_JOBS),
            self.soft("not-backed-up", ep.NOT_BACKED_UP),
            self.soft("ha resources", ep.HA_RESOURCES),
        )
        not_backed = parse.not_backed_up(nbu_p) if nbu_p is not None else []
        ha = parse.ha_resources(ha_p) if ha_p is not None else []
        cluster = PveClusterFacts(
            name=cname,
            standalone=standalone,
            quorate=bool(cluster_row.get("quorate")) if cluster_row else None,
            version=parse._s(version.get("version"), 32) if isinstance(version, dict) else None,
            node_names=sorted(node_rows),
            backup_jobs=parse.backup_jobs(jobs_p) if jobs_p is not None else [],
            not_backed_up=not_backed,
            ha_resources=ha,
        )
        self.r.facets.append(FacetResult(ckey, "pve-cluster", f"{cname} (PVE cluster)", cluster))

        rows = [x for x in resources if isinstance(x, dict)]
        storages: dict[str, list[Storage]] = {}
        for row in rows:
            is_storage = row.get("type") == "storage" and isinstance(row.get("node"), str)
            if is_storage and (st := parse.storage(row)) is not None:
                storages.setdefault(row["node"], []).append(st)

        nodes = await asyncio.gather(
            *(
                self.node(name, row, storages.get(name, []))
                for name, row in sorted(node_rows.items())
            )
        )
        for node in nodes:
            self.r.facets.append(
                FacetResult(
                    f"pve:node:{cname}/{node.name}",
                    "pve-node",
                    f"{node.name} (PVE node)",
                    node,
                    ckey,
                )
            )

        ha_state = {h.sid: h.state for h in ha}
        guest_rows = [
            x for x in rows if x.get("type") in ("qemu", "lxc") and isinstance(x.get("vmid"), int)
        ]
        guests = await asyncio.gather(
            *(self.guest(g, not_backed, ha_state, nbu_p is not None) for g in guest_rows)
        )
        for g in sorted(guests, key=lambda g: g.vmid):
            kind = "vm" if g.type == "qemu" else "lxc"
            self.r.facets.append(
                FacetResult(
                    f"pve:{kind}:{cname}/{g.vmid}",
                    f"pve-{kind}",
                    f"{g.name} ({kind.upper()} {g.vmid})",
                    g,
                    f"pve:node:{cname}/{g.node}",
                )
            )
        if not node_rows and not guest_rows:
            # The API answered, but the token sees nothing: the classic privilege-separation
            # mistake (the role was given to the user, not to the token).
            self.r.errors.append(NO_VISIBILITY)
        self.r.complete = bool(node_rows)  # never "remove" guests on an empty answer
        self.r.status = "partial" if self.r.errors else "ok"

    async def node(self, name: str, row: dict[str, Any], storages: list[Storage]) -> PveNodeFacts:
        online = bool(row.get("online"))
        st, net = (None, None)
        if online:
            st, net = await asyncio.gather(
                self.soft(f"{name} status", ep.NODE_STATUS, {"node": name}),
                self.soft(f"{name} network", ep.NODE_NETWORK, {"node": name}),
            )
        return PveNodeFacts(
            name=name,
            online=online,
            ip=parse._s(row.get("ip"), 64),
            interfaces=parse.node_interfaces(net) if net is not None else [],
            storages=storages,
            **parse.node_status(st),
        )

    async def guest(
        self,
        row: dict[str, Any],
        not_backed: list[str],
        ha_state: dict[str, str | None],
        have_backup_info: bool,
    ) -> PveGuestFacts:
        kind = str(row["type"])
        vmid, node = row["vmid"], str(row.get("node") or "")
        label = f"{kind} {vmid}"
        vars_ = {"node": node, "vmid": str(vmid)}
        cfg_ep = ep.QEMU_CONFIG if kind == "qemu" else ep.LXC_CONFIG
        cfg_p = await self.soft(f"{label} config", cfg_ep, vars_)
        cfg = parse.guest_config(kind, parse.data(cfg_p))
        running = row.get("status") == "running"
        notes: list[str] = []
        ips, os_name = [], None
        if running and kind == "qemu" and cfg.get("agent_enabled"):
            try:
                async with self.sem:
                    ips = parse.agent_ips(await self.get(ep.QEMU_AGENT_IFACES, vars_))
                    os_name = parse.agent_os(await self.get(ep.QEMU_AGENT_OSINFO, vars_))
            except HttpStatusError as exc:
                notes.append(f"guest agent not answering (HTTP {exc.status})")
            except (TransportError, SecurityRefusal, ValueError) as exc:
                notes.append(f"guest agent: {type(exc).__name__}")
        elif running and kind == "lxc":
            ifaces = await self.soft(f"{label} interfaces", ep.LXC_INTERFACES, vars_)
            ips = parse.lxc_ips(ifaces) if ifaces is not None else []
        sid = f"vm:{vmid}" if kind == "qemu" else f"ct:{vmid}"
        return PveGuestFacts(
            vmid=vmid,
            type="qemu" if kind == "qemu" else "lxc",
            name=parse._s(row.get("name"), 128) or f"{kind}-{vmid}",
            node=node,
            status=parse._s(row.get("status"), 16) or "unknown",
            template=parse._b(row.get("template")),
            ha_state=ha_state.get(sid),
            backed_up=(f"{kind}/{vmid}" not in not_backed) if have_backup_info else None,
            agent_os=os_name,
            ips=ips,
            notes=notes,
            cpu_load=row.get("cpu") if isinstance(row.get("cpu"), float) else None,
            uptime_s=parse._i(row.get("uptime")),
            **cfg,
        )
