"""unifi collector: local Network Integration API, X-API-KEY, GET-only (ADR-005)."""

import asyncio
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

from homelab_atlas.collectors.base import ApiSource, CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh.parse import norm_mac
from homelab_atlas.collectors.unifi import endpoints as ep
from homelab_atlas.collectors.unifi import parse
from homelab_atlas.collectors.unifi.events import unifi_events
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.unifi import UnifiSiteFacts
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError
from homelab_atlas.security.http import ReadOnlyHttpClient

T = TypeVar("T")
DETAIL_CONCURRENCY = 4


class UnifiCollector:
    name = "unifi"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints = ep.COLLECT

    def targets(self, inventory: Inventory) -> list[str]:
        return [s.name for s in inventory.sources.unifi]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return unifi_events(key, name, changes)

    @staticmethod
    def source(inventory: Inventory, name: str) -> ApiSource:
        src = next(s for s in inventory.sources.unifi if s.name == name)
        return ApiSource(src.name, src.url, src.credential, src.tls, "x-api-key")

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        result = CollectorResult(self.name, target, "failed")
        if ctx.http is None:
            result.errors = ["no HTTP factory configured"]
            return result
        try:
            client = ctx.http(self.source(ctx.inventory, target), self.endpoints)
            async with client:
                await _Run(client, result, target).collect()
        except SecurityRefusal as exc:
            result.status, result.facets = "refused", []
            result.errors.append(f"refused: {exc.reason.value}: {exc.detail}")
        except (TransportError, HttpStatusError, ValueError) as exc:
            result.status, result.facets = "failed", []
            result.errors.append(f"unreachable: {exc}")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result


class _Run:
    def __init__(self, client: ReadOnlyHttpClient, result: CollectorResult, source: str) -> None:
        self.c, self.r, self.source = client, result, source
        self.sem = asyncio.Semaphore(DETAIL_CONCURRENCY)

    async def pages(
        self, endpoint: Endpoint, vars_: Mapping[str, str] | None = None
    ) -> list[dict[str, Any]]:
        """Follow offset/limit pagination ({offset, limit, count, totalCount, data})."""
        items: list[dict[str, Any]] = []
        offset = 0
        for _ in range(ep.MAX_PAGES):
            body = (
                await self.c.get(endpoint, vars_, {"offset": offset, "limit": ep.PAGE_LIMIT})
            ).json()
            data = body.get("data") if isinstance(body, dict) else None
            if not isinstance(data, list) or not data:
                break
            items += [d for d in data if isinstance(d, dict)]
            offset += len(data)
            total = body.get("totalCount")
            if not isinstance(total, int) or offset >= total:
                break
        return items

    async def soft(self, label: str, call: Awaitable[Any]) -> Any:
        """A non-fatal call: failures become run errors and return None."""
        try:
            async with self.sem:
                return await call
        except HttpStatusError as exc:
            self.r.errors.append(f"{label}: HTTP {exc.status}")
        except (TransportError, SecurityRefusal) as exc:
            self.r.errors.append(f"{label}: {type(exc).__name__}")
        except ValueError:
            self.r.errors.append(f"{label}: invalid JSON")
        return None

    async def collect(self) -> None:
        info = (await self.c.get(ep.INFO)).json()
        version = parse._s(info.get("applicationVersion") if isinstance(info, dict) else None, 32)
        if parse.version_tuple(version) < ep.MIN_VERSION:
            self.r.errors.append(f"Network {version}: Integration API needs >= 9.3")
        sites = await self.pages(ep.SITES)
        for site in sites:
            sid = parse._s(site.get("id"), 64)
            if sid is not None:
                await self.site(sid, site, version)
        self.r.complete = bool(sites)
        self.r.status = "partial" if self.r.errors else "ok"

    async def site(self, sid: str, site: dict[str, Any], version: str | None) -> None:
        sv = {"site_id": sid}
        devices = await self.pages(ep.DEVICES, sv)  # fatal: drives completeness
        mac_by_id = {str(d.get("id")): m for d in devices if (m := norm_mac(d.get("macAddress")))}

        async def details(endpoint: Endpoint, var: str, obj_id: str) -> Any:
            body = (await self.c.get(endpoint, {**sv, var: obj_id})).json()
            return body if isinstance(body, dict) else None

        dev_details = await asyncio.gather(
            *(
                self.soft(
                    f"device {d.get('name')}", details(ep.DEVICE, "device_id", str(d.get("id")))
                )
                for d in devices
            )
        )
        clients, networks, wifi, zones, policies, acl, wans = await asyncio.gather(
            self.soft("clients", self.pages(ep.CLIENTS, sv)),
            self.soft("networks", self.pages(ep.NETWORKS, sv)),
            self.soft("wifi", self.pages(ep.WIFI, sv)),
            self.soft("firewall zones", self.pages(ep.ZONES, sv)),
            self.soft("firewall policies", self.pages(ep.POLICIES, sv)),
            self.soft("acl rules", self.pages(ep.ACL_RULES, sv)),
            self.soft("wans", self.pages(ep.WANS, sv)),
        )
        net_details = await asyncio.gather(
            *(
                self.soft(
                    f"network {n.get('name')}", details(ep.NETWORK, "network_id", str(n.get("id")))
                )
                for n in networks or []
            )
        )

        def keep(items: Any, fn: Callable[[dict[str, Any]], T | None]) -> list[T]:
            return [x for i in items or [] if (x := fn(i)) is not None]

        ref = parse._s(site.get("internalReference"), 64) or sid
        facts = UnifiSiteFacts(
            name=parse._s(site.get("name"), 128) or ref,
            reference=ref,
            app_version=version,
            networks=[
                x
                for n, d in zip(networks or [], net_details, strict=True)
                if (x := parse.network(n, d)) is not None
            ],
            ssids=keep(wifi, parse.ssid),
            zones=keep(zones, parse.zone),
            policies=keep(policies, parse.policy),
            acl_rules=keep(acl, parse.acl_rule),
            wans=keep(wans, parse.wan),
            clients=keep(clients, lambda c: parse.client(c, mac_by_id)),
        )
        skey = f"unifi:site:{self.source}/{ref}"
        self.r.facets.append(FacetResult(skey, "unifi-site", f"{facts.name} (UniFi site)", facts))
        for overview, det in zip(devices, dev_details, strict=True):
            dev = parse.device(overview, det, mac_by_id)
            if dev is None:
                continue
            parent = f"unifi:dev:{dev.uplink_mac}" if dev.uplink_mac else skey
            self.r.facets.append(
                FacetResult(f"unifi:dev:{dev.mac}", "unifi-device", dev.name, dev, parent)
            )
