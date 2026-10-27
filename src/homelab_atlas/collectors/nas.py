"""nas collector (UniFi UNAS), best effort (ADR-006).

Mode `drive_api`: three GET endpoints a Drive API key can read, per the community
description at github.com/LayerTM/unifi-unas-ha docs/API.md (UniFi OS 5.1.19 / Drive 4.3.6).
No official API exists, so the parser treats every field as optional.
Mode `manual`: `<config dir>/manual/<file>.yaml`, written by the owner.
"""

import time
from pathlib import Path
from typing import Any, Final

import yaml

from homelab_atlas.collectors.base import ApiSource, CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh.parse import norm_mac
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity
from homelab_atlas.inventory.hosts import Inventory, UnasSource
from homelab_atlas.models.nas import NasDisk, NasFacts, NasPool
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError

SYSTEM = Endpoint("unas.system", "GET", "/api/system")
STORAGE = Endpoint("unas.storage", "GET", "/proxy/drive/api/v2/storage")
DEVICE_INFO = Endpoint("unas.device_info", "GET", "/proxy/drive/api/v2/systems/device-info")
ENDPOINTS: Final = frozenset({SYSTEM, STORAGE, DEVICE_INFO})
MAX_MANUAL_BYTES: Final = 256 * 1024


def _s(v: Any, limit: int = 128) -> str | None:
    if isinstance(v, int | float) and not isinstance(v, bool):
        v = str(v)
    return v[:limit] if isinstance(v, str) and v else None


def _i(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) else None


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def from_drive(name: str, system: Any, storage: Any, info: Any) -> NasFacts:
    sysd, stor, inf = _d(system), _d(storage), _d(info)
    pools = [
        NasPool(
            id=str(p.get("id") or p.get("number")),
            status=_s(p.get("status"), 32),
            raid=_s(_d((_l(p.get("raidGroups")) or [{}])[0]).get("currentLevel"), 16),
            capacity_bytes=_i(p.get("capacity")),
            used_bytes=_i(p.get("usage")),
        )
        for p in _l(stor.get("pools"))
        if isinstance(p, dict) and (p.get("id") or p.get("number"))
    ]
    disks = [
        NasDisk(
            slot=str(d["slotId"]),
            model=_s(d.get("model")),
            serial=_s(d.get("serial"), 64),
            size_bytes=_i(d.get("size")),
            pool_id=_s(d.get("poolId"), 64),
            state=_s(d.get("state"), 32),
            health_score=_i(d.get("healthScore")),
            bad_sectors=_i(d.get("badSectorCount")),
            temperature_c=d.get("temperature")
            if isinstance(d.get("temperature"), int | float)
            else None,
            power_on_hours=_i(d.get("powerOnHours")),
        )
        for d in _l(stor.get("disks"))
        if isinstance(d, dict) and d.get("slotId") is not None
    ]
    return NasFacts(
        source="drive-api",
        name=_s(sysd.get("name")) or name,
        model=_s(inf.get("model")) or _s(_d(sysd.get("hardware")).get("shortname")),
        mac=norm_mac(sysd.get("mac")),
        firmware=_s(inf.get("firmwareVersion"), 32),
        drive_version=_s(inf.get("version"), 32),
        pools=pools,
        disks=disks,
    )


def from_manual(name: str, path: Path) -> NasFacts:
    if path.stat().st_size > MAX_MANUAL_BYTES:
        raise ValueError(f"{path.name}: too large")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError:
        raise ValueError(f"{path.name}: not valid YAML") from None
    if not isinstance(raw, dict):
        raise ValueError(f"{path.name}: must be a mapping")
    allowed = {"name", "model", "mac", "firmware", "pools", "disks", "shares"}
    if extra := set(raw) - allowed:
        raise ValueError(f"{path.name}: unknown keys {sorted(extra)}")
    return NasFacts.model_validate({"source": "manual", "name": name, **raw})


def nas_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p, k = c.path, c.kind
        if p[0] == "pools" and p[-1] == "status":
            sev: Severity = "info" if c.new == "fullyOperational" else "warning"
            ev("nas.pool_status", sev, f"pool {p[1]} {c.old} -> {c.new}", c)
        elif p[0] == "disks" and len(p) == 2:
            ev(f"nas.disk_{k}", "notice", f"disk in slot {p[1]} {k}", c)
        elif p[0] == "disks" and p[-1] == "state":
            sev = "info" if c.new == "optimal" else "warning"
            ev("nas.disk_state", sev, f"disk {p[1]} {c.old} -> {c.new}", c)
        elif p[0] == "disks" and p[-1] == "bad_sectors":
            if isinstance(c.new, int) and isinstance(c.old, int) and c.new > c.old:
                ev(
                    "nas.disk_bad_sectors",
                    "warning",
                    f"disk {p[1]} bad sectors {c.old} -> {c.new}",
                    c,
                )
        elif p[0] == "disks" and p[-1] == "health_score":
            ev(
                "nas.disk_health",
                "warning" if (c.new or 0) < 5 else "info",
                f"disk {p[1]} health score {c.old} -> {c.new}",
                c,
            )
        elif p[0] == "disks" and p[-1] in ("serial", "model"):
            ev("nas.disk_replaced", "notice", f"disk {p[1]} {p[-1]} {c.old} -> {c.new}", c)
        elif p in (("firmware",), ("drive_version",)):
            ev("nas.upgraded", "notice", f"{p[0]} {c.old} -> {c.new}", c)
        elif p[0] == "shares" and len(p) == 2:
            ev(f"nas.share_{k}", "notice", f"share {p[1]} {k}", c)
        elif p[0] == "pools" and len(p) == 2:
            ev(f"nas.pool_{k}", "notice", f"pool {p[1]} {k}", c)
    return out


class NasCollector:
    name = "nas"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints = ENDPOINTS

    def targets(self, inventory: Inventory) -> list[str]:
        return [s.name for s in inventory.sources.unas]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return nas_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        src: UnasSource = next(s for s in ctx.inventory.sources.unas if s.name == target)
        result = CollectorResult(self.name, target, "failed")
        try:
            facts = await (
                self._drive(src, ctx, result) if src.drive_api else self._manual(src, ctx)
            )
        except SecurityRefusal as exc:
            result.status, result.errors = "refused", [f"refused: {exc.reason.value}: {exc.detail}"]
            facts = None
        except (TransportError, HttpStatusError, OSError, ValueError) as exc:
            result.errors.append(f"unreachable: {exc}" if src.drive_api else f"manual: {exc}")
            facts = None
        if facts is not None:
            key = f"nas:{facts.mac}" if facts.mac else f"nas:name:{target}"
            result.facets = [FacetResult(key, "nas", facts.name, facts)]
            result.complete = True
            result.status = "partial" if result.errors else "ok"
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result

    async def _drive(
        self, src: UnasSource, ctx: CollectContext, result: CollectorResult
    ) -> NasFacts:
        if ctx.http is None or src.url is None or src.credential is None:
            raise ValueError("drive_api needs url, credential and an HTTP factory")
        api = ApiSource(src.name, src.url, src.credential, src.tls, "x-api-key")
        async with ctx.http(api, self.endpoints) as client:
            system = (await client.get(SYSTEM)).json()
            parts: list[Any] = []
            for endpoint in (STORAGE, DEVICE_INFO):
                try:
                    parts.append((await client.get(endpoint)).json())
                except HttpStatusError as exc:
                    result.errors.append(f"{endpoint.id}: HTTP {exc.status}")
                    parts.append(None)
        return from_drive(src.name, system, parts[0], parts[1])

    async def _manual(self, src: UnasSource, ctx: CollectContext) -> NasFacts:
        if ctx.config_dir is None or src.manual is None:
            raise ValueError("manual mode needs a config dir and a file name")
        return from_manual(src.name, ctx.config_dir / "manual" / src.manual)
