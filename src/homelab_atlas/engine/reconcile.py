"""Post-scan reconciliation (SPEC §7): correlation and unknown-device detection.

* same_as: an SSH-scanned Linux host is the same machine as a Proxmox guest (shared NIC MAC)
  or a Proxmox node (shared IP). Topology then reads node > VM (= host) > containers.
* unknown devices: MACs seen by UniFi (clients) or in ARP/NDP tables of probed hosts that no
  inventory entry, collector facet or hosts.yaml `match.mac` / address accounts for.
* missing: inventory hosts whose last MISSING_AFTER runs all failed.
Passive only (ADR-016): nothing here sends a packet.
"""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas.engine.events import EventSpec
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.store.tables import CollectorRun, Entity, Facet, utcnow

MISSING_AFTER: Final = 3
RECONCILE = "reconcile"


@dataclass(slots=True)
class Index:
    mac_owner: dict[str, str] = field(default_factory=dict)  # mac -> entity key
    ips: set[str] = field(default_factory=set)
    networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, int | None]] = field(
        default_factory=list
    )
    names: dict[str, str] = field(default_factory=dict)  # entity key -> display name


def _ip(text: Any) -> str | None:
    if not isinstance(text, str) or not text:
        return None
    try:
        return ipaddress.ip_interface(text).ip.compressed
    except ValueError:
        return None


def _claim(idx: Index, macs: Iterable[Any], key: str) -> None:
    for mac in macs:
        if isinstance(mac, str) and mac:
            idx.mac_owner.setdefault(mac, key)


def build_index(facets: list[Facet], inventory: Inventory, names: dict[str, str]) -> Index:
    idx = Index(names=names)
    by_collector: dict[str, list[Facet]] = {}
    for f in facets:
        by_collector.setdefault(f.collector, []).append(f)
    # Identity owners first (devices with their own MAC), then hosts, then guests.
    for f in by_collector.get("unifi", []):
        if (mac := f.data.get("mac")) is not None:
            _claim(idx, [mac], f.entity_key)
            if ip := _ip(f.data.get("ip")):
                idx.ips.add(ip)
        for n in f.data.get("networks") or []:
            if n.get("subnet"):
                net = ipaddress.ip_network(n["subnet"], strict=False)
                idx.networks.append((net, str(n.get("name")), n.get("vlan_id")))
    for f in by_collector.get("nas", []):
        _claim(idx, [f.data.get("mac")], f.entity_key)
    for f in by_collector.get("linux-ssh", []):
        for iface in f.data.get("interfaces") or []:
            _claim(idx, [iface.get("mac")], f.entity_key)
            idx.ips.update(
                ip for a in iface.get("addresses") or [] if (ip := _ip(a.get("address")))
            )
    for f in by_collector.get("proxmox", []):
        _claim(idx, [n.get("mac") for n in f.data.get("nics") or []], f.entity_key)
        idx.ips.update(ip for a in f.data.get("ips") or [] if (ip := _ip(a.get("address"))))
        if ip := _ip(f.data.get("ip")):
            idx.ips.add(ip)
    for h in inventory.hosts:
        if ip := _ip(h.address):
            idx.ips.add(ip)
        if h.match.mac:
            idx.mac_owner.setdefault(h.match.mac, f"inventory:{h.name}")
    return idx


def _network_of(idx: Index, ip: str | None) -> tuple[str | None, int | None]:
    if ip is None:
        return None, None
    addr = ipaddress.ip_address(ip)
    for net, name, vlan in idx.networks:
        if addr.version == net.version and addr in net:
            return name, vlan
    return None, None


def _correlate(s: Session, facets: list[Facet], idx: Index) -> None:
    guests = {f.entity_key: f for f in facets if f.collector == "proxmox" and "vmid" in f.data}
    nodes = [f for f in facets if f.collector == "proxmox" and "pve_version" in f.data]
    mac_to_guest = {
        n.get("mac"): k for k, f in guests.items() for n in f.data.get("nics") or [] if n.get("mac")
    }
    for f in facets:
        if f.collector != "linux-ssh":
            continue
        macs = [i.get("mac") for i in f.data.get("interfaces") or []]
        ips = {
            ip
            for i in f.data.get("interfaces") or []
            for a in i.get("addresses") or []
            if (ip := _ip(a.get("address")))
        }
        match = next((mac_to_guest[m] for m in macs if m in mac_to_guest), None)
        if match is None:
            match = next((n.entity_key for n in nodes if _ip(n.data.get("ip")) in ips), None)
        entity = s.get(Entity, f.entity_key)
        if entity is not None and entity.same_as != match:
            entity.same_as = match


def _candidates(facets: list[Facet]) -> dict[str, dict[str, Any]]:
    """mac -> observation (UniFi clients win over ARP: they carry names and uplinks)."""
    seen: dict[str, dict[str, Any]] = {}
    for f in facets:
        if f.collector == "linux-ssh":
            for n in f.data.get("neighbors") or []:
                if n.get("mac"):
                    seen.setdefault(
                        n["mac"],
                        {
                            "mac": n["mac"],
                            "ip": _ip(n.get("ip")),
                            "name": None,
                            "uplink_mac": None,
                            "seen_via": f"arp@{f.target}",
                        },
                    )
    for f in facets:
        if f.collector == "unifi":
            for c in f.data.get("clients") or []:
                if c.get("mac"):
                    seen[c["mac"]] = {
                        "mac": c["mac"],
                        "ip": _ip(c.get("ip")),
                        "name": c.get("name"),
                        "uplink_mac": c.get("uplink_mac"),
                        "seen_via": f"unifi@{f.target}",
                    }
    return seen


def reconcile(s: Session, scan_id: int, inventory: Inventory) -> list[EventSpec]:
    facets = list(s.scalars(select(Facet).where(Facet.collector != RECONCILE)))
    names = {e.key: e.display_name for e in s.scalars(select(Entity))}
    idx = build_index(facets, inventory, names)
    _correlate(s, facets, idx)
    events: list[EventSpec] = []
    now = utcnow()
    for mac, obs in sorted(_candidates(facets).items()):
        key = f"net:mac:{mac}"
        known = mac in idx.mac_owner or (obs["ip"] is not None and obs["ip"] in idx.ips)
        entity = s.get(Entity, key)
        if known:
            if entity is not None and entity.status == "unknown":
                entity.status = "identified"
                events.append(
                    EventSpec(
                        key,
                        "device.identified",
                        "info",
                        f"{entity.display_name}: now matches the inventory",
                    )
                )
            continue
        net, vlan = _network_of(idx, obs["ip"])
        uplink = idx.names.get(f"unifi:dev:{obs['uplink_mac']}") if obs["uplink_mac"] else None
        data = {**obs, "network": net, "vlan": vlan, "uplink": uplink}
        label = obs["name"] or mac
        if entity is None:
            s.add(
                Entity(
                    key=key,
                    kind="unknown-device",
                    display_name=label,
                    first_seen=now,
                    last_seen=now,
                    status="unknown",
                    last_scan_id=scan_id,
                )
            )
            s.add(
                Facet(
                    entity_key=key,
                    collector=RECONCILE,
                    target="network",
                    scan_id=scan_id,
                    data=data,
                )
            )
            where = f" on {net} (VLAN {vlan})" if net else ""
            via = f" via {uplink}" if uplink else f" ({obs['seen_via']})"
            events.append(
                EventSpec(
                    key,
                    "device.unknown_seen",
                    "notice",
                    f"{label}: new unknown device {mac} {obs['ip'] or ''}{where}{via}".replace(
                        "  ", " "
                    ),
                )
            )
        elif entity.status in ("unknown", "identified"):
            entity.last_seen, entity.last_scan_id, entity.status = now, scan_id, "unknown"
            facet = s.get(Facet, (key, RECONCILE))
            if facet is not None:
                facet.data, facet.scan_id = data, scan_id
    _missing(s, inventory)
    s.flush()
    return events


def _missing(s: Session, inventory: Inventory) -> None:
    for host in inventory.hosts:
        runs = list(
            s.scalars(
                select(CollectorRun)
                .where(CollectorRun.target == host.name)
                .order_by(CollectorRun.scan_id.desc())
                .limit(MISSING_AFTER)
            )
        )
        key = next((r.entity_key for r in runs if r.entity_key), None)
        entity = s.get(Entity, key) if key else None
        if entity is None:
            continue
        down = len(runs) == MISSING_AFTER and all(r.status in ("failed", "refused") for r in runs)
        if down and entity.status == "known":
            entity.status = "missing"
        elif not down and entity.status == "missing":
            entity.status = "known"
