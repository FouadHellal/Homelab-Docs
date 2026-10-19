"""Read models for the UI (and later MCP/exports). Plain dicts; templates escape everything."""

import ipaddress
from dataclasses import dataclass
from typing import Any, Final

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from homelab_atlas.engine.reconcile import RECONCILE, Index, build_index, network_of
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.store.tables import Annotation, CollectorRun, Entity, Event, Facet, Scan

HIDDEN_KINDS: Final = frozenset({"unknown-device", "container", "compose-project"})
SEVERITY_ORDER: Final = {"warning": 0, "notice": 1, "info": 2}


def _ip_key(ip: str) -> tuple[int, int]:
    try:
        a = ipaddress.ip_address(ip.split("/", maxsplit=1)[0])
        return a.version, int(a)
    except ValueError:
        return 9, 0


@dataclass(slots=True)
class Ctx:
    facets: list[Facet]
    names: dict[str, str]
    entities: dict[str, Entity]
    index: Index


def context(s: Session, inventory: Inventory | None = None) -> Ctx:
    facets = list(s.scalars(select(Facet)))
    entities = {e.key: e for e in s.scalars(select(Entity))}
    names = {k: e.display_name for k, e in entities.items()}
    real = [f for f in facets if f.collector != RECONCILE]
    return Ctx(facets, names, entities, build_index(real, inventory, names))


def canonical_key(c: Ctx, key: str) -> str:
    """Follow same_as so a VM and the Linux host inside it render as one machine."""
    e = c.entities.get(key)
    if e is not None and e.same_as is not None and e.same_as in c.entities:
        return e.same_as
    return key


# ------------------------------------------------------------------ dashboard


def dashboard(s: Session) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for kind, status, n in s.execute(
        select(Entity.kind, Entity.status, func.count()).group_by(Entity.kind, Entity.status)
    ):
        if status == "gone":
            continue
        if kind != "unknown-device":  # unknown devices have their own tile
            counts[kind] = counts.get(kind, 0) + n
    last = s.scalar(select(Scan).order_by(Scan.id.desc()).limit(1))
    runs = (
        list(s.scalars(select(CollectorRun).where(CollectorRun.scan_id == last.id))) if last else []
    )
    problems = [r for r in runs if r.status != "ok"]
    events = s.execute(
        select(Event, Entity.display_name)
        .join(Entity, Entity.key == Event.entity_key, isouter=True)
        .order_by(Event.id.desc())
        .limit(15)
    ).all()
    missing = s.scalars(select(Entity).where(Entity.status == "missing")).all()
    by_collector: dict[str, dict[str, int]] = {}
    for r in runs:
        by_collector.setdefault(r.collector, {}).setdefault(r.status, 0)
        by_collector[r.collector][r.status] += 1
    return {
        "counts": dict(sorted(counts.items())),
        "last_scan": last,
        "by_collector": dict(sorted(by_collector.items())),
        "problems": sorted(problems, key=lambda r: (r.status, r.target)),
        "events": [{"event": e, "name": n or e.entity_key} for e, n in events],
        "missing": missing,
        "unknown": s.scalar(
            select(func.count())
            .select_from(Entity)
            .where(Entity.kind == "unknown-device", Entity.status == "unknown")
        ),
    }


# ------------------------------------------------------------------ entities


def entities(s: Session, kind: str | None = None, q: str | None = None) -> list[Entity]:
    stmt = select(Entity).where(Entity.status != "gone")
    if kind:
        stmt = stmt.where(Entity.kind == kind)
    else:
        stmt = stmt.where(Entity.kind.not_in(HIDDEN_KINDS))
    if q:
        like = f"%{q[:64]}%"
        stmt = stmt.where(or_(Entity.display_name.ilike(like), Entity.key.ilike(like)))
    return list(s.scalars(stmt.order_by(Entity.kind, Entity.display_name).limit(500)))


def kinds(s: Session) -> list[str]:
    return sorted(k for (k,) in s.execute(select(Entity.kind).distinct()))


def entity_detail(s: Session, key: str) -> dict[str, Any] | None:
    entity = s.get(Entity, key)
    if entity is None:
        return None
    facets: dict[str, Any] = {}
    for f in s.scalars(select(Facet).where(Facet.entity_key == key)):
        # Node/guest data read over SSH from /etc/pve (ADR-028) is Proxmox data: show it as such
        # and leave "linux-ssh" for the Linux host inside the guest.
        pve_view = f.collector == "linux-ssh" and ("vmid" in f.data or key.startswith("pve:node:"))
        facets.setdefault("proxmox" if pve_view else f.collector, f.data)
    twins = list(s.scalars(select(Entity).where(Entity.same_as == key)))
    same = s.get(Entity, entity.same_as) if entity.same_as else None
    related = [key, *(t.key for t in twins), *([same.key] if same else [])]
    for t in twins:  # show the inner host's facets on the VM page as well
        for f in s.scalars(select(Facet).where(Facet.entity_key == t.key)):
            facets.setdefault(f.collector, f.data)
    children = list(
        s.scalars(
            select(Entity)
            .where(Entity.parent_key.in_(related), Entity.status != "gone")
            .order_by(Entity.kind, Entity.display_name)
        )
    )
    events = s.scalars(
        select(Event).where(Event.entity_key.in_(related)).order_by(Event.id.desc()).limit(50)
    ).all()
    return {
        "entity": entity,
        "facets": facets,
        "parent": s.get(Entity, entity.parent_key) if entity.parent_key else None,
        "same_as": same,
        "twins": twins,
        "children": children,
        "events": events,
        "annotation": s.get(Annotation, key),
    }


# ------------------------------------------------------------------ tables


def ip_table(s: Session, q: str | None = None) -> list[dict[str, Any]]:
    c = context(s)
    rows: dict[tuple[str, str], dict[str, Any]] = {}

    def add(
        ip: str | None, mac: str | None, key: str, source: str, iface: str | None = None
    ) -> None:
        if not ip:
            return
        addr = ip.split("/")[0]
        net, vlan = network_of(c.index, addr)
        ckey = canonical_key(c, key)
        rows.setdefault(
            (addr, ckey),
            {
                "ip": addr,
                "prefix": ip if "/" in ip else None,
                "mac": mac,
                "iface": iface,
                "key": ckey,
                "name": c.names.get(ckey, ckey),
                "source": source,
                "network": net,
                "vlan": vlan,
            },
        )

    for f in c.facets:
        d = f.data
        if f.collector == "linux-ssh":
            for i in d.get("interfaces") or []:
                for a in i.get("addresses") or []:
                    if a.get("scope") != "host":
                        add(a.get("address"), i.get("mac"), f.entity_key, "ssh", i.get("name"))
        elif f.collector == "proxmox":
            for a in d.get("ips") or []:
                add(a.get("address"), None, f.entity_key, "pve", a.get("iface"))
            add(d.get("ip"), None, f.entity_key, "pve")
        elif f.collector == "unifi":
            add(d.get("ip"), d.get("mac"), f.entity_key, "unifi")
            for cl in d.get("clients") or []:
                owner = c.index.mac_owner.get(cl.get("mac") or "", f"net:mac:{cl.get('mac')}")
                add(cl.get("ip"), cl.get("mac"), owner, "unifi client")
        elif f.collector == RECONCILE:
            # Only devices still unexplained. Identified ones are already listed under the
            # machine that explains them, and a guest's network facet repeats its UniFi row.
            e = c.entities.get(f.entity_key)
            if (
                e is not None
                and e.kind == "unknown-device"
                and e.status in ("unknown", "acknowledged")
            ):
                add(d.get("ip"), d.get("mac"), f.entity_key, "unknown")
    out = sorted(rows.values(), key=lambda r: _ip_key(r["ip"]))
    if q:
        ql = q.lower()[:64]
        out = [r for r in out if any(ql in str(v).lower() for v in r.values() if v)]
    return out


def vlan_table(s: Session) -> list[dict[str, Any]]:
    c = context(s)
    ips = ip_table(s)
    nets: list[dict[str, Any]] = []
    ssids = [x for f in c.facets if f.collector == "unifi" for x in f.data.get("ssids") or []]
    nodes_with: dict[int, list[str]] = {}
    tagged: dict[int, int] = {}
    for f in c.facets:
        if f.collector == "proxmox" and "interfaces" in f.data:
            for i in f.data["interfaces"]:
                if i.get("vlan_id") is not None:
                    nodes_with.setdefault(i["vlan_id"], []).append(
                        c.names.get(f.entity_key, f.entity_key)
                    )
        if f.collector == "proxmox" and "nics" in f.data:
            for n in f.data["nics"]:
                if n.get("vlan_tag") is not None:
                    tagged[n["vlan_tag"]] = tagged.get(n["vlan_tag"], 0) + 1
    for f in c.facets:
        if f.collector != "unifi":
            continue
        for n in f.data.get("networks") or []:
            vlan = n.get("vlan_id")
            nets.append(
                {
                    "name": n.get("name"),
                    "vlan": vlan,
                    "subnet": n.get("subnet"),
                    "gateway": n.get("gateway_ip"),
                    "dhcp": n.get("dhcp_mode"),
                    "isolation": n.get("isolation"),
                    "ssids": [x["name"] for x in ssids if x.get("network_id") == n.get("id")],
                    "members": sorted({r["name"] for r in ips if r["network"] == n.get("name")}),
                    "pve_nodes": sorted(nodes_with.get(vlan, [])) if vlan is not None else [],
                    "tagged_guest_nics": tagged.get(vlan, 0) if vlan is not None else 0,
                }
            )
    return sorted(nets, key=lambda n: (n["vlan"] is None, n["vlan"] or 0))


def port_table(s: Session, q: str | None = None) -> list[dict[str, Any]]:
    c = context(s)
    rows: list[dict[str, Any]] = []
    for f in c.facets:
        name = c.names.get(f.entity_key, f.entity_key)
        if f.collector == "linux-ssh":
            for sock in f.data.get("sockets") or []:
                rows.append(
                    {
                        "name": name,
                        "key": f.entity_key,
                        "proto": sock.get("proto"),
                        "address": sock.get("address"),
                        "port": sock.get("port"),
                        "what": sock.get("process"),
                        "source": "listening",
                    }
                )
        elif f.collector == "docker":
            for ctr in f.data.get("containers") or []:
                for p in ctr.get("ports") or []:
                    rows.append(
                        {
                            "name": name,
                            "key": f.entity_key,
                            "proto": p.get("proto"),
                            "address": p.get("host_ip"),
                            "port": p.get("host_port"),
                            "what": f"{ctr.get('key')} -> {p.get('container_port')}",
                            "source": "published",
                        }
                    )
    rows.sort(key=lambda r: (r["port"] or 0, r["proto"] or "", r["name"]))
    if q:
        ql = q.lower()[:64]
        rows = [r for r in rows if any(ql in str(v).lower() for v in r.values() if v)]
    return rows


def changes(
    s: Session,
    severity: str | None = None,
    q: str | None = None,
    before: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    stmt = (
        select(Event, Entity.display_name, Scan.started_at, Scan.label)
        .join(Entity, Entity.key == Event.entity_key, isouter=True)
        .join(Scan, Scan.id == Event.scan_id)
    )
    if severity in SEVERITY_ORDER:
        stmt = stmt.where(Event.severity == severity)
    if q:
        like = f"%{q[:64]}%"
        stmt = stmt.where(or_(Event.summary.ilike(like), Event.type.ilike(like)))
    if before:
        stmt = stmt.where(Event.id < before)
    rows = s.execute(stmt.order_by(Event.id.desc()).limit(limit)).all()
    return [
        {"event": e, "name": n or e.entity_key, "at": at, "label": label}
        for e, n, at, label in rows
    ]


def unknown_devices(s: Session, include_ack: bool = False) -> list[dict[str, Any]]:
    statuses = ["unknown", "acknowledged"] if include_ack else ["unknown"]
    rows = s.execute(
        select(Entity, Facet)
        .join(Facet, Facet.entity_key == Entity.key)
        .where(Entity.kind == "unknown-device", Entity.status.in_(statuses))
        .order_by(Entity.first_seen.desc())
    ).all()
    return [{"entity": e, **f.data} for e, f in rows]
