"""Read models for the v2 UI: machines, grouped IPs, what runs where (ADR-029).

A *machine* is what a person thinks of as one box: a Proxmox VM and the Linux host inside it
are one machine (same_as), with every facet merged. Everything here is computed on read.
"""

import ipaddress
import re
from collections import defaultdict
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas.engine.apps import detect
from homelab_atlas.engine.reconcile import RECONCILE
from homelab_atlas.store.tables import Entity, Event, Facet
from homelab_atlas.web.queries import _ip_key, context, ip_table

MACHINE_KINDS: Final = ("pve-node", "pve-vm", "pve-lxc", "linux-host", "nas")
INTERNAL_IFACE_RE: Final = re.compile(
    r"^(docker\d*|br-[0-9a-f]{6,}|veth|cni|flannel|virbr|lxcbr|kube)", re.I
)


# Proxmox `ostype` codes (qm.conf / pct.conf) to something a person reads.
OSTYPES: Final = {
    "l26": "Linux",
    "l24": "Linux 2.4",
    "win11": "Windows 11",
    "win10": "Windows 10",
    "win8": "Windows 8",
    "win7": "Windows 7",
    "wvista": "Windows Vista",
    "w2k8": "Windows 2008",
    "w2k3": "Windows 2003",
    "w2k": "Windows 2000",
    "wxp": "Windows XP",
    "solaris": "Solaris",
    "other": "Other OS",
    "debian": "Debian",
    "ubuntu": "Ubuntu",
    "centos": "CentOS",
    "fedora": "Fedora",
    "opensuse": "openSUSE",
    "archlinux": "Arch Linux",
    "alpine": "Alpine",
    "gentoo": "Gentoo",
    "nixos": "NixOS",
    "devuan": "Devuan",
    "unmanaged": "Unmanaged",
}


def os_label(code: str | None) -> str | None:
    """`l26` -> `Linux`; anything unknown is shown as is."""
    if not code:
        return None
    return OSTYPES.get(code.lower(), code)


def top_apps(cards: list[dict[str, Any]], n: int = 3) -> list[str]:
    """Most common recognised apps across machines, for the dashboard tile."""
    counts: dict[str, int] = defaultdict(int)
    for m in cards:
        for a in m["apps"]:
            if a["category"] not in {"system", "remote", "containers", "hypervisor"}:
                counts[a["name"]] += 1
    return sorted(counts, key=lambda k: (-counts[k], k))[:n]


def _is_link_local(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip.split("/", maxsplit=1)[0])
    except ValueError:
        return False
    return a.is_link_local or a.is_loopback


def _merge(facets: dict[str, dict[str, Any]], more: dict[str, dict[str, Any]]) -> None:
    for collector, data in more.items():
        facets.setdefault(collector, data)


def machines(s: Session) -> list[dict[str, Any]]:
    """One card per machine, with what runs on it."""
    ents = {e.key: e for e in s.scalars(select(Entity)) if e.status != "gone"}
    by_entity: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for f in s.scalars(select(Facet)):
        by_entity[f.entity_key][f.collector] = f.data
    twins: dict[str, list[str]] = defaultdict(list)
    for e in ents.values():
        if e.same_as and e.same_as in ents:
            twins[e.same_as].append(e.key)
    ip_rows = ip_table(s)
    ips_by_key: dict[str, list[str]] = defaultdict(list)
    for r in ip_rows:
        if not _is_link_local(r["ip"]) and not INTERNAL_IFACE_RE.match(r.get("iface") or ""):
            ips_by_key[r["key"]].append(r["ip"])
    out = []
    for key, e in ents.items():
        if e.kind not in MACHINE_KINDS or (e.same_as and e.same_as in ents):
            continue
        facets = dict(by_entity.get(key, {}))
        for t in twins.get(key, []):
            _merge(facets, by_entity.get(t, {}))
        out.append(_card(key, e, facets, ents, sorted(set(ips_by_key.get(key, [])), key=_ip_key)))
    order = {"pve-node": 0, "pve-vm": 1, "pve-lxc": 1, "linux-host": 2, "nas": 3}
    return sorted(out, key=lambda m: (order.get(m["kind"], 9), m["node"] or "", m["name"].lower()))


def _guest(facets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    for c in ("proxmox", "linux-ssh"):
        g = facets.get(c)
        if isinstance(g, dict) and "vmid" in g:
            return g
    return {}


def _card(key: str, e: Entity, facets: dict[str, dict[str, Any]], ents: dict[str, Entity],
          ips: list[str]) -> dict[str, Any]:  # fmt: skip
    lx = (
        facets.get("linux-ssh")
        if isinstance(facets.get("linux-ssh"), dict) and "vmid" not in facets["linux-ssh"]
        else None
    )
    # A guest entity's "linux-ssh" facet is the /etc/pve view; the host's own facet is a twin's.
    if lx is None:
        lx = next((d for c, d in facets.items() if c == "linux-ssh" and "vmid" not in d), None)
    dk = facets.get("docker") or {}
    g = _guest(facets)
    services = [x for x in (lx or {}).get("services") or [] if x.get("active") == "active"]
    containers = dk.get("containers") or []
    apps = detect(
        services, (lx or {}).get("processes") or [], containers, (lx or {}).get("sockets") or []
    )
    os_ = (lx or {}).get("os") or {}
    parent = ents.get(e.parent_key) if e.parent_key else None
    node = (
        parent.display_name.replace(" (PVE node)", "")
        if parent and parent.kind == "pve-node"
        else g.get("node")
    )
    net = facets.get(RECONCILE) or {}
    return {
        "key": key,
        "name": e.display_name,
        "short": re.sub(r" \((VM|LXC) \d+\)$| \(PVE node\)$", "", e.display_name),
        "kind": e.kind,
        "status": g.get("status") or e.status,
        "node": node,
        "vmid": g.get("vmid"),
        "cores": g.get("cores"),
        "memory_mb": g.get("memory_mb"),
        "os": os_.get("os_pretty") or g.get("agent_os") or os_label(g.get("ostype")),
        "kernel": os_.get("kernel"),
        "ips": ips or ([net["ip"]] if net.get("ip") else []),
        "vlan": net.get("vlan"),
        "network": net.get("network"),
        "uplink": net.get("uplink"),
        "documented": lx is not None,  # atlas logs in to it (SSH)
        "services": len(services),
        "containers": len(containers),
        "containers_running": sum(1 for c in containers if c.get("status") == "running"),
        "ports": len((lx or {}).get("sockets") or []),
        "apps": apps,
        "tags": g.get("tags") or [],
    }


def running(s: Session, key: str) -> dict[str, Any]:
    """Everything running on one machine (host page "Running" panel)."""
    keys = [key, *(e.key for e in s.scalars(select(Entity).where(Entity.same_as == key)))]
    lx: dict[str, Any] = {}
    dk: dict[str, Any] = {}
    for f in s.scalars(select(Facet).where(Facet.entity_key.in_(keys))):
        if f.collector == "linux-ssh" and "vmid" not in f.data:
            lx = f.data
        elif f.collector == "docker":
            dk = f.data
    services = [x for x in lx.get("services") or [] if x.get("active") == "active"]
    procs = sorted(lx.get("processes") or [], key=lambda p: -(p.get("cpu_pct") or 0))
    containers = dk.get("containers") or []
    return {
        "apps": detect(services, procs, containers, lx.get("sockets") or []),
        "services": sorted(services, key=lambda x: x.get("unit") or ""),
        "failed": [x for x in lx.get("services") or [] if x.get("active") == "failed"],
        "containers": containers,
        "processes": procs[:60],
        "process_count": len(procs),
        "sockets": lx.get("sockets") or [],
        "timers": lx.get("timers") or [],
    }


def everything_running(s: Session, q: str | None = None) -> dict[str, Any]:
    """Services page: apps, services and containers across every machine."""
    ms = machines(s)
    apps: dict[str, dict[str, Any]] = {}
    for m in ms:
        for a in m["apps"]:
            row = apps.setdefault(a["name"], {**a, "hosts": []})
            row["hosts"].append(
                {
                    "key": m["key"],
                    "name": m["short"],
                    "ip": (m["ips"] or [None])[0],
                    "web_port": a.get("web_port"),
                }
            )
    svc_rows, ctr_rows = [], []
    for m in ms:
        if not m["documented"] and not m["containers"]:
            continue
        r = running(s, m["key"])
        for x in r["services"]:
            svc_rows.append(
                {
                    "host": m["short"],
                    "key": m["key"],
                    "unit": x.get("unit"),
                    "description": x.get("description"),
                    "enabled": x.get("enabled"),
                }
            )
        for c in r["containers"]:
            ctr_rows.append(
                {
                    "host": m["short"],
                    "key": m["key"],
                    **{
                        k: c.get(k)
                        for k in ("name", "image", "status", "health", "compose_project")
                    },
                    "ports": [
                        f"{p.get('host_port')}→{p.get('container_port')}/{p.get('proto')}"
                        for p in c.get("ports") or []
                    ],
                }
            )
    if q:
        ql = q.lower()[:64]
        svc_rows = [r for r in svc_rows if ql in str(r).lower()]
        ctr_rows = [r for r in ctr_rows if ql in str(r).lower()]
        apps = {k: v for k, v in apps.items() if ql in str(v).lower()}
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in sorted(apps.values(), key=lambda a: a["name"].lower()):
        by_cat[a["category_label"]].append(a)
    return {
        "apps_by_category": dict(sorted(by_cat.items())),
        "services": svc_rows,
        "containers": ctr_rows,
        "machines": ms,
    }


def ip_groups(s: Session, q: str | None = None, everything: bool = False) -> dict[str, Any]:
    """One row per device: its addresses, MACs, networks and sources together."""
    rows = ip_table(s)
    hidden = 0
    groups: dict[str, dict[str, Any]] = {}
    for r in rows:
        internal = _is_link_local(r["ip"]) or bool(INTERNAL_IFACE_RE.match(r.get("iface") or ""))
        if internal and not everything:
            hidden += 1
            continue
        g = groups.setdefault(
            r["key"],
            {
                "key": r["key"],
                "name": r["name"],
                "ips": [],
                "macs": set(),
                "networks": set(),
                "sources": set(),
                "internal": 0,
            },
        )
        if not any(x["ip"] == r["ip"] for x in g["ips"]):
            g["ips"].append(
                {
                    "ip": r["ip"],
                    "iface": r.get("iface"),
                    "internal": internal,
                    "network": r.get("network"),
                    "vlan": r.get("vlan"),
                }
            )
        if r.get("mac"):
            g["macs"].add(r["mac"])
        if r.get("network"):
            g["networks"].add(
                f"{r['network']} (VLAN {r['vlan']})" if r.get("vlan") is not None else r["network"]
            )
        g["sources"].add(r["source"])
        g["internal"] += int(internal)
    out = []
    for g in groups.values():
        g["ips"].sort(key=lambda x: (x["internal"], _ip_key(x["ip"])))
        g["macs"], g["networks"], g["sources"] = (
            sorted(g["macs"]),
            sorted(g["networks"]),
            sorted(g["sources"]),
        )
        g["primary"] = g["ips"][0]["ip"] if g["ips"] else None
        out.append(g)
    out.sort(key=lambda g: _ip_key(g["primary"] or "z"))
    if q:
        ql = q.lower()[:64]
        out = [g for g in out if ql in str(g).lower()]
    return {"groups": out, "hidden": hidden}


def recent_activity(s: Session, limit: int = 8) -> list[dict[str, Any]]:
    rows = s.execute(
        select(Event, Entity.display_name)
        .join(Entity, Entity.key == Event.entity_key, isouter=True)
        .order_by(Event.id.desc())
        .limit(limit)
    ).all()
    return [{"event": e, "name": n or e.entity_key} for e, n in rows]


def discovered_not_documented(s: Session) -> list[dict[str, Any]]:
    """Infrastructure UniFi sees (VMs, Pis, servers) that atlas does not log in to yet."""
    c = context(s)
    documented_macs: set[str] = set()
    documented_ips: set[str] = set()
    for f in c.facets:
        if f.collector == "linux-ssh" and "interfaces" in f.data:
            for i in f.data.get("interfaces") or []:
                if i.get("mac"):
                    documented_macs.add(i["mac"])
                for a in i.get("addresses") or []:
                    documented_ips.add(str(a.get("address") or "").split("/")[0])
    from homelab_atlas.engine.classify import classify  # noqa: PLC0415

    out = []
    seen: set[str] = set()
    for f in c.facets:
        if f.collector != "unifi":
            continue
        for cl in f.data.get("clients") or []:
            mac, ip = cl.get("mac") or "", cl.get("ip")
            if not mac or mac in seen or mac in documented_macs or (ip and ip in documented_ips):
                continue
            seen.add(mac)
            v = classify(
                mac,
                cl.get("name"),
                wired={"WIRED": True, "WIRELESS": False}.get(str(cl.get("type"))),
            )
            if not v.infrastructure:
                continue
            owner = c.index.mac_owner.get(mac)
            out.append(
                {
                    "name": cl.get("name") or (c.names.get(owner) if owner else None) or mac,
                    "ip": ip,
                    "mac": mac,
                    "category": v.category,
                    "reasons": list(v.reasons),
                    "type": "pi" if v.category == "pi" else "linux",
                }
            )
    return sorted(out, key=lambda x: _ip_key(x["ip"] or "z"))
