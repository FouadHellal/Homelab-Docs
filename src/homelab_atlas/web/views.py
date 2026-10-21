"""Read models for the v2 UI: machines, grouped IPs, what runs where (ADR-029).

A *machine* is what a person thinks of as one box: a Proxmox VM and the Linux host inside it
are one machine (same_as), with every facet merged. Everything here is computed on read.
"""

import ipaddress
import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas.engine.apps import (
    CATEGORY_LABELS,
    CustomRule,
    app_for_unit,
    catalog,
    detect,
)
from homelab_atlas.engine.reconcile import RECONCILE
from homelab_atlas.store.facets import facet_views
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


def short_name(display_name: str) -> str:
    """`docker01 (VM 101)` -> `docker01`, `pve1 (PVE node)` -> `pve1`."""
    return re.sub(r" \((VM|LXC) \d+\)$| \(PVE node\)$", "", display_name)


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
    sources: dict[str, str] = {}
    ssh_target: dict[str, str] = {}
    for f in facet_views(s.scalars(select(Facet))):
        by_entity[f.entity_key][f.collector] = f.data
        if f.collector == "proxmox":
            sources[f.entity_key] = f.source
        elif f.collector == "linux-ssh":
            ssh_target[f.entity_key] = f.target
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
        card = _card(key, e, facets, ents, sorted(set(ips_by_key.get(key, [])), key=_ip_key))
        card["pve_source"] = sources.get(key)
        card["target"] = ssh_target.get(key) or next(
            (ssh_target[t] for t in twins.get(key, []) if t in ssh_target), None
        )
        out.append(card)
    order = {"pve-node": 0, "pve-vm": 1, "pve-lxc": 1, "linux-host": 2, "nas": 3}
    return sorted(out, key=lambda m: (order.get(m["kind"], 9), m["node"] or "", m["name"].lower()))


def _guest(facets: dict[str, dict[str, Any]]) -> dict[str, Any]:
    g = facets.get("proxmox")  # the strongest Proxmox source (store.facets)
    return g if isinstance(g, dict) and "vmid" in g else {}


def _card(key: str, e: Entity, facets: dict[str, dict[str, Any]], ents: dict[str, Entity],
          ips: list[str]) -> dict[str, Any]:  # fmt: skip
    lx = facets.get("linux-ssh")  # the Linux host itself (or the one inside this guest)
    dk = facets.get("docker") or {}
    g = _guest(facets)
    services = [x for x in (lx or {}).get("services") or [] if x.get("active") == "active"]
    containers = dk.get("containers") or []
    apps = detect(
        services,
        (lx or {}).get("processes") or [],
        containers,
        (lx or {}).get("sockets") or [],
        host=short_name(e.display_name),
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
        "short": short_name(e.display_name),
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
        "nics": [
            {"bridge": n.get("bridge"), "vlan": n.get("vlan_tag"), "mac": n.get("mac")}
            for n in g.get("nics") or []
        ],
        "pve": _node_info(facets, lx) if key.startswith("pve:node:") else None,
    }


def _node_info(facets: dict[str, dict[str, Any]], lx: dict[str, Any] | None) -> dict[str, Any]:
    """A Proxmox node's version, size and bridges, from the API or from its own host facts."""
    p = facets.get("proxmox") or {}
    bridges = [
        {
            "name": i["iface"],
            "cidr": i.get("cidr"),
            "vlan_aware": i.get("vlan_aware"),
            "ports": i.get("bridge_ports") or [],
        }
        for i in p.get("interfaces") or []
        if i.get("type") in ("bridge", "OVSBridge") and i.get("iface")
    ]
    if not bridges and lx:
        ports: dict[str, list[str]] = defaultdict(list)
        for i in lx.get("interfaces") or []:
            if i.get("master"):
                ports[i["master"]].append(i["name"])
        bridges = [
            {
                "name": i["name"],
                "vlan_aware": None,
                "ports": ports.get(i["name"], []),
                "cidr": next(
                    (
                        a.get("address")
                        for a in i.get("addresses") or []
                        if ":" not in str(a.get("address"))
                    ),
                    None,
                ),
            }
            for i in lx.get("interfaces") or []
            if i.get("kind") == "bridge" and str(i.get("name", "")).startswith(("vmbr", "vnet"))
        ]
    mem = p.get("memory_bytes")
    return {
        "version": p.get("pve_version") or ((lx or {}).get("pve") or {}).get("version"),
        "cpu_cores": p.get("cpu_cores"),
        "cpu_model": p.get("cpu_model"),
        "memory_gb": round(mem / 2**30, 1) if isinstance(mem, int) else None,
        "uptime_s": p.get("uptime_s"),
        "cpu_load": p.get("cpu_load"),
        "online": p.get("online"),
        "bridges": sorted(bridges, key=lambda b: b["name"]),
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
    ent = s.get(Entity, key)
    host = short_name(ent.display_name) if ent is not None else None
    return {
        "apps": detect(services, procs, containers, lx.get("sockets") or [], host=host),
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


def discovered_not_documented(
    s: Session, target_addresses: Iterable[str] = ()
) -> list[dict[str, Any]]:
    """Infrastructure UniFi sees (VMs, Pis, servers) that atlas does not log in to yet.

    Addresses that are already targets are left out: they are listed under "Needs attention"
    until their first successful scan.
    """
    targets = {a.strip().lower() for a in target_addresses}
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
            known = documented_ips | targets
            name = str(cl.get("name") or "").lower()
            if (
                not mac
                or mac in seen
                or mac in documented_macs
                or (ip and ip in known)
                or (name and name in targets)
            ):
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


def proxmox_summary(cards: list[dict[str, Any]]) -> dict[str, Any]:
    """Topology header numbers (nodes, guests by type/state, allocated vCPU and RAM)."""
    nodes = [m for m in cards if m["kind"] == "pve-node"]
    guests = [m for m in cards if m["kind"] in ("pve-vm", "pve-lxc") and m["vmid"] is not None]
    cores = sum((m.get("pve") or {}).get("cpu_cores") or 0 for m in nodes)
    ram = sum((m.get("pve") or {}).get("memory_gb") or 0 for m in nodes)
    return {
        "nodes": len(nodes),
        "clusters": sorted({m["key"].removeprefix("pve:node:").split("/")[0] for m in nodes}),
        "guests": len(guests),
        "vms": sum(1 for m in guests if m["kind"] == "pve-vm"),
        "lxcs": sum(1 for m in guests if m["kind"] == "pve-lxc"),
        "running": sum(1 for m in guests if m["status"] == "running"),
        "stopped": sum(1 for m in guests if m["status"] == "stopped"),
        "unknown": sum(1 for m in guests if m["status"] not in ("running", "stopped")),
        "vcpu": sum(m["cores"] or 0 for m in guests if m["status"] != "stopped"),
        "cores": cores or None,
        "mem_gb": round(
            sum(m["memory_mb"] or 0 for m in guests if m["status"] != "stopped") / 1024, 1
        ),
        "ram_gb": round(ram, 1) or None,
        "documented": sum(1 for m in guests if m["documented"]),
    }


KIND_LABELS: Final = {
    "pve-node": "Proxmox node",
    "pve-vm": "VM",
    "pve-lxc": "LXC",
    "linux-host": "Host",
    "nas": "NAS",
}
SERVICE_STATES: Final = ("running", "failed", "inactive", "all")
SERVICE_COLUMNS: Final = (
    "machine", "kind", "node", "ip", "type", "name", "description", "state", "sub",
    "enabled", "app", "category", "image", "ports",
)  # fmt: skip


def _unit_state(active: str | None) -> str:
    if active == "active":
        return "running"
    return "failed" if active == "failed" else "inactive"


def _container_state(c: dict[str, Any]) -> str:
    status = str(c.get("status") or "")
    if status == "running":
        return "running"
    if status in ("restarting", "dead") or (c.get("exit_code") or 0) != 0:
        return "failed"
    return "inactive"


def _machine_rows(
    m: dict[str, Any], lx: dict[str, Any], dk: dict[str, Any]
) -> list[dict[str, Any]]:
    base = {
        "machine": m["short"],
        "key": m["key"],
        "kind": KIND_LABELS.get(m["kind"], m["kind"]),
        "node": m["node"] or "",
        "ip": (m["ips"] or [""])[0],
    }
    rows: list[dict[str, Any]] = []
    for u in lx.get("services") or []:
        app = app_for_unit(str(u.get("unit") or ""))
        rows.append(
            {
                **base,
                "type": "systemd",
                "name": str(u.get("unit") or "").removesuffix(".service"),
                "description": u.get("description") or "",
                "state": _unit_state(u.get("active")),
                "sub": u.get("sub") or "",
                "enabled": u.get("enabled") or "",
                "app": app.name if app else "",
                "category": CATEGORY_LABELS.get(app.category, app.category) if app else "",
                "image": "",
                "ports": "",
            }
        )
    for c in dk.get("containers") or []:
        found = next((a for a in detect(containers=[c]) if a["category"] != "system"), None)
        health = f" ({c.get('health')})" if c.get("health") else ""
        ports = [
            f"{p.get('host_port')}->{p.get('container_port')}/{p.get('proto')}"
            for p in c.get("ports") or []
            if p.get("host_port")
        ]
        rows.append(
            {
                **base,
                "type": "container",
                "name": c.get("name") or "",
                "description": c.get("compose_project") or "",
                "state": _container_state(c),
                "sub": str(c.get("status") or "") + health,
                "enabled": c.get("restart_policy") or "",
                "app": found["name"] if found else "",
                "category": found["category_label"] if found else "",
                "image": c.get("image") or "",
                "ports": ", ".join(ports),
            }
        )
    return rows


def service_table(
    s: Session,
    *,
    machine: str | None = None,
    state: str = "running",
    kind: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    """Every systemd unit and Docker container on every documented machine, one row each,
    filtered the way the Services page (and its CSV export) asks."""
    cards = machines(s)
    twins: dict[str, list[str]] = defaultdict(list)
    for e in s.scalars(select(Entity).where(Entity.same_as.is_not(None))):
        twins[str(e.same_as)].append(e.key)
    facets: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for f in s.scalars(select(Facet).where(Facet.collector.in_(("linux-ssh", "docker")))):
        facets[f.entity_key][f.collector] = f.data
    rows: list[dict[str, Any]] = []
    for m in cards:
        if not m["documented"] and not m["containers"]:
            continue
        lx: dict[str, Any] = {}
        dk: dict[str, Any] = {}
        for k in (m["key"], *twins.get(m["key"], [])):
            lx = lx or facets[k].get("linux-ssh") or {}
            dk = dk or facets[k].get("docker") or {}
        rows.extend(_machine_rows(m, lx, dk))
    total = len(rows)
    counts = {st: sum(1 for r in rows if r["state"] == st) for st in SERVICE_STATES[:3]}
    names = sorted({r["machine"] for r in rows}, key=str.lower)
    if machine:
        rows = [r for r in rows if r["machine"] == machine]
    if state in SERVICE_STATES[:3]:
        rows = [r for r in rows if r["state"] == state]
    if kind in ("systemd", "container"):
        rows = [r for r in rows if r["type"] == kind]
    if q:
        ql = q.lower()[:64]
        rows = [r for r in rows if any(ql in str(v).lower() for v in r.values())]
    rows.sort(key=lambda r: (r["machine"].lower(), r["type"], r["name"].lower()))
    return {
        "rows": rows,
        "total": total,
        "counts": counts,
        "machines": names,
        "undocumented": sorted(
            m["short"] for m in cards if not m["documented"] and m["status"] != "stopped"
        ),
    }


# Ports nobody needs to name: DHCP clients, rpcbind, chrony, mDNS, SSDP, NetBIOS.
IGNORED_PORTS: Final = frozenset({68, 111, 123, 137, 138, 323, 546, 1900, 5353})
GENERIC_PROCS: Final = frozenset({
    "docker-proxy", "python", "python3", "node", "java", "ruby", "perl", "php", "php-fpm",
    "dotnet", "mono", "deno", "bun", "beam.smp", "gunicorn", "uvicorn", "busybox", "sh", "bash",
})  # fmt: skip


def _is_loopback(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.strip("[]").split("%")[0]).is_loopback
    except ValueError:
        return address in ("localhost",)


def unrecognised_ports(s: Session) -> list[dict[str, Any]]:
    """Listening ports no recognised app explains, grouped by what would name them: a
    container image, a process, or (generic process) the port on that machine. ADR-034."""
    cards = {m["key"]: m for m in machines(s) if m["documented"]}
    twins: dict[str, list[str]] = defaultdict(list)
    for e in s.scalars(select(Entity).where(Entity.same_as.is_not(None))):
        twins[str(e.same_as)].append(e.key)
    facets: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for f in s.scalars(select(Facet).where(Facet.collector.in_(("linux-ssh", "docker")))):
        facets[f.entity_key][f.collector] = f.data
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for key, m in cards.items():
        lx: dict[str, Any] = {}
        dk: dict[str, Any] = {}
        for k in (key, *twins.get(key, [])):
            lx = lx or facets[k].get("linux-ssh") or {}
            dk = dk or facets[k].get("docker") or {}
        claimed_ports = {p for a in m["apps"] for p in a["ports"]}
        claimed_ctrs = {c for a in m["apps"] for c in a["containers"]}
        by_name = {a.name: a for a in catalog()}
        claimed_procs = {
            pn.lower() for a in m["apps"] if a["name"] in by_name for pn in by_name[a["name"]].procs
        }
        published = {
            p.get("host_port"): c for c in dk.get("containers") or [] for p in c.get("ports") or []
        }
        for sock in lx.get("sockets") or []:
            port, proc = sock.get("port"), str(sock.get("process") or "").lower()
            if not isinstance(port, int) or port in IGNORED_PORTS or port in claimed_ports:
                continue
            if _is_loopback(str(sock.get("address") or "")) or proc in claimed_procs:
                continue
            ctr = published.get(port) if proc in ("docker-proxy", "") else None
            if ctr is not None:
                if str(ctr.get("name") or "") in claimed_ctrs:
                    continue
                image = str(ctr.get("image") or "").split("@")[0].rsplit(":", 1)[0].lower()
                gkey, kind, value = ("image", image), "image", image
                label = f"container {ctr.get('name')} ({image})"
            elif proc and proc not in GENERIC_PROCS:
                gkey, kind, value, label = ("proc", proc), "proc", proc, f"process {proc}"
            else:
                host = m["short"].lower()
                gkey, kind, value = ("port", f"{host}:{port}"), "port", str(port)
                label = f"port {port}" + (f" ({proc})" if proc else " (process unknown)")
            g = groups.setdefault(
                gkey,
                {"kind": kind, "value": value, "label": label, "ports": set(), "machines": {},
                 "protos": set()},
            )  # fmt: skip
            g["ports"].add(port)
            g["protos"].add(str(sock.get("proto") or "tcp"))
            g["machines"][m["short"]] = m["key"]
    out = []
    for g in groups.values():
        out.append({**g, "ports": sorted(g["ports"]), "protos": sorted(g["protos"]),
                    "machines": sorted(g["machines"].items())})  # fmt: skip
    return sorted(out, key=lambda g: (-len(g["machines"]), g["ports"][0]))


def custom_rule_from(
    *, name: str, category: str, kind: str, value: str, ports: list[int], machines: list[str]
) -> CustomRule:
    """The rule the "Name it" form creates for one unrecognised-port group."""
    data: dict[str, Any] = {"name": name.strip(), "category": category, "ports": ports}
    if kind == "image":
        data["images"] = [value]
    elif kind == "proc":
        data["procs"] = [value]
    else:  # a generic process: the port itself is the evidence, on these machines only
        data["strong_ports"] = True
        data["hosts"] = [m.lower() for m in machines]
    web = next((p for p in ports if p in (80, 443, 3000, 5000, 8000, 8080, 8443, 9000)), None)
    if web is None and len(ports) == 1:
        web = ports[0]
    data["web"] = web
    return CustomRule.model_validate(data)
