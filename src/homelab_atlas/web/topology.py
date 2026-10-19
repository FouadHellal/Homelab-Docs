"""Cytoscape element lists for the topology views (SPEC §10, ADR-030).

* proxmox (`logical`): cluster box > one box per PVE node. Inside: the node itself (hub), its
  bridges, and its VMs/LXCs wired to the bridge their NIC uses (each guest = the machine
  inside, with apps/services/containers); containers on request; other machines (Pi, NAS,
  bare-metal Linux) in their own box. Data from the API or from /etc/pve (ADR-031).
* physical: UniFi site > gateway > switches > APs, clients hung off their uplink device, each
  client classified (infrastructure vs personal/IoT) so the UI can hide the noise;
* vlan:     one compound node per UniFi network, members by IP address.
Labels and every other value are data; cytoscape renders them as text, never as HTML.
"""

from typing import Any, Literal

from sqlalchemy.orm import Session

from homelab_atlas.engine.classify import classify
from homelab_atlas.engine.reconcile import RECONCILE
from homelab_atlas.web.queries import Ctx, canonical_key, context, ip_table
from homelab_atlas.web.views import machines

View = Literal["physical", "logical", "vlan"]


def _node(c: Ctx, key: str, *, parent: str | None = None, node_id: str | None = None,
          label: str | None = None, kind: str | None = None) -> dict[str, Any]:  # fmt: skip
    e = c.entities.get(key)
    data: dict[str, Any] = {
        "id": node_id or key,
        "key": key,
        "label": label or c.names.get(key, key),
        "kind": kind or (e.kind if e else "unknown"),
        "status": e.status if e else "unknown",
    }
    if parent:
        data["parent"] = parent
    return {"data": data}


def _edge(src: str, dst: str, kind: str = "link") -> dict[str, Any]:
    return {"data": {"id": f"{src}->{dst}", "source": src, "target": dst, "kind": kind}}


def physical(c: Ctx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    present: set[str] = set()
    devices = [f for f in c.facets if f.collector == "unifi" and "mac" in f.data]
    for f in c.facets:
        if f.collector == "unifi" and "clients" in f.data:
            out.append(_node(c, f.entity_key, kind="unifi-site"))
            present.add(f.entity_key)
    for f in devices:
        feats = f.data.get("features") or []
        kind = "gateway" if "gateway" in feats else "ap" if "accessPoint" in feats else "switch"
        out.append(_node(c, f.entity_key, kind=kind))
        present.add(f.entity_key)
    for f in devices:
        e = c.entities.get(f.entity_key)
        if e is not None and e.parent_key in present:
            out.append(_edge(e.parent_key, f.entity_key, "uplink"))
    for f in c.facets:
        if f.collector != "unifi" or "clients" not in f.data:
            continue
        for cl in f.data["clients"]:
            mac = cl.get("mac") or ""
            owner = c.index.mac_owner.get(mac, f"net:mac:{mac}")
            key = canonical_key(c, owner)
            if key not in present:
                ckind = None if key in c.entities else "unknown-device"
                node = _node(c, key, label=c.names.get(key, cl.get("name") or mac), kind=ckind)
                known = key in c.entities and c.entities[key].kind != "unknown-device"
                v = classify(mac, cl.get("name"), wired=cl.get("type") == "WIRED")
                node["data"].update(
                    {
                        "ip": cl.get("ip"),
                        "mac": mac,
                        "category": v.category,
                        "infra": known or v.infrastructure,
                    }
                )
                out.append(node)
                present.add(key)
            uplink = f"unifi:dev:{cl.get('uplink_mac')}"
            if uplink in present:
                out.append(
                    _edge(uplink, key, "wireless" if cl.get("type") == "WIRELESS" else "wired")
                )
    return _dedupe(out)


def _card_data(m: dict[str, Any]) -> dict[str, Any]:
    web = next((a for a in m["apps"] if a.get("web_port")), None)
    ip = (m["ips"] or [None])[0]
    return {
        "ip": ip,
        "os": m["os"],
        "node": m["node"],
        "vmid": m["vmid"],
        "status": m["status"],
        "apps": [a["name"] for a in m["apps"] if a["category"] != "system"][:8],
        "services": m["services"],
        "containers": m["containers"],
        "ports": m["ports"],
        "documented": m["documented"],
        "cores": m["cores"],
        "memory_mb": m["memory_mb"],
        "vlan": m["vlan"],
        "network": m["network"],
        "uplink": m["uplink"],
        "web": f"https://{ip}:{web['web_port']}"
        if web and ip and web["web_port"] in (443, 8006, 8007, 9443)
        else (f"http://{ip}:{web['web_port']}" if web and ip else None),
        "web_app": web["name"] if web else None,
        "scan_target": m.get("target"),
        "pve_from": m.get("pve_source"),
        "tags": m.get("tags") or [],
        "ips": m["ips"][:6],
    }


def _node_box(
    key: str, m: dict[str, Any], guests: list[dict[str, Any]], cid: str
) -> list[dict[str, Any]]:
    info = m.get("pve") or {}
    running = sum(1 for g in guests if g["status"] == "running")
    bits = [
        m["short"],
        (m["ips"] or [""])[0],
        f"PVE {info['version']}" if info.get("version") else "",
        f"{len(guests)} guests ({running} running)",
    ]
    out: list[dict[str, Any]] = [
        {
            "data": {
                "id": key,
                "key": key,
                "label": "  ·  ".join(b for b in bits if b),
                "kind": "pve-node",
                "role": "group",
                "parent": cid,
                **_card_data(m),
                "pve": info,
                "guest_count": len(guests),
                "running": running,
            }
        },
        {
            "data": {
                "id": f"hub:{key}",
                "key": key,
                "label": m["short"],
                "kind": "pve-hub",
                "parent": key,
                **_card_data(m),
                "pve": info,
            }
        },
    ]
    bridges = {b["name"]: b for b in info.get("bridges") or []}
    for g in guests:
        for n in g["nics"]:
            if n["bridge"] and n["bridge"] not in bridges:
                bridges[n["bridge"]] = {"name": n["bridge"], "cidr": None, "ports": []}
    used = {n["bridge"] for g in guests for n in g["nics"] if n["bridge"]}
    for name, b in sorted(bridges.items()):
        bid = f"br:{key}:{name}"
        sub = b.get("cidr") or ("VLAN-aware" if b.get("vlan_aware") else "")
        out.append(
            {
                "data": {
                    "id": bid,
                    "label": name,
                    "sub": sub,
                    "kind": "bridge",
                    "parent": key,
                    "ports": b.get("ports") or [],
                    "idle": name not in used,
                    "node_key": key,
                }
            }
        )
        out.append(_edge(f"hub:{key}", bid, "trunk"))
    for g in sorted(guests, key=lambda g: g["vmid"] or 0):
        out.append(
            {
                "data": {
                    "id": g["key"],
                    "key": g["key"],
                    "label": g["short"],
                    "kind": g["kind"],
                    "parent": key,
                    **_card_data(g),
                    "nics": g["nics"],
                    "bridge": next((n["bridge"] for n in g["nics"] if n["bridge"]), None),
                }
            }
        )
        wired = False
        for i, n in enumerate(g["nics"]):
            if not n["bridge"]:
                continue
            edge = _edge(f"br:{key}:{n['bridge']}", g["key"], "nic" if i == 0 else "nic2")
            edge["data"]["id"] += f"#{i}"
            if n["vlan"] is not None:
                edge["data"]["label"] = f"VLAN {n['vlan']}"
            out.append(edge)
            wired = True
        if not wired:
            out.append(_edge(f"hub:{key}", g["key"], "trunk"))
    return out


def _is_pve_host(m: dict[str, Any]) -> bool:
    """A Linux host that runs Proxmox VE but has no node data yet (old probe, no sudo)."""
    return m["kind"] == "linux-host" and any(a["name"] == "Proxmox VE" for a in m["apps"])


def proxmox(s: Session, c: Ctx) -> list[dict[str, Any]]:
    """Cluster > node boxes; inside each box the node itself (hub), its bridges and its guests
    wired to the bridge their NIC uses (ADR-031). Other machines get their own box."""
    out: list[dict[str, Any]] = []
    cards = {m["key"]: m for m in machines(s)}
    nodes = {k: m for k, m in cards.items() if m["kind"] == "pve-node" or _is_pve_host(m)}
    guests_of: dict[str, list[dict[str, Any]]] = {k: [] for k in nodes}
    by_name = {m["short"].lower(): k for k, m in nodes.items()}
    for key, m in cards.items():
        if m["kind"] not in ("pve-vm", "pve-lxc"):
            continue
        parent = c.entities[key].parent_key if key in c.entities else None
        parent = parent if parent in nodes else by_name.get(str(m["node"] or "").lower())
        if parent is not None:
            guests_of[parent].append(m)
    clusters: dict[str, list[str]] = {}
    for key in sorted(nodes, key=lambda k: nodes[k]["short"].lower()):
        cname = key.removeprefix("pve:node:").split("/")[0] if key.startswith("pve:") else "Proxmox"
        clusters.setdefault(cname, []).append(key)
    for cname, keys in sorted(clusters.items()):
        cid = f"cluster:{cname}"
        total = sum(len(guests_of[k]) for k in keys)
        out.append(
            {
                "data": {
                    "id": cid,
                    "label": f"{cname}  ·  {len(keys)} nodes  ·  {total} guests",
                    "kind": "pve-cluster",
                    "role": "group",
                }
            }
        )
        for key in keys:
            out.extend(_node_box(key, nodes[key], guests_of[key], cid))
    # Guests whose node is unknown (should not happen; never drop a machine silently).
    placed = {d["data"]["id"] for d in out}
    for key, m in cards.items():
        if m["kind"] in ("pve-vm", "pve-lxc") and key not in placed:
            out.append(
                {
                    "data": {
                        "id": key,
                        "key": key,
                        "label": m["short"],
                        "kind": m["kind"],
                        "parent": "group:other",
                        **_card_data(m),
                    }
                }
            )
    others = [
        m for m in cards.values() if m["kind"] in ("linux-host", "nas") and m["key"] not in nodes
    ]
    if others or any(d["data"].get("parent") == "group:other" for d in out):
        out.append(
            {
                "data": {
                    "id": "group:other",
                    "label": "Other machines",
                    "kind": "group",
                    "role": "group",
                }
            }
        )
        for m in others:
            out.append(
                {
                    "data": {
                        "id": m["key"],
                        "key": m["key"],
                        "label": m["short"],
                        "kind": m["kind"],
                        "parent": "group:other",
                        **_card_data(m),
                    }
                }
            )
    # Containers (shown on request by the UI): children of the machine that runs them.
    machine_ids = {d["data"]["id"] for d in out}
    for key, e in c.entities.items():
        if e.kind != "container" or e.status == "gone":
            continue
        host = canonical_key(c, e.parent_key or "")
        if host in nodes:
            host = f"hub:{host}"  # containers on the hypervisor itself hang off its hub
        if host not in machine_ids:
            continue
        name = (
            e.display_name.split("/")[-2]
            if e.display_name.count("/") >= 3
            else e.display_name.split("/")[-1]
        )
        out.append(
            {
                "data": {
                    "id": key,
                    "key": key,
                    "label": name,
                    "kind": "container",
                    "host": host,
                    "status": e.status,
                }
            }
        )
        out.append(
            {"data": {"id": f"{host}->{key}", "source": host, "target": key, "kind": "runs"}}
        )
    return _dedupe(out)


def logical(c: Ctx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    keep = {
        "pve-cluster",
        "pve-node",
        "pve-vm",
        "pve-lxc",
        "linux-host",
        "compose-project",
        "container",
        "nas",
    }
    for key, e in c.entities.items():
        if e.kind not in keep or e.status == "gone" or e.same_as:
            continue  # same_as hosts are drawn as their VM
        short = e.display_name.split("/")
        label = short[-2] if e.kind == "container" and len(short) > 3 else short[-1]
        out.append(
            _node(c, key, label=label if e.kind in ("container", "compose-project") else None)
        )
        parent = e.parent_key
        if e.kind == "container":
            project = next((v for v in (e.display_name.split("/")[1:2]) if v), None)
            compose = f"compose:{e.parent_key}/{project}" if project else None
            parent = compose if compose in c.entities else e.parent_key
        if parent:
            out.append(_edge(canonical_key(c, parent), key, "contains"))
    ids = {n["data"]["id"] for n in out if "source" not in n["data"]}
    return [
        x
        for x in _dedupe(out)
        if "source" not in x["data"] or (x["data"]["source"] in ids and x["data"]["target"] in ids)
    ]


def vlan(s: Session, c: Ctx) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    rows = ip_table(s)
    nets = sorted(
        {(r["network"], r["vlan"]) for r in rows if r["network"]}, key=lambda n: n[1] or 0
    )
    for name, vid in nets:
        out.append(
            {"data": {"id": f"vlan:{name}", "label": f"{name} (VLAN {vid})", "kind": "vlan"}}
        )
    for r in rows:
        if not r["network"] or r["key"].startswith("unifi:site"):
            continue
        out.append(
            _node(
                c,
                r["key"],
                parent=f"vlan:{r['network']}",
                node_id=f"{r['network']}|{r['key']}",
                label=f"{r['name']}\n{r['ip']}",
            )
        )
    return _dedupe(out)


def _dedupe(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out = []
    for i in items:
        if i["data"]["id"] not in seen:
            seen.add(i["data"]["id"])
            out.append(i)
    return out


def build(s: Session, view: View) -> list[dict[str, Any]]:
    c = context(s)
    c.facets[:] = [f for f in c.facets if f.collector != RECONCILE]
    if view == "physical":
        return physical(c)
    if view == "logical":
        return proxmox(s, c)
    return vlan(s, c)
