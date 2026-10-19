"""Cytoscape element lists for the topology views (SPEC §10, ADR-030).

* proxmox (`logical`): cluster box > one box per PVE node > its VMs/LXCs as tiles (each = the
  machine inside, with apps/services/containers); containers as children on request; other
  machines (Pi, NAS, bare-metal Linux) in their own box. Guests of nodes atlas does not log in
  to come from a node's /etc/pve view and are marked "not documented".
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
    }


def proxmox(s: Session, c: Ctx) -> list[dict[str, Any]]:
    """Cluster > nodes > guests, plus other machines. Containers are children of their machine."""
    out: list[dict[str, Any]] = []
    cards = {m["key"]: m for m in machines(s)}
    clusters: dict[str, str] = {}
    for key, m in cards.items():
        if m["kind"] != "pve-node":
            continue
        cname = key.removeprefix("pve:node:").split("/")[0]
        cid = clusters.setdefault(cname, f"cluster:{cname}")
        out.append(
            {"data": {"id": cid, "label": f"{cname}", "kind": "pve-cluster", "role": "group"}}
        )
        out.append(
            {
                "data": {
                    "id": key,
                    "key": key,
                    "label": m["short"],
                    "kind": "pve-node",
                    "role": "group",
                    "parent": cid,
                    **_card_data(m),
                }
            }
        )
    nodes_by_name = {k.split("/")[-1]: k for k, m in cards.items() if m["kind"] == "pve-node"}
    for key, m in cards.items():
        if m["kind"] not in ("pve-vm", "pve-lxc"):
            continue
        parent = c.entities[key].parent_key if key in c.entities else None
        parent = parent if parent in cards else nodes_by_name.get(m["node"] or "")
        out.append(
            {
                "data": {
                    "id": key,
                    "key": key,
                    "label": m["short"],
                    "kind": m["kind"],
                    "parent": parent,
                    **_card_data(m),
                }
            }
        )
    # Guests of nodes atlas does not log in to, from any node's /etc/pve view (ADR-028).
    present = {d["data"]["id"] for d in out}
    for f in c.facets:
        pve = f.data.get("pve") if f.collector == "linux-ssh" else None
        if not isinstance(pve, dict):
            continue
        cname = str(pve.get("cluster") or pve.get("node") or "pve")
        cid = clusters.setdefault(cname, f"cluster:{cname}")
        if cid not in present:
            out.append(
                {"data": {"id": cid, "label": cname, "kind": "pve-cluster", "role": "group"}}
            )
            present.add(cid)
        for g in pve.get("cluster_guests") or []:
            gkey = f"pve:{'vm' if g.get('type') == 'qemu' else 'lxc'}:{cname}/{g.get('vmid')}"
            nkey = f"pve:node:{cname}/{g.get('node')}"
            if nkey not in present:
                out.append(
                    {
                        "data": {
                            "id": nkey,
                            "key": nkey,
                            "label": g.get("node"),
                            "kind": "pve-node",
                            "role": "group",
                            "parent": cid,
                            "documented": False,
                            "status": "unscanned",
                        }
                    }
                )
                present.add(nkey)
            if gkey in present:
                continue
            out.append(
                {
                    "data": {
                        "id": gkey,
                        "label": g.get("name"),
                        "kind": "pve-vm" if g.get("type") == "qemu" else "pve-lxc",
                        "parent": nkey,
                        "vmid": g.get("vmid"),
                        "node": g.get("node"),
                        "documented": False,
                        "status": "unscanned",
                        "apps": [],
                        "services": 0,
                        "containers": 0,
                    }
                }
            )
            present.add(gkey)
    others = [m for m in cards.values() if m["kind"] in ("linux-host", "nas")]
    if others:
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
