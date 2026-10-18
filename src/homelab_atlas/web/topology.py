"""Cytoscape element lists for the three topology views (SPEC §10).

* physical: UniFi site > gateway > switches > APs, clients hung off their uplink device;
* logical:  PVE cluster > nodes > guests (= the Linux host inside) > compose projects > containers;
* vlan:     one compound node per UniFi network, members by IP address.
Labels are data; cytoscape renders them as text, never as HTML.
"""

from typing import Any, Literal

from sqlalchemy.orm import Session

from homelab_atlas.engine.reconcile import RECONCILE
from homelab_atlas.web.queries import Ctx, canonical_key, context, ip_table

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
                out.append(_node(c, key, label=c.names.get(key, cl.get("name") or mac), kind=ckind))
                present.add(key)
            uplink = f"unifi:dev:{cl.get('uplink_mac')}"
            if uplink in present:
                out.append(
                    _edge(uplink, key, "wireless" if cl.get("type") == "WIRELESS" else "wired")
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
        return logical(c)
    return vlan(s, c)
