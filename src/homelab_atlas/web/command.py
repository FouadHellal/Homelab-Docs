"""Command Center (ADR-039): one page that says what runs, what is down, what is stale.

Everything here is computed from what atlas already stored (facets, collector runs, events,
incidents). No new collection happens on page load. The rules:

* Freshness per (target, collector): **fresh** while the last good run is younger than
  `max(3 x interval, 45 min)`, **stale** after that, **failed** when the latest run failed
  (the last good data is still shown, with its age), **never** when there is no good run.
* A service is **healthy** only on positive evidence from fresh data (unit active, container
  running and not unhealthy, process seen); **degraded** (unhealthy container), **down**
  (failed unit, exited or restarting container), **stale** (the evidence is old) or
  **unknown** (nothing says either way, e.g. a port only, or the machine never answered).
  atlas does not probe services itself: "healthy" means "observed running at the last scan".
* Missing data is never counted as healthy or as zero: counts come with an "unknown" part.
"""

from collections import defaultdict
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from homelab_atlas.engine.apps import CATEGORY_LABELS
from homelab_atlas.models.nas import POOL_NOTE, POOL_OK
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import CollectorRun, Entity, Event, Facet
from homelab_atlas.web.queries import latest_runs
from homelab_atlas.web.views import service_table

MIN_STALE: Final = timedelta(minutes=45)
STALE_FACTOR: Final = 3
#: Disk / storage use from which a mount or pool is called out.
FULL_PCT: Final = 90
GROUPS: Final[Mapping[str, tuple[str, frozenset[str]]]] = {
    "infrastructure": ("Infrastructure", frozenset({"hypervisor", "containers", "system"})),
    "media": ("Media", frozenset({"media"})),
    "networking": ("Networking", frozenset({"dns", "vpn", "proxy", "web", "remote"})),
    "security": ("Security", frozenset({"security"})),
    "automation": ("Automation", frozenset({"automation", "home", "dev"})),
    "storage": ("Storage & data", frozenset({"files", "backup", "database"})),
    "monitoring": ("Monitoring", frozenset({"monitoring", "inventory"})),
}
SERVICE_STATES: Final = ("healthy", "degraded", "down", "stale", "unknown")
HTTPS_PORTS: Final = frozenset({443, 8006, 8007, 8443, 8920, 9443})
#: Apps worth a quick-access tile, in this order, when they exist in the inventory.
QUICK_APPS: Final = (
    "Proxmox VE",
    "Proxmox Backup Server",
    "Pi-hole",
    "AdGuard Home",
    "Home Assistant",
    "Jellyfin",
    "Plex",
    "Zabbix web",
    "Grafana",
    "Uptime Kuma",
    "Portainer",
    "NetBox",
    "Nextcloud",
    "Immich",
    "Vaultwarden",
    "n8n",
    "Node-RED",
    "Cockpit",
    "Webmin",
)
QUICK_LINKS_FILE: Final = "quick-links.yaml"


def group_of(category: str | None) -> str:
    for gid, (_label, cats) in GROUPS.items():
        if category in cats:
            return gid
    return "other"


def _now() -> datetime:
    return datetime.now(UTC)  # the DB hands back aware UTC datetimes (UTCDateTime)


def stale_after(interval_s: int | None) -> timedelta:
    if not interval_s:
        return timedelta(hours=24)  # collector disabled on a schedule: manual scans only
    return max(timedelta(seconds=interval_s * STALE_FACTOR), MIN_STALE)


def freshness(
    s: Session, intervals: Mapping[str, int], now: datetime | None = None
) -> dict[tuple[str, str], dict[str, Any]]:
    """(target, collector) -> {state, status, when, last_ok, age_s, errors}."""
    now = now or _now()
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for target, runs in latest_runs(s).items():
        for r in runs:
            ok = r["last_ok"]
            if ok is None:
                state = "never"
            elif r["status"] in ("failed", "refused"):
                state = "failed"
            elif now - ok > stale_after(intervals.get(r["collector"])):
                state = "stale"
            else:
                state = "fresh"
            out[(target, r["collector"])] = {
                **r,
                "state": state,
                "age_s": int((now - ok).total_seconds()) if ok else None,
            }
    return out


def _worst(states: list[str]) -> str:
    for st in ("failed", "never", "stale", "fresh"):
        if st in states:
            return st
    return "never"


# ------------------------------------------------------------------ summary cards


def _part(label: str, n: int, cls: str, *, count: bool = True) -> dict[str, Any]:
    """A card line. Counts show as "<n> <label>" and only when n > 0; text parts as is."""
    return {"label": label, "n": n, "cls": cls, "count": count}


def summary(
    s: Session, cards: list[dict[str, Any]], fresh: Mapping[tuple[str, str], dict[str, Any]]
) -> list[dict[str, Any]]:
    views = list(facet_views(s.scalars(select(Facet))))
    out: list[dict[str, Any]] = []

    nodes = [v for v in views if v.entity_key.startswith("pve:node:") and v.collector == "proxmox"]
    online = sum(1 for n in nodes if n.data.get("online") is True)
    offline = sum(1 for n in nodes if n.data.get("online") is False)
    out.append(
        {
            "id": "nodes",
            "label": "Proxmox nodes",
            "n": online,
            "total": len(nodes),
            "parts": [
                _part("online", online, "ok"),
                _part("offline", offline, "bad"),
                _part("unknown", len(nodes) - online - offline, "unknown"),
            ],
            "href": "/entities?kind=pve-node",
            "icon": "topology",
        }
    )

    for kind, label, href in (
        ("pve-vm", "Virtual machines", "/entities?kind=pve-vm"),
        ("pve-lxc", "LXC containers", "/entities?kind=pve-lxc"),
    ):
        mine = [c for c in cards if c["kind"] == kind]
        run = sum(1 for c in mine if c["status"] == "running")
        stop = sum(1 for c in mine if c["status"] == "stopped")
        out.append(
            {
                "id": kind,
                "label": label,
                "n": run,
                "total": len(mine),
                "parts": [
                    _part("running", run, "ok"),
                    _part("stopped", stop, "muted"),
                    _part("unknown", len(mine) - run - stop, "unknown"),
                ],
                "href": href,
                "icon": "inventory",
            }
        )

    running = unhealthy = stopped = stale_ctr = 0
    for v in views:
        if v.collector != "docker":
            continue
        is_stale = fresh.get((v.target, "docker"), {}).get("state") != "fresh"
        for c in v.data.get("containers") or []:
            if is_stale:
                stale_ctr += 1
            elif c.get("status") == "running" and c.get("health") == "unhealthy":
                unhealthy += 1
            elif c.get("status") == "running":
                running += 1
            else:
                stopped += 1
    total = running + unhealthy + stopped + stale_ctr
    out.append(
        {
            "id": "containers",
            "label": "Docker containers",
            "n": running,
            "total": total,
            "parts": [
                _part("running", running, "ok"),
                _part("unhealthy", unhealthy, "warn"),
                _part("stopped", stopped, "muted"),
                _part("stale", stale_ctr, "unknown"),
            ],
            "href": "/services?kind=container&state=all",
            "icon": "services",
        }
    )

    devices = [
        v for v in views if v.collector == "unifi" and "mac" in v.data and "radios" in v.data
    ]
    by_type: dict[str, list[Any]] = defaultdict(list)
    for d in devices:
        by_type[device_type(d.data, s, d.entity_key)].append(d)
    up = sum(1 for d in devices if str(d.data.get("state") or "").upper() == "ONLINE")
    down = sum(
        1 for d in devices if d.data.get("state") and str(d.data["state"]).upper() != "ONLINE"
    )
    out.append(
        {
            "id": "network",
            "label": "Network devices",
            "n": up,
            "total": len(devices),
            "parts": [
                _part(f"{len(by_type[t])} {t}", len(by_type[t]), "muted", count=False)
                for t in ("gateway", "switch", "AP")
                if by_type[t]
            ]
            + [_part("offline", down, "bad")]
            if devices
            else [],
            "href": "/topology?view=physical",
            "icon": "ips",
        }
    )

    apps = sorted({a["name"] for c in cards for a in c["apps"] if a["category"] != "system"})
    out.append(
        {
            "id": "apps",
            "label": "Apps found",
            "n": len(apps),
            "total": None,
            "parts": [
                _part(
                    f"on {sum(1 for c in cards if c['documented'])} documented machines",
                    0,
                    "muted",
                    count=False,
                )
            ],
            "href": "/running",
            "icon": "apps",
        }
    )

    st = storage(views)
    full = [x for x in st if x["pct"] is not None and x["pct"] >= FULL_PCT]
    known = [x for x in st if x["pct"] is not None]
    free = sum((x["total"] or 0) - (x["used"] or 0) for x in known)
    out.append(
        {
            "id": "storage",
            "label": "Storage",
            "n": len(known) - len(full),
            "total": len(st),
            "parts": [
                *(
                    [_part(f"{len(full)} over {FULL_PCT}%", len(full), "warn", count=False)]
                    if full
                    else []
                ),
                _part(f"{human_bytes(free)} free", 0, "muted", count=False),
                _part("unknown", len(st) - len(known), "unknown"),
            ],
            "href": "#resources",
            "icon": "exports",
        }
    )

    unknown_dev = (
        s.scalar(
            select(func.count())
            .select_from(Entity)
            .where(Entity.kind == "unknown-device", Entity.status == "unknown")
        )
        or 0
    )
    day = _now() - timedelta(hours=24)
    new_dev = (
        s.scalar(
            select(func.count())
            .select_from(Entity)
            .where(
                Entity.kind == "unknown-device",
                Entity.status == "unknown",
                Entity.first_seen >= day,
            )
        )
        or 0
    )
    out.append(
        {
            "id": "unknown",
            "label": "Unknown devices",
            "n": unknown_dev,
            "total": None,
            "parts": [_part(f"{new_dev} new today", new_dev, "warn", count=False)]
            if new_dev
            else [],
            "href": "/unknown",
            "icon": "unknown",
        }
    )
    return out


def device_type(data: Mapping[str, Any], s: Session, key: str) -> str:
    feats = {str(f).lower() for f in data.get("features") or []}
    if "accesspoint" in feats or data.get("radios"):
        return "AP"
    e = s.get(Entity, key)
    if e is not None and (e.parent_key or "").startswith("unifi:site:"):
        return "gateway"
    if "switching" in feats or len(data.get("ports") or []) > 1:
        return "switch"
    return "device"


def human_bytes(n: int | float | None) -> str:
    if n is None:
        return "?"
    v = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(v) < 1024 or unit == "PB":
            return f"{v:.0f} {unit}" if unit in ("B", "KB") else f"{v:.1f} {unit}"
        v /= 1024
    return "?"


def storage(views: list[Any]) -> list[dict[str, Any]]:
    """Every storage atlas knows the capacity of: NAS pools, Proxmox storages, Linux mounts
    (local disks and network shares). pct None = size unknown."""
    out: list[dict[str, Any]] = []

    def add(kind: str, where: str, name: str, total: Any, used: Any, *, href: str) -> None:
        t = total if isinstance(total, int) and total > 0 else None
        u = used if isinstance(used, int) and used >= 0 else None
        out.append(
            {
                "kind": kind,
                "where": where,
                "name": name,
                "total": t,
                "used": u,
                "pct": round(u * 100 / t) if t and u is not None else None,
                "href": href,
            }
        )

    for v in views:
        href = f"/entity?key={v.entity_key}"
        if v.collector == "nas":
            for p in v.data.get("pools") or []:
                add(
                    "NAS pool",
                    v.data.get("name") or "NAS",
                    f"pool {p.get('id')}",
                    p.get("capacity_bytes"),
                    p.get("used_bytes"),
                    href=href,
                )
        elif v.collector == "proxmox" and v.entity_key.startswith("pve:node:"):
            for st in v.data.get("storages") or []:
                add(
                    "Proxmox storage",
                    v.data.get("name") or "?",
                    str(st.get("storage")),
                    st.get("total_bytes"),
                    st.get("used_bytes"),
                    href=href,
                )
        elif v.collector == "linux-ssh":
            for m in v.data.get("mounts") or []:
                if m.get("fstype") in ("tmpfs", "devtmpfs", "overlay", "squashfs", "vfat"):
                    continue
                kind = "Network share" if m.get("fstype") in NETWORK_FS else "Disk"
                add(
                    kind,
                    v.target,
                    str(m.get("target")),
                    m.get("size_bytes"),
                    m.get("used_bytes"),
                    href=href,
                )
    return sorted(out, key=lambda x: -(x["pct"] or -1))


NETWORK_FS: Final = frozenset({"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p"})


# ------------------------------------------------------------------ services


def services(
    s: Session, cards: list[dict[str, Any]], fresh: Mapping[tuple[str, str], dict[str, Any]]
) -> list[dict[str, Any]]:
    """One row per recognised app per machine, with an evidence-backed state."""
    rows_by_key: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in service_table(s, state="all")["rows"]:
        rows_by_key[r["key"]].append(r)
    out = []
    for m in cards:
        target = m.get("target")
        fr = fresh.get((target, "linux-ssh"), {}) if target else {}
        dk = fresh.get((target, "docker"), {}) if target else {}
        for a in m["apps"]:
            if a["category"] == "system":
                continue
            mine = [r for r in rows_by_key.get(m["key"], []) if r["app"] == a["name"]]
            state, why = app_state(a, mine, fr, dk)
            ip = (m["ips"] or [None])[0]
            web = a.get("web_port")
            out.append(
                {
                    "name": a["name"],
                    "machine": m["short"],
                    "key": m["key"],
                    "ip": ip,
                    "ports": a.get("ports") or [],
                    "category": a["category"],
                    "category_label": a.get("category_label")
                    or CATEGORY_LABELS.get(a["category"], ""),
                    "group": group_of(a["category"]),
                    "state": state,
                    "why": why,
                    "observed": fr.get("last_ok") or dk.get("last_ok"),
                    "source": "SSH scan"
                    + (" + Docker" if any(r["type"] == "container" for r in mine) else ""),
                    "url": (
                        f"{'https' if web in HTTPS_PORTS else 'http'}://{ip}:{web}"
                        if web and ip
                        else None
                    ),
                }
            )
    return sorted(out, key=lambda r: (SERVICE_STATES.index(r["state"]), r["name"].lower()))


def app_state(
    app: Mapping[str, Any],
    rows: list[dict[str, Any]],
    ssh: Mapping[str, Any],
    docker: Mapping[str, Any],
) -> tuple[str, str]:
    states = {r["state"] for r in rows}
    unhealthy = any("unhealthy" in str(r.get("sub")) for r in rows if r["type"] == "container")
    freshness_states = [x for x in (ssh.get("state"), docker.get("state")) if x]
    if not freshness_states or set(freshness_states) <= {"never"}:
        return "unknown", "atlas has not read this machine successfully yet"
    if "fresh" not in freshness_states:
        return "stale", "last observation is older than the scan interval allows"
    if "failed" in states:
        return "down", "a unit or container for it failed"
    if unhealthy:
        return "degraded", "its container reports unhealthy"
    if "running" in states or any(e.startswith("process ") for e in app.get("evidence") or []):
        return "healthy", "observed running at the last scan"
    if states and states <= {"inactive"}:
        return "down", "its unit or container is not running"
    return "unknown", "only a listening port or a name points to it"


# ------------------------------------------------------------------ attention, resources


def issues(
    s: Session,
    cards: list[dict[str, Any]],
    fresh: Mapping[tuple[str, str], dict[str, Any]],
    svc: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Ongoing problems, as of the latest data (as opposed to the change timeline)."""
    out: list[dict[str, Any]] = []
    for (target, coll), f in sorted(fresh.items()):
        if f["state"] in ("failed", "never") and f["status"] != "ok":
            out.append(
                {
                    "sev": "warning",
                    "title": f"{target}: {coll} {f['status']}",
                    "detail": "; ".join(f["errors"][:2]) or "no detail reported",
                    "href": "/targets",
                    "since": f["when"],
                }
            )
        elif f["state"] == "stale":
            out.append(
                {
                    "sev": "notice",
                    "title": f"{target}: {coll} data is stale",
                    "detail": "the last good scan is older than expected",
                    "href": "/targets",
                    "since": f["last_ok"],
                }
            )
    for r in svc:
        if r["state"] in ("down", "degraded"):
            out.append(
                {
                    "sev": "warning" if r["state"] == "down" else "notice",
                    "title": f"{r['name']} {r['state']} on {r['machine']}",
                    "detail": r["why"],
                    "href": f"/app?name={r['name']}",
                    "since": r["observed"],
                }
            )
    views = list(facet_views(s.scalars(select(Facet))))
    for v in views:
        if v.collector == "unifi" and "radios" in v.data:
            st = str(v.data.get("state") or "")
            if st and st.upper() != "ONLINE":
                out.append(
                    {
                        "sev": "warning",
                        "title": f"{v.data.get('name')} is {st.lower()}",
                        "detail": "UniFi reports this device offline",
                        "href": f"/entity?key={v.entity_key}",
                        "since": None,
                    }
                )
        elif v.collector == "proxmox" and v.entity_key.startswith("pve:node:"):
            if v.data.get("online") is False:
                out.append(
                    {
                        "sev": "warning",
                        "title": f"Proxmox node {v.data.get('name')} offline",
                        "detail": "reported by the cluster",
                        "since": None,
                        "href": f"/entity?key={v.entity_key}",
                    }
                )
        elif v.collector == "nas":
            for p in v.data.get("pools") or []:
                if p.get("status") and p["status"] not in POOL_OK:
                    note = p["status"] in POOL_NOTE
                    out.append(
                        {
                            "sev": "notice" if note else "warning",
                            "title": f"NAS pool {p.get('id')}: "
                            + ("no data protection (no redundancy)" if note else p["status"]),
                            "detail": v.data.get("name") or "",
                            "since": None,
                            "href": f"/entity?key={v.entity_key}",
                        }
                    )
    for x in storage(views):
        if x["pct"] is not None and x["pct"] >= FULL_PCT:
            out.append(
                {
                    "sev": "notice",
                    "title": f"{x['name']} on {x['where']} is {x['pct']}% full",
                    "detail": f"{human_bytes((x['total'] or 0) - (x['used'] or 0))} free",
                    "href": x["href"],
                    "since": None,
                }
            )
    rank = {"warning": 0, "notice": 1, "info": 2}
    return sorted(out, key=lambda i: (rank.get(i["sev"], 3), i["title"]))


def resources(s: Session) -> dict[str, Any]:
    """Point-in-time figures from the last scans. Not a time series, and labelled as such."""
    views = list(facet_views(s.scalars(select(Facet))))
    nodes: list[dict[str, Any]] = []
    guests: list[dict[str, Any]] = []
    for v in views:
        if v.collector != "proxmox":
            continue
        d = v.data
        if v.entity_key.startswith("pve:node:"):
            nodes.append(
                {
                    "name": d.get("name"),
                    "key": v.entity_key,
                    "cpu": _pct(d.get("cpu_load")),
                    "cores": d.get("cpu_cores"),
                    "memory": d.get("memory_bytes"),
                    "uptime_s": d.get("uptime_s"),
                    "online": d.get("online"),
                }
            )
        elif "vmid" in d and d.get("status") == "running":
            guests.append(
                {
                    "name": d.get("name"),
                    "key": v.entity_key,
                    "node": d.get("node"),
                    "cpu": _pct(d.get("cpu_load")),
                    "cores": d.get("cores"),
                    "memory_mb": d.get("memory_mb"),
                }
            )
    guests = sorted((g for g in guests if g["cpu"] is not None), key=lambda g: -g["cpu"])[:8]
    return {
        "nodes": sorted(nodes, key=lambda n: str(n["name"])),
        "busiest": guests,
        "storage": storage(views)[:12],
    }


def _pct(v: Any) -> float | None:
    return round(v * 100, 1) if isinstance(v, int | float) and not isinstance(v, bool) else None


# ------------------------------------------------------------------ quick access, timeline


def quick_links(
    cards: list[dict[str, Any]],
    unifi_urls: list[str],
    data_dir: Path | None,
    extra: Mapping[str, str] | None = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name in QUICK_APPS:
        for m in cards:
            a = next((x for x in m["apps"] if x["name"] == name and x.get("web_port")), None)
            ip = (m["ips"] or [None])[0]
            if a is None or not ip:
                continue
            web = a["web_port"]
            url = f"{'https' if web in HTTPS_PORTS else 'http'}://{ip}:{web}"
            if url not in seen:
                seen.add(url)
                out.append(
                    {"name": name, "where": m["short"], "url": url, "category": a["category"]}
                )
    for u in unifi_urls:
        out.insert(0, {"name": "UniFi", "where": "gateway", "url": u, "category": "dns"})
    for name, url in (extra or {}).items():
        if url not in seen:
            out.insert(1, {"name": "Jellyfin", "where": name, "url": url, "category": "media"})
    for pin in pinned_links(data_dir):
        out.insert(0, {**pin, "where": "pinned", "category": "custom"})
    return out[:24]


def pinned_links(data_dir: Path | None) -> list[dict[str, str]]:
    """`<data dir>/quick-links.yaml`: [{name: ..., url: https://...}] chosen by the owner."""
    if data_dir is None:
        return []
    path = data_dir / QUICK_LINKS_FILE
    try:
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            return []
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return []
    out = []
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        name, url = item.get("name"), item.get("url")
        if not (isinstance(name, str) and isinstance(url, str)):
            continue
        if not url.startswith(("https://", "http://")) or "@" in url.split("/", 3)[2]:
            continue  # no other schemes, no credentials in links
        out.append({"name": name[:48], "url": url[:512]})
    return out[:12]


def timeline(
    s: Session,
    *,
    hours: int = 24,
    severity: str | None = None,
    q: str | None = None,
    limit: int = 40,
) -> list[dict[str, Any]]:
    since = _now() - timedelta(hours=hours)
    stmt = (
        select(Event, Entity.display_name)
        .join(Entity, Entity.key == Event.entity_key, isouter=True)
        .where(Event.created_at >= since)
        .order_by(Event.id.desc())
    )
    if severity in ("warning", "notice", "info"):
        stmt = stmt.where(Event.severity == severity)
    if q:
        like = f"%{q[:64]}%"
        stmt = stmt.where(
            Event.summary.ilike(like) | Event.type.ilike(like) | Entity.display_name.ilike(like)
        )
    return [
        {"e": e, "name": n or e.entity_key, "group": e.type.split(".")[0]}
        for e, n in s.execute(stmt.limit(limit)).all()
    ]


def overall(
    fresh: Mapping[tuple[str, str], dict[str, Any]], issues_: list[dict[str, Any]]
) -> dict[str, Any]:
    states = [f["state"] for f in fresh.values()]
    last_ok = max((f["last_ok"] for f in fresh.values() if f["last_ok"]), default=None)
    warnings = sum(1 for i in issues_ if i["sev"] == "warning")
    if not states:
        level, text = "unknown", "Nothing scanned yet"
    elif warnings:
        level, text = "bad", f"{warnings} problem{'s' if warnings != 1 else ''} need attention"
    elif "stale" in states or "failed" in states:
        level, text = "warn", "Some data is stale"
    else:
        level, text = "ok", "All good as of the last scans"
    return {
        "level": level,
        "text": text,
        "last_ok": last_ok,
        "fresh": states.count("fresh"),
        "stale": states.count("stale"),
        "failed": states.count("failed") + states.count("never"),
        "total": len(states),
    }


def integrations(
    s: Session, fresh: Mapping[tuple[str, str], dict[str, Any]], configured: Mapping[str, list[str]]
) -> list[dict[str, Any]]:
    """Data sources: configured or not, and how their last scans went."""
    labels = {
        "proxmox": "Proxmox VE",
        "unifi": "UniFi",
        "nas": "UniFi UNAS",
        "jellyfin": "Jellyfin",
        "linux-ssh": "Machines (SSH)",
        "docker": "Docker",
    }
    out = []
    for coll, label in labels.items():
        names = configured.get(coll, [])
        states = [f["state"] for (t, c), f in fresh.items() if c == coll]
        last = max(
            (f["last_ok"] for (t, c), f in fresh.items() if c == coll and f["last_ok"]),
            default=None,
        )
        out.append(
            {
                "id": coll,
                "label": label,
                "configured": bool(names),
                "targets": len(names),
                "state": _worst(states) if names else "off",
                "last_ok": last,
                "counts": {
                    st: states.count(st)
                    for st in ("fresh", "stale", "failed", "never")
                    if st in states
                },
            }
        )
    return out


def last_run_id(s: Session) -> int:
    return int(s.scalar(select(func.max(CollectorRun.id))) or 0)
