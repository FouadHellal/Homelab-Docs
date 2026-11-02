"""Media diagnosis (ADR-040): why is Jellyfin (not) working, from evidence atlas holds.

Inputs, all already collected: the Jellyfin API run, the Jellyfin machine's SSH scan (mounts,
services, containers), Proxmox's view of that VM/LXC, and the UniFi UNAS run. Nothing is
probed live here, and nothing is ever restarted or remounted.

Each check is pass / warn / fail / unknown with the evidence behind it. The verdict names a
cause only when the checks support it; otherwise it says what failed and what is unknown.
A library folder only counts as "on the NAS" when the longest mount containing it is a
network filesystem: a folder that exists on the local disk (share not mounted) fails.
"""

import ipaddress
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from homelab_atlas.inventory.hosts import Inventory, JellyfinSource
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import CollectorRun, Entity, Facet, Scan

CheckState = Literal["pass", "warn", "fail", "unknown"]
NETWORK_FS: Final = frozenset({"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p"})
#: Fresh while the last good run is younger than this many intervals (and at least 45 min).
STALE_FACTOR: Final = 3
MIN_STALE: Final = timedelta(minutes=45)
CONDITIONS: Final = {
    0: "healthy",
    1: "Jellyfin API unreachable",
    2: "Jellyfin machine unavailable",
    3: "machine up, Jellyfin service down",
    4: "media storage missing or inaccessible",
    5: "NAS unavailable",
    6: "network or DNS may be involved",
    7: "data is stale",
    8: "not enough evidence",
}


@dataclass(slots=True)
class Check:
    id: str
    label: str
    state: CheckState
    detail: str
    href: str | None = None


@dataclass(slots=True)
class Diagnosis:
    source: str
    status: Literal["healthy", "degraded", "down", "stale", "unknown"]
    condition: int
    headline: str
    explanation: str
    checks: list[Check] = field(default_factory=list)
    host: str | None = None
    host_key: str | None = None
    storage: list[dict[str, Any]] = field(default_factory=list)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.checks if c.state == "fail"]


@dataclass(slots=True)
class RunInfo:
    status: str | None
    last_ok: datetime | None
    when: datetime | None
    errors: list[str]

    def state(self, interval_s: int | None, now: datetime) -> str:
        if self.status is None:
            return "never"
        if self.status in ("failed", "refused"):
            return "failed"
        if self.last_ok is None:
            return "never"
        limit = max(timedelta(seconds=(interval_s or 8 * 3600) * STALE_FACTOR), MIN_STALE)
        return "stale" if now - self.last_ok > limit else "fresh"


def run_info(s: Session, target: str, collector: str) -> RunInfo:
    last = s.execute(
        select(CollectorRun, Scan.finished_at)
        .join(Scan, Scan.id == CollectorRun.scan_id)
        .where(CollectorRun.target == target, CollectorRun.collector == collector)
        .order_by(CollectorRun.id.desc())
        .limit(1)
    ).first()
    ok = s.scalar(
        select(func.max(Scan.finished_at))
        .join(CollectorRun, CollectorRun.scan_id == Scan.id)
        .where(
            CollectorRun.target == target,
            CollectorRun.collector == collector,
            CollectorRun.status.in_(("ok", "partial")),
        )
    )
    if last is None:
        return RunInfo(None, None, None, [])
    run, when = last
    return RunInfo(run.status, ok, when, [str(e) for e in (run.errors or [])][:4])


def jellyfin_host(inv: Inventory, src: JellyfinSource) -> str | None:
    """The atlas machine target running Jellyfin: configured, or found by the URL's IP."""
    if src.host:
        return src.host
    host = urlsplit(src.url).hostname or ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    for h in inv.hosts:
        if h.address == host or (ip is not None and h.address == str(ip)):
            return h.name
    return None


def mount_for(path: str, mounts: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """The mount a path lives on: the longest mount target that is a prefix of it."""
    best: Mapping[str, Any] | None = None
    for m in mounts:
        t = str(m.get("target") or "")
        if not t:
            continue
        inside = path == t or path.startswith(t.rstrip("/") + "/") or t == "/"
        if inside and (best is None or len(t) > len(str(best.get("target")))):
            best = m
    return best


def _age(dt: datetime | None, now: datetime) -> str:
    if dt is None:
        return "never"
    secs = int((now - dt).total_seconds())
    for unit, n in (("d", 86400), ("h", 3600), ("min", 60)):
        if secs >= n:
            return f"{secs // n} {unit} ago"
    return "just now"


def diagnose(
    s: Session,
    inv: Inventory,
    src: JellyfinSource,
    intervals: Mapping[str, int],
    now: datetime | None = None,
) -> Diagnosis:
    now = now or datetime.now(UTC)
    checks: list[Check] = []
    api = run_info(s, src.name, "jellyfin")
    api_state = api.state(intervals.get("jellyfin"), now)
    facet = s.get(Facet, (f"jellyfin:{src.name}", "jellyfin"))
    jf: dict[str, Any] = dict(facet.data) if facet is not None else {}
    if api_state == "fresh":
        checks.append(
            Check(
                "api",
                "Jellyfin API answers",
                "pass",
                f"version {jf.get('version') or '?'}, checked {_age(api.last_ok, now)}",
            )
        )
    elif api_state == "failed":
        checks.append(
            Check(
                "api",
                "Jellyfin API answers",
                "fail",
                "; ".join(api.errors) or "the last check failed",
                "/targets",
            )
        )
    elif api_state == "stale":
        checks.append(
            Check(
                "api",
                "Jellyfin API answers",
                "warn",
                f"last good check {_age(api.last_ok, now)}: too old to rely on",
            )
        )
    else:
        checks.append(Check("api", "Jellyfin API answers", "unknown", "never checked yet"))

    host = jellyfin_host(inv, src)
    ssh = run_info(s, host, "linux-ssh") if host else RunInfo(None, None, None, [])
    ssh_state = ssh.state(intervals.get("linux-ssh"), now) if host else "never"
    lx: dict[str, Any] = {}
    dk: dict[str, Any] = {}
    host_key = None
    if host:
        for f in s.scalars(select(Facet).where(Facet.target == host)):
            if f.collector == "linux-ssh" and "os" in f.data:
                lx, host_key = dict(f.data), f.entity_key
            elif f.collector == "docker" and "containers" in f.data:
                dk = dict(f.data)
    if not host:
        checks.append(
            Check(
                "host",
                "Jellyfin machine answers SSH",
                "unknown",
                "no atlas target runs Jellyfin: set `host:` on the Jellyfin source "
                "or add the machine on Targets",
                "/targets",
            )
        )
    elif ssh_state == "fresh":
        checks.append(
            Check(
                "host",
                "Jellyfin machine answers SSH",
                "pass",
                f"{host} scanned {_age(ssh.last_ok, now)}",
            )
        )
    elif ssh_state == "failed":
        checks.append(
            Check(
                "host",
                "Jellyfin machine answers SSH",
                "fail",
                f"{host}: " + ("; ".join(ssh.errors) or "scan failed"),
                "/targets",
            )
        )
    elif ssh_state == "stale":
        checks.append(
            Check(
                "host",
                "Jellyfin machine answers SSH",
                "warn",
                f"{host}: last good scan {_age(ssh.last_ok, now)}",
            )
        )
    else:
        checks.append(
            Check(
                "host",
                "Jellyfin machine answers SSH",
                "unknown",
                f"{host} was never scanned successfully",
                "/targets",
            )
        )

    vm_status = _guest_status(s, host_key)
    if vm_status == "running":
        checks.append(Check("vm", "Proxmox runs the VM/LXC", "pass", "status running"))
    elif vm_status in ("stopped", "paused"):
        checks.append(Check("vm", "Proxmox runs the VM/LXC", "fail", f"status {vm_status}"))
    else:
        checks.append(
            Check(
                "vm",
                "Proxmox runs the VM/LXC",
                "unknown",
                "not linked to a Proxmox guest (bare metal, or no Proxmox data)",
            )
        )

    svc_state, svc_detail = _service(lx, dk) if lx or dk else ("unknown", "no scan of the machine")
    checks.append(Check("service", "Jellyfin service / container runs", svc_state, svc_detail))

    storage, st_state, st_detail = _storage(jf, lx, src.min_free_pct)
    checks.append(
        Check("mounts", "Library folders are on mounted network storage", st_state, st_detail)
    )
    space = [x for x in storage if x.get("low")]
    if space:
        checks.append(
            Check(
                "space",
                "Free space on media storage",
                "warn",
                ", ".join(f"{x['mount']} {x['free_pct']}% free" for x in space),
            )
        )
    task = next((t for t in jf.get("tasks") or [] if t.get("name") == "Scan Media Library"), None)
    if task and task.get("last_status") == "Failed":
        checks.append(
            Check(
                "library",
                "Last library scan",
                "warn",
                f"failed: {task.get('last_error') or 'no message'}",
            )
        )
    elif task and task.get("last_status"):
        checks.append(Check("library", "Last library scan", "pass", str(task["last_status"])))

    nas = [_nas(s, n.name, intervals, now) for n in inv.sources.unas]
    if nas:
        bad = [n for n in nas if n[0] == "fail"]
        checks.append(
            Check("nas", "NAS answers", "fail" if bad else nas[0][0], "; ".join(n[1] for n in nas))
        )
    else:
        checks.append(Check("nas", "NAS answers", "unknown", "no UniFi UNAS configured"))

    d = _verdict(src.name, checks)
    d.host, d.host_key, d.storage = host, host_key, storage
    return d


def _guest_status(s: Session, host_key: str | None) -> str | None:
    if host_key is None:
        return None
    e = s.get(Entity, host_key)
    guest = e.same_as if e is not None else None
    if not guest or not guest.startswith(("pve:vm:", "pve:lxc:")):
        return None
    views = facet_views(s.scalars(select(Facet).where(Facet.entity_key == guest)))
    data = next((v.data for v in views if v.collector == "proxmox"), {})
    status = data.get("status")
    return str(status) if status else None


def _service(lx: Mapping[str, Any], dk: Mapping[str, Any]) -> tuple[CheckState, str]:
    units = [u for u in lx.get("services") or [] if str(u.get("unit", "")).startswith("jellyfin")]
    ctrs = [c for c in dk.get("containers") or [] if "jellyfin" in str(c.get("image", "")).lower()]
    if any(u.get("active") == "active" for u in units):
        return "pass", "unit " + ", ".join(str(u["unit"]) for u in units) + " active"
    if any(c.get("status") == "running" for c in ctrs):
        bad = [c for c in ctrs if c.get("health") == "unhealthy"]
        if bad:
            return "warn", f"container {bad[0].get('name')} running but unhealthy"
        return "pass", "container " + ", ".join(str(c.get("name")) for c in ctrs) + " running"
    if units or ctrs:
        what = [str(u["unit"]) for u in units] + [str(c.get("name")) for c in ctrs]
        return "fail", "found but not running: " + ", ".join(what)
    return "unknown", "no jellyfin unit or container seen (installed differently?)"


def _storage(
    jf: Mapping[str, Any], lx: Mapping[str, Any], min_free_pct: int
) -> tuple[list[dict[str, Any]], CheckState, str]:
    folders = [loc for lib in jf.get("libraries") or [] for loc in lib.get("locations") or []]
    if not folders:
        return [], "unknown", "Jellyfin reported no library folders (yet)"
    mounts = list(lx.get("mounts") or [])
    if not mounts:
        return [], "unknown", "no mount table for the Jellyfin machine (not scanned over SSH)"
    rows: list[dict[str, Any]] = []
    for path in folders:
        m = mount_for(path, mounts)
        fstype = str(m.get("fstype")) if m else None
        size, avail = (m.get("size_bytes"), m.get("avail_bytes")) if m else (None, None)
        free_pct = (
            round(avail * 100 / size)
            if isinstance(size, int) and size and isinstance(avail, int)
            else None
        )
        rows.append(
            {
                "folder": path,
                "mount": str(m.get("target")) if m else "?",
                "source": m.get("source") if m else None,
                "fstype": fstype,
                "network": fstype in NETWORK_FS,
                "size": size,
                "avail": avail,
                "free_pct": free_pct,
                "low": free_pct is not None and free_pct < min_free_pct,
                "readable": size is not None,
            }
        )
    local = [r for r in rows if not r["network"]]
    unread = [r for r in rows if r["network"] and not r["readable"]]
    if local:
        r = local[0]
        return (
            rows,
            "fail",
            (
                f"{r['folder']} is on {r['mount']} ({r['fstype'] or '?'}), not on a network share: "
                "the NAS share looks unmounted (the folder exists on the local disk)"
            ),
        )
    if unread:
        return (
            rows,
            "warn",
            f"{unread[0]['mount']} is mounted but its size could not be read "
            "(stale or hung mount?)",
        )
    mounts_seen = sorted({f"{r['mount']} ({r['fstype']})" for r in rows})
    return rows, "pass", "on " + ", ".join(mounts_seen)


def _nas(
    s: Session, name: str, intervals: Mapping[str, int], now: datetime
) -> tuple[CheckState, str]:
    info = run_info(s, name, "nas")
    st = info.state(intervals.get("nas"), now)
    if st == "fresh":
        return "pass", f"{name} answered {_age(info.last_ok, now)}"
    if st == "failed":
        return "fail", f"{name}: " + ("; ".join(info.errors) or "check failed")
    if st == "stale":
        return "warn", f"{name}: last answer {_age(info.last_ok, now)}"
    return "unknown", f"{name}: never checked"


def _verdict(source: str, checks: list[Check]) -> Diagnosis:
    by = {c.id: c.state for c in checks}
    api, host, vm, svc = by.get("api"), by.get("host"), by.get("vm"), by.get("service")
    mounts, nas = by.get("mounts"), by.get("nas")

    def d(status: Any, cond: int, headline: str, why: str) -> Diagnosis:
        return Diagnosis(source, status, cond, headline, why, checks)

    if api == "fail":
        if vm == "fail":
            return d(
                "down",
                2,
                "The Jellyfin VM/LXC is not running",
                "Proxmox reports it stopped; the API failing follows from that.",
            )
        if host == "fail" and vm == "pass":
            return d(
                "down",
                6,
                "Jellyfin and its machine do not answer, but Proxmox runs it",
                "Network, DNS, a firewall or a hung guest are likely; atlas cannot tell "
                "which from here.",
            )
        if host == "fail":
            return d(
                "down",
                2,
                "The Jellyfin machine does not answer",
                "Neither the API nor SSH answered. Whether the machine is off or the "
                "network is at fault is unknown (no Proxmox data for it).",
            )
        if host == "pass" and svc == "fail":
            return d(
                "down",
                3,
                "The machine is up but the Jellyfin service is not running",
                "SSH works and the jellyfin unit/container was seen stopped.",
            )
        if host == "pass":
            return d(
                "down",
                1,
                "The Jellyfin API does not answer although its machine is up",
                "Check the API key, the port and the service logs. The service state at "
                "the last scan: " + next(c.detail for c in checks if c.id == "service"),
            )
        return d(
            "down",
            1,
            "The Jellyfin API does not answer",
            "The machine's state is unknown, so the cause cannot be narrowed down.",
        )
    if mounts == "fail":
        if nas == "fail":
            return d(
                "degraded",
                5,
                "Media storage is missing and the NAS does not answer",
                "Jellyfin runs, but its library folders are not on the NAS share, and the "
                "NAS itself failed its last check.",
            )
        return d(
            "degraded",
            4,
            "Jellyfin runs, but its media storage is not mounted",
            next(c.detail for c in checks if c.id == "mounts"),
        )
    if api == "warn" or host == "warn":
        return d(
            "stale",
            7,
            "Jellyfin looked fine, but the data is stale",
            "Recent scans are missing; this is the last known state, not the current one.",
        )
    if api == "unknown":
        return d(
            "unknown",
            8,
            "Not enough evidence yet",
            "The Jellyfin API has not been checked. Add it on Targets or wait for a scan.",
        )
    if mounts == "warn" or any(c.state == "warn" for c in checks):
        warn = next(c for c in checks if c.state == "warn")
        return d(
            "degraded",
            4 if warn.id in ("mounts", "space") else 0,
            f"Jellyfin runs: {warn.label.lower()} needs a look",
            warn.detail,
        )
    if api == "pass":
        unknown = [c.label for c in checks if c.state == "unknown"]
        why = "Every check that could run passed." + (
            f" Not verified: {', '.join(unknown)}." if unknown else ""
        )
        if mounts == "pass":
            return d("healthy", 0, "Jellyfin is up and its media storage is mounted", why)
        return d("healthy", 0, "Jellyfin is up (media storage not verified)", why)
    return d("unknown", 8, "Not enough evidence", "Some checks could not run.")
