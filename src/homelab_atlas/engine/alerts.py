"""Alert rules (ADR-047): what becomes an incident, and so a Taskora ticket or a message.

A *rule type* is a detector over data atlas already holds (facets, collector runs, entities),
with typed parameters. A *rule* is an instance of a type: enabled or not, a severity, its
parameters, which machines it applies to, and whether its incidents open a Taskora ticket and
send an n8n message. Built-in rules exist for every type (their ids are the historical incident
kinds, so existing incidents keep their keys); the owner can change them and add their own in
`<data>/alerts.yaml` from the Alerts page. Incident keys are `<rule id>:<subject>`.

Detectors read facts only. Facts from a collector whose latest run failed are stale and never
open or keep an incident: the source failure is the incident instead.
"""

import fnmatch
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas.engine import media
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.nas import POOL_NOTE, POOL_OK
from homelab_atlas.store.facets import FacetView, facet_views
from homelab_atlas.store.tables import CollectorRun, Entity, Facet

Severity = Literal["info", "notice", "warning"]
RULES_FILE: Final = "alerts.yaml"
RULE_ID_RE: Final = r"^[a-z][a-z0-9.-]{1,47}$"
SOURCE_FAILURES: Final = 2
API_COLLECTORS: Final = {"proxmox": "Proxmox API", "unifi": "UniFi", "nas": "NAS"}
PSEUDO_FS: Final = frozenset(
    {
        "tmpfs",
        "devtmpfs",
        "squashfs",
        "overlay",
        "ramfs",
        "iso9660",
        "efivarfs",
        "proc",
        "sysfs",
        "cgroup2",
        "autofs",
        "nsfs",
        "tracefs",
        "fuse.lxcfs",
        "fuse.snapfuse",
    }
)
PSEUDO_PREFIXES: Final = ("/snap/", "/run", "/dev", "/sys", "/proc", "/var/lib/docker/")
CATEGORIES: Final = {
    "system": "Machines",
    "proxmox": "Proxmox",
    "containers": "Containers",
    "network": "Network",
    "security": "Security",
    "storage": "Storage & media",
    "atlas": "atlas itself",
}


@dataclass(frozen=True, slots=True)
class Condition:
    key: str
    kind: str
    title: str
    severity: str
    entity_key: str | None
    evidence: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a detector found. `host` is what a rule's machine filter matches."""

    subject: str
    title: str
    entity_key: str | None = None
    evidence: tuple[str, ...] = ()
    host: str | None = None
    severity: Severity | None = None  # a detector may escalate (e.g. disk at 95 %)


@dataclass(frozen=True, slots=True)
class Param:
    name: str
    label: str
    kind: Literal["int", "list"]
    default: int | list[str]
    lo: int = 0
    hi: int = 1_000_000
    help: str = ""


# ------------------------------------------------------------------ evaluation scope


@dataclass(slots=True)
class Scope:
    s: Session
    inv: Inventory
    intervals: Mapping[str, int]
    now: datetime
    _views: list[FacetView] | None = None
    _runs: dict[tuple[str, str], list[CollectorRun]] | None = None
    _media: list[media.Diagnosis] | None = None

    @property
    def runs(self) -> dict[tuple[str, str], list[CollectorRun]]:
        if self._runs is None:
            out: dict[tuple[str, str], list[CollectorRun]] = {}
            q = select(CollectorRun).order_by(CollectorRun.id.desc()).limit(4000)
            for r in self.s.scalars(q):
                lst = out.setdefault((r.target, r.collector), [])
                if len(lst) < SOURCE_FAILURES:
                    lst.append(r)
            self._runs = out
        return self._runs

    @property
    def failing(self) -> set[tuple[str, str]]:
        return {k for k, rs in self.runs.items() if rs and rs[0].status in ("failed", "refused")}

    @property
    def views(self) -> list[FacetView]:
        """Fresh facts only: a collector whose latest run failed contributes nothing."""
        if self._views is None:
            failing = self.failing
            self._views = [
                v
                for v in facet_views(self.s.scalars(select(Facet)))
                if (v.target, v.collector) not in failing
            ]
        return self._views

    def of(self, collector: str) -> list[FacetView]:
        return [v for v in self.views if v.collector == collector]

    @property
    def media(self) -> list[media.Diagnosis]:
        if self._media is None:
            self._media = [
                media.diagnose(self.s, self.inv, src, self.intervals, self.now)
                for src in self.inv.sources.jellyfin
            ]
        return self._media


Detector = Callable[[Scope, Mapping[str, Any]], list[Finding]]


@dataclass(frozen=True, slots=True)
class RuleType:
    id: str
    category: str
    label: str
    description: str
    severity: Severity
    detect: Detector
    params: tuple[Param, ...] = ()
    enabled: bool = True


# ------------------------------------------------------------------ detectors


def _media_down(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(d.source, d.headline, f"jellyfin:{d.source}", _media_ev(d), d.host)
        for d in sc.media
        if d.status == "down"
    ]


def _media_storage(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(d.source, d.headline, f"jellyfin:{d.source}", _media_ev(d), d.host)
        for d in sc.media
        if d.condition in (4, 5) and any(c.id == "mounts" and c.state == "fail" for c in d.checks)
    ]


def _media_space(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    out = []
    pct = {src.name: src.min_free_pct for src in sc.inv.sources.jellyfin}
    for d in sc.media:
        low = [x for x in d.storage if x.get("low")]
        if low:
            out.append(
                Finding(
                    d.source,
                    f"Media storage for {d.source} below {pct.get(d.source, 10)}% free",
                    f"jellyfin:{d.source}",
                    tuple(f"{x['mount']}: {x['free_pct']}% free" for x in low),
                    d.host,
                )
            )
    return out


def _media_ev(d: media.Diagnosis) -> tuple[str, ...]:
    return tuple(f"{c.label}: {c.state} - {c.detail}" for c in d.checks if c.state != "pass")


def _host_unreachable(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    need = int(p.get("failures", 2))
    out = []
    for h in sc.inv.hosts:
        if "linux-ssh" not in h.collectors:
            continue
        runs = list(
            sc.s.scalars(
                select(CollectorRun)
                .where(CollectorRun.target == h.name, CollectorRun.collector == "linux-ssh")
                .order_by(CollectorRun.id.desc())
                .limit(need)
            )
        )
        if len(runs) == need and all(r.status == "failed" for r in runs):
            errs = tuple(str(e) for e in (runs[0].errors or [])[:3])
            out.append(Finding(h.name, f"{h.name} does not answer SSH", None, errs, h.name))
    return out


def _source_failed(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    out = []
    for (target, collector), rs in sorted(sc.runs.items()):
        label = API_COLLECTORS.get(collector)
        if label is None or len(rs) < SOURCE_FAILURES:
            continue
        if all(r.status in ("failed", "refused") for r in rs):
            errs = tuple(str(e)[:300] for e in (rs[0].errors or [])[:3])
            why = f": {errs[0]}" if errs else ""
            out.append(
                Finding(
                    f"{collector}:{target}",
                    f"{label} source {target} fails{why}"[:256],
                    None,
                    errs,
                    target,
                )
            )
    return out


def _nas_pool(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            f"{v.target}:{pl.get('id')}",
            f"NAS pool {pl.get('id')} is {pl['status']}",
            v.entity_key,
            (),
            v.target,
        )
        for v in sc.of("nas")
        for pl in v.data.get("pools") or []
        if pl.get("status") and pl["status"] not in POOL_OK | POOL_NOTE
    ]


def _guests(sc: Scope) -> list[FacetView]:
    return [v for v in sc.of("proxmox") if "vmid" in v.data and not v.data.get("template")]


def _guest_label(d: Mapping[str, Any]) -> str:
    return f"{'LXC' if d.get('type') == 'lxc' else 'VM'} {d.get('name')} ({d.get('vmid')})"


def _guest_stopped(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            v.entity_key,
            f"{_guest_label(v.data)} stopped, set to start at boot",
            v.entity_key,
            (f"node {v.data.get('node')}: status stopped, onboot=1",),
            str(v.data.get("name")),
        )
        for v in _guests(sc)
        if v.data.get("onboot") and v.data.get("status") == "stopped"
    ]


def _guest_no_backup(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            v.entity_key,
            f"{_guest_label(v.data)} is not in any backup job",
            v.entity_key,
            (f"node {v.data.get('node')}",),
            str(v.data.get("name")),
        )
        for v in _guests(sc)
        if v.data.get("backed_up") is False
    ]


def _guest_memory(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    pct = int(p.get("pct", 95))
    out = []
    for v in _guests(sc):
        used, total = v.data.get("mem_used_bytes"), v.data.get("mem_max_bytes")
        if v.data.get("status") != "running" or not isinstance(used, int):
            continue
        if not isinstance(total, int) or total <= 0 or used * 100 // total < pct:
            continue
        out.append(
            Finding(
                v.entity_key,
                f"{_guest_label(v.data)} uses {used * 100 // total}% of its RAM",
                v.entity_key,
                (f"{used >> 20} MiB of {total >> 20} MiB",),
                str(v.data.get("name")),
            )
        )
    return out


def _pve_storage(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    pct = int(p.get("pct", 90))
    out = []
    for v in sc.of("proxmox"):
        if "vmid" in v.data:
            continue
        for st in v.data.get("storages") or []:
            used, total = st.get("used_bytes"), st.get("total_bytes")
            if isinstance(used, int) and isinstance(total, int) and total > 0:
                now_pct = used * 100 // total
                if now_pct >= pct:
                    node = v.data.get("name")
                    out.append(
                        Finding(
                            f"{node}:{st.get('storage')}",
                            f"Proxmox storage {st.get('storage')} on {node} is {now_pct}% full",
                            v.entity_key,
                            (f"{used >> 30} GiB of {total >> 30} GiB",),
                            str(node),
                            "warning" if now_pct >= 95 else None,
                        )
                    )
    return out


def _pve_node_offline(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            str(v.data.get("name")),
            f"Proxmox node {v.data.get('name')} is offline",
            v.entity_key,
            (),
            str(v.data.get("name")),
        )
        for v in sc.of("proxmox")
        if "vmid" not in v.data and v.data.get("online") is False
    ]


RESTART_LOOP: Final = 5


def _containers(sc: Scope) -> list[tuple[FacetView, dict[str, Any]]]:
    return [
        (v, c)
        for v in sc.of("docker")
        for c in v.data.get("containers") or []
        if isinstance(c, dict)
    ]


def _container_down(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    loop = int(p.get("restarts", RESTART_LOOP))
    out = []
    for v, c in _containers(sc):
        status, health = c.get("status"), c.get("health")
        raw = c.get("restart_count")
        restarts = raw if isinstance(raw, int) else 0
        exited_bad = (
            status == "exited"
            and isinstance(c.get("exit_code"), int)
            and c["exit_code"] != 0
            and (c.get("restart_policy") or "") in ("always", "unless-stopped")
        )
        looping = status == "restarting" or (restarts >= loop and status != "running")
        if health == "unhealthy" or looping or exited_bad:
            what = (
                "unhealthy"
                if health == "unhealthy"
                else "restarting"
                if looping
                else f"exited with code {c.get('exit_code')}"
            )
            out.append(
                Finding(
                    f"{v.target}/{c.get('name')}",
                    f"Container {c.get('name')} on {v.target} is {what}"[:256],
                    v.entity_key,
                    (
                        f"image {c.get('image')}",
                        f"status {status}, health {health or 'n/a'}, restarts {restarts}",
                    ),
                    v.target,
                )
            )
    return out


def _container_privileged(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    out = []
    for v, c in _containers(sc):
        why = [
            w
            for w, on in (
                ("privileged", c.get("privileged")),
                ("mounts the Docker socket", c.get("docker_socket")),
            )
            if on
        ]
        if why:
            out.append(
                Finding(
                    f"{v.target}/{c.get('name')}",
                    f"Container {c.get('name')} on {v.target} {' and '.join(why)}",
                    v.entity_key,
                    (f"image {c.get('image')}",),
                    v.target,
                )
            )
    return out


def _container_latest(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            f"{v.target}/{c.get('name')}",
            f"Container {c.get('name')} on {v.target} runs an unpinned image",
            v.entity_key,
            (f"image {c.get('image')}",),
            v.target,
        )
        for v, c in _containers(sc)
        if str(c.get("image") or "").endswith(":latest") or ":" not in str(c.get("image") or ":")
    ]


def full_mounts(mounts: list[Any], pct: int = 90) -> list[tuple[str, int]]:
    """(mount point, % used) of real filesystems at `pct` or more."""
    out = []
    for m in mounts:
        if not isinstance(m, dict):
            continue
        target, fstype = str(m.get("target") or ""), str(m.get("fstype") or "")
        size, used = m.get("size_bytes"), m.get("used_bytes")
        if fstype in PSEUDO_FS or target.startswith(PSEUDO_PREFIXES) or not target:
            continue
        if (
            isinstance(size, int)
            and size > 0
            and isinstance(used, int)
            and used * 100 // size >= pct
        ):
            out.append((target, used * 100 // size))
    return out


def _disk_full(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    pct, warn = int(p.get("pct", 90)), int(p.get("warning_pct", 95))
    return [
        Finding(
            f"{v.target}:{target}",
            f"{target} on {v.target} is {used}% full",
            v.entity_key,
            (f"{target}: {used}% used",),
            v.target,
            "warning" if used >= warn else None,
        )
        for v in sc.of("linux-ssh")
        for target, used in full_mounts(v.data.get("mounts") or [], pct)
    ]


def _service_failed(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    ignore = [str(x) for x in p.get("ignore") or []]
    out = []
    for v in sc.of("linux-ssh"):
        for svc in v.data.get("services") or []:
            unit = str(svc.get("unit") or "")
            if svc.get("active") == "failed" and not any(fnmatch.fnmatch(unit, g) for g in ignore):
                out.append(
                    Finding(
                        f"{v.target}:{unit}",
                        f"Service {unit} failed on {v.target}",
                        v.entity_key,
                        (str(svc.get("description") or ""),),
                        v.target,
                    )
                )
    return out


def _extra_root(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            f"{v.target}:{u.get('name')}",
            f"{v.target}: account {u.get('name')} has uid 0 (root)",
            v.entity_key,
            (f"shell {u.get('shell')}, home {u.get('home')}",),
            v.target,
        )
        for v in sc.of("linux-ssh")
        for u in v.data.get("users") or []
        if u.get("uid") == 0 and u.get("name") != "root"
    ]


def _unexpected_port(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    allowed = {int(x) for x in p.get("allowed") or [] if str(x).isdigit()}
    out = []
    for v in sc.of("linux-ssh"):
        for sk in v.data.get("sockets") or []:
            addr, port = str(sk.get("address") or ""), sk.get("port")
            if sk.get("proto") != "tcp" or not isinstance(port, int) or port in allowed:
                continue
            if addr in ("0.0.0.0", "::", "*", "[::]"):  # noqa: S104 - matching, not binding
                out.append(
                    Finding(
                        f"{v.target}:tcp/{port}",
                        f"{v.target} listens on tcp/{port} on every interface",
                        v.entity_key,
                        (f"process {sk.get('process') or '?'}",),
                        v.target,
                    )
                )
    return out


def _unifi_devices(sc: Scope) -> list[FacetView]:
    return [v for v in sc.of("unifi") if v.data.get("mac") and "clients" not in v.data]


def _unifi_offline(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            str(v.data["mac"]),
            f"UniFi {v.data.get('name')} is {str(v.data.get('state')).lower()}",
            v.entity_key,
            (f"model {v.data.get('model')}, IP {v.data.get('ip')}",),
            str(v.data.get("name")),
        )
        for v in _unifi_devices(sc)
        if str(v.data.get("state") or "ONLINE").upper() not in ("ONLINE", "")
    ]


def _unknown_device(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    vlans = {int(x) for x in p.get("vlans") or [] if str(x).isdigit()}
    out = []
    for e in sc.s.scalars(
        select(Entity).where(Entity.kind == "unknown-device", Entity.status == "unknown")
    ):
        f = sc.s.get(Facet, (e.key, "reconcile"))
        d = f.data if f is not None else {}
        if vlans and d.get("vlan") not in vlans:
            continue
        out.append(
            Finding(
                e.key.removeprefix("net:mac:"),
                f"Unknown device {d.get('name') or e.display_name} ({d.get('ip') or 'no IP'}) on "
                f"{d.get('network') or 'the network'}",
                e.key,
                tuple(str(r) for r in d.get("reasons") or [])[:3],
                d.get("name"),
            )
        )
    return out


def _weak_wifi(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    floor = -int(p.get("dbm", 75))
    out = []
    for v in sc.of("unifi"):
        for cl in v.data.get("clients") or []:
            sig = cl.get("signal_dbm")
            if isinstance(sig, int) and sig < floor:
                name = cl.get("name") or cl.get("hostname") or cl.get("mac")
                out.append(
                    Finding(
                        str(cl.get("mac")),
                        f"Weak Wi-Fi for {name}: {sig} dBm",
                        None,
                        (f"SSID {cl.get('ssid')}, channel {cl.get('channel')}",),
                        str(name),
                    )
                )
    return out


def _k8s_pods(sc: Scope, p: Mapping[str, Any]) -> list[Finding]:
    restarts = int(p.get("restarts", 5))
    out = []
    for v in sc.of("kubernetes"):
        for pod in v.data.get("pods") or []:
            bad = (
                pod.get("reason")
                in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "OOMKilled", "Error")
                or pod.get("phase") == "Failed"
            )
            n = pod.get("restarts")
            if bad or (isinstance(n, int) and n >= restarts and not pod.get("ready")):
                ns, name = pod.get("namespace"), pod.get("name")
                out.append(
                    Finding(
                        f"{v.target}/{ns}/{pod.get('owner') or name}",
                        f"Pod {ns}/{name} on {v.target}: {pod.get('reason') or pod.get('phase')}",
                        v.entity_key,
                        (f"node {pod.get('node')}, restarts {pod.get('restarts')}",),
                        v.target,
                    )
                )
    return out


def _k8s_nodes(sc: Scope, _p: Mapping[str, Any]) -> list[Finding]:
    return [
        Finding(
            f"{v.target}/{n.get('name')}",
            f"Kubernetes node {n.get('name')} is not ready",
            v.entity_key,
            tuple(str(x) for x in n.get("problems") or [])[:3],
            v.target,
        )
        for v in sc.of("kubernetes")
        for n in v.data.get("nodes") or []
        if n.get("ready") is False
    ]


TYPES: Final[tuple[RuleType, ...]] = (
    RuleType(
        "host.unreachable",
        "system",
        "Machine unreachable",
        "A machine's SSH scan failed several times in a row.",
        "warning",
        _host_unreachable,
        (Param("failures", "Failed scans in a row", "int", 2, 1, 20),),
    ),
    RuleType(
        "disk.full",
        "system",
        "Disk nearly full",
        "A real filesystem (not snaps, overlays or RAM disks) is above the threshold.",
        "notice",
        _disk_full,
        (
            Param("pct", "Notice at % used", "int", 90, 1, 100),
            Param("warning_pct", "Warning at % used", "int", 95, 1, 100),
        ),
    ),
    RuleType(
        "service.failed",
        "system",
        "systemd service failed",
        "A unit is in the failed state.",
        "notice",
        _service_failed,
        (
            Param(
                "ignore",
                "Ignore units (globs)",
                "list",
                ["fwupd-refresh.service", "systemd-networkd-wait-online.service"],
            ),
        ),
        enabled=False,
    ),
    RuleType(
        "source.failed",
        "atlas",
        "Data source failing",
        "A Proxmox, UniFi or NAS API source failed twice in a row: atlas is blind there.",
        "warning",
        _source_failed,
    ),
    RuleType(
        "guest.stopped",
        "proxmox",
        "Guest stopped",
        "A VM or LXC set to start at boot is not running.",
        "warning",
        _guest_stopped,
    ),
    RuleType(
        "pve.node",
        "proxmox",
        "Proxmox node offline",
        "The cluster reports a node offline.",
        "warning",
        _pve_node_offline,
    ),
    RuleType(
        "pve.storage",
        "proxmox",
        "Proxmox storage nearly full",
        "A storage pool of a node is above the threshold.",
        "notice",
        _pve_storage,
        (Param("pct", "Alert at % used", "int", 90, 1, 100),),
    ),
    RuleType(
        "guest.memory",
        "proxmox",
        "Guest out of memory",
        "A running guest uses most of its RAM.",
        "notice",
        _guest_memory,
        (Param("pct", "Alert at % of RAM", "int", 95, 1, 100),),
        enabled=False,
    ),
    RuleType(
        "guest.backup",
        "proxmox",
        "Guest without backup",
        "A VM or LXC is in no backup job.",
        "notice",
        _guest_no_backup,
        enabled=False,
    ),
    RuleType(
        "container.down",
        "containers",
        "Container down",
        "A container is unhealthy, crash-looping, or exited with an error under an "
        "always/unless-stopped policy.",
        "warning",
        _container_down,
        (Param("restarts", "Restarts that count as a loop", "int", 5, 1, 1000),),
    ),
    RuleType(
        "container.privileged",
        "security",
        "Privileged container",
        "A container runs privileged or mounts the Docker socket (root on the host).",
        "notice",
        _container_privileged,
        enabled=False,
    ),
    RuleType(
        "container.latest",
        "containers",
        "Unpinned image",
        "A container runs an image tagged :latest (updates arrive unannounced).",
        "info",
        _container_latest,
        enabled=False,
    ),
    RuleType(
        "security.root",
        "security",
        "Extra root account",
        "An account other than root has uid 0.",
        "warning",
        _extra_root,
    ),
    RuleType(
        "security.port",
        "security",
        "Unexpected open port",
        "A TCP port listens on every interface and is not in the allowed list.",
        "notice",
        _unexpected_port,
        (Param("allowed", "Allowed ports", "list", ["22", "80", "443", "8006", "9100"]),),
        enabled=False,
    ),
    RuleType(
        "unifi.offline",
        "network",
        "UniFi device offline",
        "A gateway, switch or access point is not online.",
        "warning",
        _unifi_offline,
    ),
    RuleType(
        "network.unknown",
        "network",
        "Unknown device",
        "A device on the network that no machine or annotation explains.",
        "notice",
        _unknown_device,
        (Param("vlans", "Only these VLANs (empty: all)", "list", []),),
        enabled=False,
    ),
    RuleType(
        "wifi.weak",
        "network",
        "Weak Wi-Fi signal",
        "A wireless client's signal is below the threshold.",
        "info",
        _weak_wifi,
        (Param("dbm", "Below -dBm", "int", 75, 40, 100),),
        enabled=False,
    ),
    RuleType(
        "nas.pool",
        "storage",
        "NAS pool degraded",
        "A NAS pool is not fully operational.",
        "warning",
        _nas_pool,
    ),
    RuleType(
        "media.down",
        "storage",
        "Jellyfin down",
        "The Jellyfin diagnosis says the server or its machine is down.",
        "warning",
        _media_down,
    ),
    RuleType(
        "media.storage",
        "storage",
        "Media storage missing",
        "Jellyfin runs but its library is not on mounted network storage.",
        "warning",
        _media_storage,
    ),
    RuleType(
        "media.space",
        "storage",
        "Media storage low",
        "A media mount is below its free-space threshold.",
        "notice",
        _media_space,
    ),
    RuleType(
        "k8s.pod",
        "containers",
        "Kubernetes pod failing",
        "A pod crash-loops, cannot pull its image, was OOM-killed or failed.",
        "warning",
        _k8s_pods,
        (Param("restarts", "Restarts while not ready", "int", 5, 1, 1000),),
    ),
    RuleType(
        "k8s.node",
        "containers",
        "Kubernetes node not ready",
        "A cluster node reports NotReady.",
        "warning",
        _k8s_nodes,
    ),
)
BY_TYPE: Final = {t.id: t for t in TYPES}


# ------------------------------------------------------------------ rules


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=RULE_ID_RE)
    name: str = Field(min_length=1, max_length=80)
    type: str
    enabled: bool = True
    severity: Severity = "notice"
    params: dict[str, int | list[str]] = Field(default_factory=dict)
    #: Machine/source names this rule applies to (globs, comma-separated; "*" = all).
    match: str = Field(default="*", max_length=200)
    exclude: str = Field(default="", max_length=200)
    ticket: bool = True
    notify: bool = True
    builtin: bool = False

    @field_validator("type")
    @classmethod
    def _known(cls, v: str) -> str:
        if v not in BY_TYPE:
            raise ValueError(f"unknown rule type {v!r}")
        return v

    def clean_params(self) -> dict[str, int | list[str]]:
        """Parameters of this rule's type, defaults filled in, out-of-range values clamped."""
        out: dict[str, int | list[str]] = {}
        for p in BY_TYPE[self.type].params:
            raw = self.params.get(p.name, p.default)
            if p.kind == "int":
                n = raw if isinstance(raw, int) else p.default
                out[p.name] = max(p.lo, min(p.hi, n)) if isinstance(n, int) else p.lo
            else:
                items = raw if isinstance(raw, list) else []
                out[p.name] = [str(x).strip()[:64] for x in items if str(x).strip()][:50]
        return out

    def applies_to(self, host: str | None) -> bool:
        if host is None:
            return self.match.strip() in ("", "*")
        name = host.lower()
        inc = [g.strip().lower() for g in self.match.split(",") if g.strip()] or ["*"]
        exc = [g.strip().lower() for g in self.exclude.split(",") if g.strip()]
        return any(fnmatch.fnmatch(name, g) for g in inc) and not any(
            fnmatch.fnmatch(name, g) for g in exc
        )


def builtin_rules() -> list[Rule]:
    return [
        Rule(id=t.id, name=t.label, type=t.id, enabled=t.enabled, severity=t.severity, builtin=True)
        for t in TYPES
    ]


_path: Path | None = None


def configure(path: Path | None) -> None:
    """Where the owner's rules live (`<data>/alerts.yaml`); None = built-ins only."""
    global _path  # noqa: PLW0603 - one process-wide setting, like apps.configure_custom
    _path = path


def load_rules(path: Path | None = None) -> list[Rule]:
    """Built-in rules with the owner's changes applied, then the owner's own rules."""
    path = path if path is not None else _path
    rules = {r.id: r for r in builtin_rules()}
    raw: Any = None
    if path is not None and path.is_file():
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            raw = None
    for item in (raw or {}).get("rules") or [] if isinstance(raw, dict) else []:
        if not isinstance(item, dict):
            continue
        base = rules.get(str(item.get("id")))
        try:
            merged = {
                **(base.model_dump() if base else {}),
                **item,
                "builtin": base is not None and base.builtin,
            }
            rule = Rule.model_validate(merged)
        except ValidationError:
            continue
        rules[rule.id] = rule
    return list(rules.values())


def save_rules(path: Path, rules: list[Rule]) -> None:
    """Store only what differs from the built-ins, plus custom rules."""
    defaults = {r.id: r.model_dump() for r in builtin_rules()}
    out = []
    for r in rules:
        d = r.model_dump(exclude={"builtin"})
        base = defaults.get(r.id)
        if base is None:
            out.append(d)
        else:
            diff = {k: v for k, v in d.items() if base.get(k) != v}
            if diff:
                out.append({"id": r.id, **diff})
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(yaml.safe_dump({"rules": out}, sort_keys=False, allow_unicode=True), "utf-8")
    tmp.replace(path)


def new_rule_id(name: str, taken: set[str]) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "rule"
    base = base if re.fullmatch(r"[a-z].*", base) else f"r-{base}"
    rid, n = base, 2
    while rid in taken:
        rid, n = f"{base}-{n}", n + 1
    return rid


def rule_for_key(key: str, rules: list[Rule] | None = None) -> Rule | None:
    rid = key.split(":", 1)[0]
    return next((r for r in (rules if rules is not None else load_rules()) if r.id == rid), None)


@dataclass(slots=True)
class Preview:
    rule: Rule
    findings: list[Finding] = field(default_factory=list)


def evaluate(
    s: Session,
    inv: Inventory,
    intervals: Mapping[str, int],
    now: datetime,
    rules: list[Rule] | None = None,
    *,
    include_disabled: bool = False,
) -> list[Preview]:
    """Run every (enabled) rule. A detector that breaks never stops the others."""
    sc = Scope(s, inv, intervals, now)
    out = []
    for rule in rules if rules is not None else load_rules():
        if not rule.enabled and not include_disabled:
            continue
        try:
            found = BY_TYPE[rule.type].detect(sc, rule.clean_params())
        except Exception:  # noqa: BLE001 - one broken detector must not hide the rest
            found = []
        out.append(Preview(rule, [f for f in found if rule.applies_to(f.host)]))
    return out


def conditions(
    s: Session,
    inv: Inventory,
    intervals: Mapping[str, int],
    now: datetime,
    rules: list[Rule] | None = None,
) -> list[Condition]:
    out: dict[str, Condition] = {}
    for p in evaluate(s, inv, intervals, now, rules):
        for f in p.findings:
            key = f"{p.rule.id}:{f.subject}"[:128]
            sev = f.severity if f.severity and p.rule.builtin else p.rule.severity
            out.setdefault(
                key,
                Condition(key, p.rule.type, f.title[:256], sev, f.entity_key, f.evidence[:20]),
            )
    return list(out.values())
