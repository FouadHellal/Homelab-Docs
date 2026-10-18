"""Typed events derived from diffs (SPEC §8).

Rules are explicit, so `atlas diff` says "port tcp/8443 opened" instead of listing JSON paths.
Anything no rule claims is folded into one `facts.changed` event per entity.
"""

import fnmatch
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Final, Literal

from homelab_atlas.engine.diff import Change

Severity = Literal["info", "notice", "warning"]

KEY_PACKAGES: Final = (
    "openssh-server",
    "sudo",
    "docker-ce",
    "docker.io",
    "containerd.io",
    "linux-image-*",
    "proxmox-ve",
    "pve-manager",
    "proxmox-kernel-*",
    "pve-kernel-*",
    "systemd",
    "openssl",
    "libssl3*",
    "libc6",
    "qemu-guest-agent",
    "nginx",
    "nginx-*",
    "apache2",
    "postgresql-*",
    "mariadb-server",
    "unattended-upgrades",
    "wireguard",
    "wireguard-tools",
    "tailscale",
    "raspberrypi-kernel",
    "linux-image-rpi*",
    "bash",
    "curl",
)
PRIVILEGED_GROUPS: Final = frozenset({"sudo", "wheel", "docker", "adm", "root", "lxd", "disk"})


@dataclass(frozen=True, slots=True)
class EventSpec:
    entity_key: str
    type: str
    severity: Severity
    summary: str
    path: str = ""
    old: Any = None
    new: Any = None


def is_key_package(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pat) for pat in KEY_PACKAGES)


def _sock(v: dict[str, Any]) -> str:
    proc = f" ({v['process']})" if v.get("process") else ""
    return f"{v.get('proto')}/{v.get('port')} on {v.get('address')}{proc}"


def linux_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    """Map linux-ssh fact changes to events. `name` is the inventory host name."""
    out: list[EventSpec] = []
    unclaimed: list[Change] = []
    other_pkgs: dict[str, int] = defaultdict(int)
    cron: dict[str, list[str]] = defaultdict(list)

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p, k = c.path, c.kind
        head = p[0]
        if head == "sockets" and len(p) == 2 and k in ("added", "removed"):
            v = c.new if k == "added" else c.old
            if k == "added":
                ev("port.opened", "notice", f"port {_sock(v)} opened", c)
            else:
                ev("port.closed", "info", f"port {_sock(v)} closed", c)
        elif head == "sockets" and p[-1] == "process":
            ev("port.owner_changed", "notice", f"{p[1]} now owned by {c.new} (was {c.old})", c)
        elif head == "services" and len(p) == 2:
            unit = p[1]
            ev(
                f"service.{k}" if k != "changed" else "service.changed",
                "info",
                f"service {unit} {k}",
                c,
            )
        elif head == "services" and p[-1] == "active":
            unit = p[1]
            if c.new == "failed":
                ev("service.failed", "warning", f"service {unit} failed (was {c.old})", c)
            elif c.old == "failed":
                ev("service.recovered", "info", f"service {unit} recovered ({c.new})", c)
            else:
                ev("service.state_changed", "info", f"service {unit} {c.old} -> {c.new}", c)
        elif head == "services" and p[-1] == "enabled":
            verb = (
                "enabled" if c.new == "enabled" else "disabled" if c.old == "enabled" else "changed"
            )
            ev(f"service.{verb}", "notice", f"service {p[1]} {c.old} -> {c.new}", c)
        elif head == "packages":
            pkg = p[1]
            if is_key_package(pkg):
                if k == "changed":
                    ev("package.upgraded", "notice", f"{pkg} {c.old} -> {c.new}", c)
                elif k == "added":
                    ev("package.installed", "notice", f"{pkg} {c.new['version']} installed", c)
                else:
                    ev("package.removed", "notice", f"{pkg} removed", c)
            else:
                other_pkgs[k] += 1
        elif p == ("os", "kernel"):
            ev("kernel.changed", "notice", f"kernel {c.old} -> {c.new}", c)
        elif p in (("os", "os_version_id"), ("os", "os_codename")):
            ev("os.upgraded", "notice", f"OS {p[1]} {c.old} -> {c.new}", c)
        elif p == ("os", "hostname"):
            ev("host.renamed", "warning", f"hostname {c.old} -> {c.new}", c)
        elif head == "interfaces" and len(p) == 4 and p[2] == "addresses" and k != "changed":
            ip = p[3]
            ev(
                "ip.added" if k == "added" else "ip.removed",
                "notice",
                f"{ip} {'added to' if k == 'added' else 'removed from'} {p[1]}",
                c,
            )
        elif head == "interfaces" and len(p) == 2:
            ev(f"interface.{k}", "info", f"interface {p[1]} {k}", c)
        elif head == "interfaces" and p[-1] == "mac":
            ev("interface.mac_changed", "warning", f"{p[1]} MAC {c.old} -> {c.new}", c)
        elif head == "routes" and len(p) == 2:
            v = c.new if k == "added" else c.old
            if isinstance(v, dict) and v.get("dst") == "default":
                ev(
                    "route.default_changed",
                    "warning",
                    f"default route via {v.get('gateway')} {k}",
                    c,
                )
            else:
                ev(f"route.{k}", "info", f"route {p[1]} {k}", c)
        elif head == "mounts" and len(p) == 2:
            ev(f"mount.{k}", "info", f"mount {p[1]} {k}", c)
        elif head == "users" and len(p) == 2:
            if k == "added":
                ev("user.added", "warning", f"local user {p[1]} (uid {c.new['uid']}) added", c)
            else:
                ev("user.removed", "info", f"local user {p[1]} removed", c)
        elif head == "users" and len(p) == 4 and p[2] == "groups":
            group = p[3]
            sev: Severity = "warning" if group in PRIVILEGED_GROUPS else "notice"
            verb = "joined" if k == "added" else "left"
            ev("user.groups_changed", sev, f"user {p[1]} {verb} group {group}", c)
        elif head == "cron" and len(p) == 2:
            source = p[1].split("|", 1)[0]
            cron[source].append(k)
        elif head in ("nameservers", "search_domains"):
            ev("dns.changed", "notice", f"{head} {c.dotted.split('.', 1)[-1]} {k}", c)
        elif p == ("probe", "version"):
            ev("probe.updated", "info", f"probe {c.old} -> {c.new}", c)
        elif p == ("probe", "matches"):
            if c.new is False:
                ev("probe.mismatch", "warning", "installed probe hash does not match", c)
        elif head == "probe":
            pass  # hash churn accompanies probe.updated / probe.mismatch
        else:
            unclaimed.append(c)

    for source, kinds in sorted(cron.items()):
        counts = ", ".join(f"{kinds.count(x)} {x}" for x in ("added", "removed") if x in kinds)
        out.append(
            EventSpec(
                key, "cron.changed", "notice", f"{name}: cron {source}: {counts}", f"cron.{source}"
            )
        )
    if other_pkgs:
        total = sum(other_pkgs.values())
        detail = ", ".join(f"{n} {k}" for k, n in sorted(other_pkgs.items()))
        out.append(
            EventSpec(
                key,
                "packages.changed",
                "info",
                f"{name}: {total} other packages changed ({detail})",
                "packages",
            )
        )
    if unclaimed:
        fields = sorted(
            {c.path[0] if len(c.path) == 1 else ".".join(c.path[:2]) for c in unclaimed}
        )
        out.append(
            EventSpec(
                key,
                "facts.changed",
                "info",
                f"{name}: {len(unclaimed)} other changes in {', '.join(fields[:8])}",
                ",".join(fields[:8]),
            )
        )
    return out
