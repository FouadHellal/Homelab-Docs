"""Proxmox change events: migrations, power state, sizing, NICs/VLANs, backups, upgrades."""

from collections import defaultdict

from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity


def proxmox_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []
    grouped: dict[str, int] = defaultdict(int)
    unclaimed: list[Change] = []
    status_changed = any(c.path == ("status",) for c in changes)

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p, k = c.path, c.kind
        head = p[0]
        # ---------------------------------------------------------- guests
        if p == ("node",):
            ev("guest.migrated", "notice", f"migrated {c.old} -> {c.new}", c)
        elif p == ("status",):
            if c.new == "stopped":
                ev("guest.stopped", "warning", f"stopped (was {c.old})", c)
            elif c.new == "running":
                ev("guest.started", "info", f"started (was {c.old})", c)
            else:
                ev("guest.state_changed", "info", f"{c.old} -> {c.new}", c)
        elif p in (("memory_mb",), ("cores",), ("sockets",)):
            ev("guest.resized", "notice", f"{head} {c.old} -> {c.new}", c)
        elif head == "disks":
            ev(
                "guest.disk_changed",
                "notice",
                f"disk {p[1]} {k}" + (f" {c.old} -> {c.new}" if k == "changed" else ""),
                c,
            )
        elif head == "nics" and p[-1] == "mac":
            ev("guest.mac_changed", "warning", f"{p[1]} MAC {c.old} -> {c.new}", c)
        elif head == "nics":
            detail = f" {p[2]} {c.old} -> {c.new}" if len(p) == 3 else f" {k}"
            ev("guest.nic_changed", "notice", f"{p[1]}{detail}", c)
        elif head == "ips" and len(p) == 2:
            if not status_changed:  # IPs vanish when a guest stops; that is not news
                ev(f"ip.{k}", "notice", f"{p[1]} {k}", c)
        elif p == ("agent_os",):
            if not status_changed and c.old is not None and c.new is not None:
                ev("guest.os_changed", "notice", f"OS {c.old} -> {c.new}", c)
        elif p == ("ha_state",):
            ev("ha.state_changed", "notice", f"HA state {c.old} -> {c.new}", c)
        elif p in (("onboot",), ("template",), ("agent_enabled",)):
            ev(f"guest.{head}_changed", "info", f"{head} {c.old} -> {c.new}", c)
        elif head == "tags":
            grouped["tags"] += 1
        elif p == ("backed_up",):
            pass  # reported once, at cluster level (not_backed_up)
        # ---------------------------------------------------------- nodes
        elif p == ("pve_version",):
            ev("pve.upgraded", "notice", f"{c.old} -> {c.new}", c)
        elif p == ("kernel",):
            ev("kernel.changed", "notice", f"kernel {c.old} -> {c.new}", c)
        elif p == ("online",):
            if c.new is False:
                ev("node.offline", "warning", "node offline", c)
            else:
                ev("node.online", "info", "node back online", c)
        elif head == "interfaces" and len(p) == 2:
            ev(f"network.iface_{k}", "notice", f"interface {p[1]} {k}", c)
        elif head == "interfaces":
            ev("network.iface_changed", "notice", f"interface {p[1]} {p[2]} {c.old} -> {c.new}", c)
        elif head == "storages" and len(p) == 2:
            ev(f"storage.{k}", "notice", f"storage {p[1]} {k}", c)
        elif head == "storages" and p[-1] == "status":
            sev: Severity = "warning" if c.new != "available" else "info"
            ev("storage.state_changed", sev, f"storage {p[1]} {c.old} -> {c.new}", c)
        # ---------------------------------------------------------- cluster
        elif p == ("quorate",):
            if c.new is False:
                ev("cluster.quorum_lost", "warning", "cluster lost quorum", c)
            else:
                ev("cluster.quorum_ok", "info", "cluster quorate again", c)
        elif head == "node_names" and len(p) == 2:
            ev(f"cluster.node_{k}", "notice", f"node {p[1]} {k}", c)
        elif head == "backup_jobs" and len(p) == 2:
            ev(f"backup.job_{k}", "notice", f"backup job {p[1]} {k}", c)
        elif head == "backup_jobs" and p[-1] == "enabled" and c.new is False:
            ev("backup.job_disabled", "warning", f"backup job {p[1]} disabled", c)
        elif head == "backup_jobs":
            ev("backup.job_changed", "notice", f"backup job {p[1]} {p[2]} {c.old} -> {c.new}", c)
        elif head == "not_backed_up" and len(p) == 2:
            if k == "added":
                ev("backup.missing", "warning", f"{p[1]} is not covered by any backup job", c)
            else:
                ev("backup.resolved", "info", f"{p[1]} no longer listed as not backed up", c)
        elif p == ("version",):
            pass  # node-level pve.upgraded covers it
        else:
            unclaimed.append(c)

    if grouped["tags"]:
        out.append(EventSpec(key, "guest.tags_changed", "info", f"{name}: tags changed", "tags"))
    if unclaimed:
        fields = sorted({".".join(c.path[:2]) for c in unclaimed})
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
