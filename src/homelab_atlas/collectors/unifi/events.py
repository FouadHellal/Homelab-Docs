"""UniFi change events: device state/firmware/uplinks, VLANs, SSIDs, firewall policies."""

from collections import defaultdict
from typing import Any

from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity


def _name(v: Any, fallback: str) -> str:
    return str(v.get("name") or fallback) if isinstance(v, dict) else fallback


def unifi_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []
    unclaimed: list[Change] = []
    grouped: dict[str, int] = defaultdict(int)

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p, k = c.path, c.kind
        head = p[0]
        v = c.new if k == "added" else c.old
        # ------------------------------------------------------------ devices
        if p == ("state",):
            if c.new in {"OFFLINE", "CONNECTION_INTERRUPTED"}:
                ev("device.offline", "warning", f"device {c.new.lower()} (was {c.old})", c)
            elif c.new == "ONLINE":
                ev("device.online", "info", f"device online (was {c.old})", c)
            else:
                ev("device.state_changed", "info", f"state {c.old} -> {c.new}", c)
        elif p == ("firmware",):
            ev("fw.upgraded", "notice", f"firmware {c.old} -> {c.new}", c)
        elif p == ("ip",):
            ev("device.ip_changed", "notice", f"IP {c.old} -> {c.new}", c)
        elif p == ("uplink_mac",):
            ev("topology.uplink_changed", "notice", f"uplink {c.old} -> {c.new}", c)
        elif p == ("model",):
            ev("device.replaced", "warning", f"model {c.old} -> {c.new}", c)
        elif head in ("ports", "radios"):
            grouped[head] += 1
        # ------------------------------------------------------------ site
        elif head == "networks" and len(p) == 2:
            vlan = v.get("vlan_id") if isinstance(v, dict) else None
            ev(f"vlan.{k}", "notice", f"network {_name(v, p[1])} (VLAN {vlan}) {k}", c)
        elif head == "networks":
            ev("network.changed", "notice", f"network {p[1]} {p[2]} {c.old} -> {c.new}", c)
        elif head == "ssids" and len(p) == 2:
            sec = v.get("security") if isinstance(v, dict) else None
            sev: Severity = "warning" if k == "added" and sec == "OPEN" else "notice"
            ev(f"wifi.ssid_{k}", sev, f"SSID {_name(v, p[1])} ({sec}) {k}", c)
        elif head == "ssids" and p[-1] == "security":
            sev = "warning" if c.new == "OPEN" else "notice"
            ev("wifi.security_changed", sev, f"SSID {p[1]} security {c.old} -> {c.new}", c)
        elif head == "ssids":
            ev("wifi.ssid_changed", "info", f"SSID {p[1]} {p[2]} {c.old} -> {c.new}", c)
        elif head == "zones":
            ev(
                f"firewall.zone_{k}" if len(p) == 2 else "firewall.zone_changed",
                "notice",
                f"firewall zone {_name(v, p[1]) if len(p) == 2 else p[1]} {k}",
                c,
            )
        elif head == "policies" and len(p) == 2:
            ev(f"firewall.policy_{k}", "notice", f"firewall policy {_name(v, p[1])!r} {k}", c)
        elif head == "policies" and p[-1] == "enabled":
            sev = "warning" if c.new is False else "notice"
            ev(
                "firewall.policy_" + ("disabled" if c.new is False else "enabled"),
                sev,
                f"firewall policy {p[1]} {'disabled' if c.new is False else 'enabled'}",
                c,
            )
        elif head == "policies":
            ev(
                "firewall.policy_changed",
                "notice",
                f"firewall policy {p[1]} {p[2]} {c.old} -> {c.new}",
                c,
            )
        elif head == "acl_rules":
            grouped["acl_rules"] += 1
        elif head == "wans":
            ev(f"wan.{k}" if len(p) == 2 else "wan.changed", "notice", f"WAN {p[1]} {k}", c)
        elif p == ("app_version",):
            ev("unifi.upgraded", "notice", f"Network application {c.old} -> {c.new}", c)
        else:
            unclaimed.append(c)

    for what, n in sorted(grouped.items()):
        out.append(
            EventSpec(
                key,
                f"{what}.changed",
                "info",
                f"{name}: {n} {what.replace('_', ' ')} change(s)",
                what,
            )
        )
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
