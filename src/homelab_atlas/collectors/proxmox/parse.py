"""Parse Proxmox VE API payloads into facts. Total: unexpected shapes are skipped."""

import re
from typing import Any, Final

from homelab_atlas.collectors.linux_ssh.parse import norm_ip, norm_mac
from homelab_atlas.models.proxmox import (
    BackupJob,
    GuestDisk,
    GuestIp,
    GuestNic,
    HaResource,
    NodeInterface,
    Storage,
)

NIC_KEY_RE: Final = re.compile(r"net\d{1,2}")
QEMU_DISK_RE: Final = re.compile(r"(scsi|virtio|sata|ide|efidisk|tpmstate)\d{1,2}")
LXC_DISK_RE: Final = re.compile(r"rootfs|mp\d{1,3}")
NIC_MODELS: Final = frozenset({"virtio", "e1000", "e1000e", "rtl8139", "vmxnet3", "ne2k_pci"})


def data(payload: Any) -> Any:
    return payload.get("data") if isinstance(payload, dict) else None


def _s(v: Any, limit: int = 256) -> str | None:
    if isinstance(v, int | float) and not isinstance(v, bool):
        v = str(v)
    return v[:limit] if isinstance(v, str) and v else None


def _i(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


def _b(v: Any) -> bool:
    return v in (1, True, "1", "yes", "on")


def kv(text: str) -> tuple[str | None, dict[str, str]]:
    """Proxmox property string: 'virtio=AA:..,bridge=vmbr0,tag=20' -> (first_bare, {k: v})."""
    first: str | None = None
    out: dict[str, str] = {}
    for i, part in enumerate(text.split(",")):
        k, sep, v = part.partition("=")
        if not sep:
            if i == 0:
                first = k
            continue
        out[k.strip()] = v.strip()
    return first, out


def qemu_nic(slot: str, text: str) -> GuestNic:
    _, props = kv(text)
    model = next((m for m in NIC_MODELS if m in props), None)
    return GuestNic(
        slot=slot,
        model=model,
        mac=norm_mac(props.get(model, "")) if model else None,
        bridge=_s(props.get("bridge"), 32),
        vlan_tag=_i(props.get("tag")),
        firewall=_b(props.get("firewall")),
        link_down=_b(props.get("link_down")),
    )


def lxc_nic(slot: str, text: str) -> GuestNic:
    _, props = kv(text)
    return GuestNic(
        slot=slot,
        model=_s(props.get("type"), 16) or "veth",
        mac=norm_mac(props.get("hwaddr", "")),
        bridge=_s(props.get("bridge"), 32),
        vlan_tag=_i(props.get("tag")),
        firewall=_b(props.get("firewall")),
        link_down=_b(props.get("link_down")),
    )


def disk(slot: str, text: str) -> GuestDisk | None:
    first, props = kv(text)
    if props.get("media") == "cdrom" or first in (None, "none"):
        return None
    storage, _, volume = first.partition(":")
    return GuestDisk(
        slot=slot,
        storage=storage[:64] or None,
        volume=volume[:128] or None,
        size=_s(props.get("size"), 16),
        mountpoint=_s(props.get("mp"), 256),
    )


def guest_config(kind: str, cfg: Any) -> dict[str, Any]:
    if not isinstance(cfg, dict):
        return {}
    nics, disks = [], []
    for key in sorted(cfg):
        value = cfg[key]
        if not isinstance(value, str):
            continue
        if NIC_KEY_RE.fullmatch(key):
            nics.append(qemu_nic(key, value) if kind == "qemu" else lxc_nic(key, value))
        elif (QEMU_DISK_RE if kind == "qemu" else LXC_DISK_RE).fullmatch(key) and (
            d := disk(key, value)
        ) is not None:
            disks.append(d)
    agent_first, agent_props = kv(str(cfg.get("agent", "")))
    tags = [t for t in re.split(r"[;, ]+", str(cfg.get("tags", ""))) if t]
    return {
        "cores": _i(cfg.get("cores")),
        "sockets": _i(cfg.get("sockets")),
        "memory_mb": _i(cfg.get("memory")),
        "onboot": _b(cfg.get("onboot")),
        "ostype": _s(cfg.get("ostype"), 32),
        "agent_enabled": _b(agent_first) or _b(agent_props.get("enabled")),
        "unprivileged": _b(cfg.get("unprivileged")) if kind == "lxc" else None,
        "features": _s(cfg.get("features"), 128),
        "description": _s(cfg.get("description"), 2048),
        "tags": sorted(t[:64] for t in tags[:32]),
        "nics": nics,
        "disks": disks,
    }


def agent_ips(payload: Any) -> list[GuestIp]:
    result = data(payload)
    result = result.get("result") if isinstance(result, dict) else None
    ips: list[GuestIp] = []
    for iface in result if isinstance(result, list) else []:
        if not isinstance(iface, dict) or iface.get("name") == "lo":
            continue
        for a in iface.get("ip-addresses") or []:
            if not isinstance(a, dict):
                continue
            ip, prefix = a.get("ip-address"), _i(a.get("prefix"))
            if (
                isinstance(ip, str)
                and prefix is not None
                and not ip.startswith(("127.", "fe80:", "::1"))
            ):
                ips.append(
                    GuestIp(address=norm_ip(f"{ip}/{prefix}"), iface=_s(iface.get("name"), 64))
                )
    return ips


def agent_os(payload: Any) -> str | None:
    result = data(payload)
    result = result.get("result") if isinstance(result, dict) else None
    if not isinstance(result, dict):
        return None
    return _s(result.get("pretty-name"), 128) or _s(result.get("name"), 128)


def lxc_ips(payload: Any) -> list[GuestIp]:
    ips: list[GuestIp] = []
    items = data(payload)
    for iface in items if isinstance(items, list) else []:
        if not isinstance(iface, dict) or iface.get("name") == "lo":
            continue
        for key in ("inet", "inet6"):
            v = iface.get(key)
            if isinstance(v, str) and "/" in v and not v.startswith(("127.", "fe80:", "::1")):
                ips.append(GuestIp(address=norm_ip(v), iface=_s(iface.get("name"), 64)))
    return ips


def node_interfaces(payload: Any) -> list[NodeInterface]:
    out = []
    items = data(payload)
    for n in items if isinstance(items, list) else []:
        if not isinstance(n, dict) or not isinstance(n.get("iface"), str):
            continue
        ports = str(n.get("bridge_ports") or n.get("slaves") or "")
        out.append(
            NodeInterface(
                iface=n["iface"][:64],
                type=_s(n.get("type"), 16),
                cidr=norm_ip(n["cidr"]) if isinstance(n.get("cidr"), str) else None,
                cidr6=norm_ip(n["cidr6"]) if isinstance(n.get("cidr6"), str) else None,
                gateway=_s(n.get("gateway"), 64),
                bridge_ports=sorted(p for p in ports.split() if p),
                vlan_aware=_b(n.get("bridge_vlan_aware")),
                vlan_id=_i(n.get("vlan-id")),
                vlan_raw_device=_s(n.get("vlan-raw-device"), 64),
                autostart=_b(n.get("autostart")),
                comments=_s(n.get("comments"), 256),
                active=_b(n.get("active")),
            )
        )
    return out


def storage(item: dict[str, Any]) -> Storage | None:
    name = _s(item.get("storage"), 64)
    if name is None:
        return None
    return Storage(
        storage=name,
        type=_s(item.get("plugintype"), 32),
        content=sorted(c for c in str(item.get("content") or "").split(",") if c),
        shared=_b(item.get("shared")),
        total_bytes=_i(item.get("maxdisk")),
        status=_s(item.get("status"), 16),
        used_bytes=_i(item.get("disk")),
    )


def backup_jobs(payload: Any) -> list[BackupJob]:
    out = []
    items = data(payload)
    for j in items if isinstance(items, list) else []:
        if not isinstance(j, dict) or not isinstance(j.get("id"), str):
            continue
        out.append(
            BackupJob(
                id=j["id"][:64],
                enabled=j.get("enabled", 1) not in (0, "0", False),
                schedule=_s(j.get("schedule"), 64),
                storage=_s(j.get("storage"), 64),
                mode=_s(j.get("mode"), 16),
                all=_b(j.get("all")),
                vmids=sorted(v for v in str(j.get("vmid") or "").split(",") if v),
                node=_s(j.get("node"), 64),
                comment=_s(j.get("comment"), 256),
            )
        )
    return out


def ha_resources(payload: Any) -> list[HaResource]:
    items = data(payload)
    return [
        HaResource(sid=h["sid"][:64], state=_s(h.get("state"), 16), group=_s(h.get("group"), 64))
        for h in (items if isinstance(items, list) else [])
        if isinstance(h, dict) and isinstance(h.get("sid"), str)
    ]


def not_backed_up(payload: Any) -> list[str]:
    items = data(payload)
    return sorted(
        f"{g.get('type')}/{g['vmid']}"
        for g in (items if isinstance(items, list) else [])
        if isinstance(g, dict) and isinstance(g.get("vmid"), int)
    )


def node_status(payload: Any) -> dict[str, Any]:
    raw = data(payload)
    s: dict[str, Any] = raw if isinstance(raw, dict) else {}
    cpu_raw, mem_raw = s.get("cpuinfo"), s.get("memory")
    cpu: dict[str, Any] = cpu_raw if isinstance(cpu_raw, dict) else {}
    mem: dict[str, Any] = mem_raw if isinstance(mem_raw, dict) else {}
    pveversion = str(s.get("pveversion") or "")  # "pve-manager/9.2.1/abcdef"
    kversion = str(s.get("kversion") or "").split()  # "Linux 6.14.8-2-pve #1 SMP ..."
    cpu_load = s.get("cpu")
    return {
        "pve_version": _s(pveversion.split("/")[1], 32) if pveversion.count("/") >= 1 else None,
        "kernel": _s(kversion[1], 64) if len(kversion) > 1 else None,
        "cpu_model": _s(cpu.get("model"), 128),
        "cpu_cores": _i(cpu.get("cpus")),
        "memory_bytes": _i(mem.get("total")),
        "uptime_s": _i(s.get("uptime")),
        "cpu_load": cpu_load if isinstance(cpu_load, float) else None,
    }
