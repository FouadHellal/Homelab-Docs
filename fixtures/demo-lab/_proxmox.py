"""Proxmox VE part of the synthetic demo lab: recorded API responses (PVE 9.2 shapes).

Two-node cluster "homelab" (pve1, pve2), 14 guests. MACs/IPs match the SSH recordings so
VM <-> host correlation (M4) has something real to join on.
"""

import copy
import hashlib
from typing import Any

BASE = "/api2/json"


def mac(name: str, n: int = 0) -> str:  # same scheme as generate.py
    h = hashlib.sha256(f"{name}/{n}".encode()).digest()
    return "bc:24:11:" + ":".join(f"{b:02x}" for b in h[:3])


# vmid, type, name, node, status, cores, memory MiB, tags, ips (agent/lxc view)
GUESTS: list[tuple[int, str, str, str, str, int, int, str, list[str]]] = [
    (101, "qemu", "docker01", "pve1", "running", 4, 8192, "docker;prod", ["10.0.20.11/24"]),
    (102, "qemu", "docker02", "pve2", "running", 4, 8192, "docker", ["10.0.20.12/24", "2001:db8:20::12/64"]),
    (103, "qemu", "web01", "pve1", "running", 2, 2048, "prod;web", ["10.0.20.21/24"]),
    (104, "qemu", "db01", "pve2", "running", 2, 4096, "db;prod", ["10.0.20.31/24"]),
    (105, "qemu", "legacy01", "pve1", "running", 1, 1024, "legacy", ["10.0.20.70/24"]),
    (106, "qemu", "ipv6only01", "pve2", "running", 1, 1024, "", ["2001:db8:20::80/64"]),
    (110, "qemu", "win11", "pve2", "stopped", 4, 8192, "windows", ["10.0.20.110/24"]),
    (111, "qemu", "homeassistant", "pve1", "running", 2, 4096, "iot", []),
    (9000, "qemu", "debian-12-template", "pve1", "stopped", 2, 2048, "template", []),
    (201, "lxc", "mediatheque", "pve1", "running", 2, 2048, "media", ["10.0.20.50/24"]),
    (202, "lxc", "backup01", "pve2", "running", 1, 512, "backup", ["10.0.20.40/24"]),
    (203, "lxc", "adguard", "pve1", "running", 1, 512, "dns", ["10.0.20.53/24"]),
    (204, "lxc", "media01", "pve2", "running", 4, 4096, "docker;media", ["10.0.20.55/24"]),
    (205, "lxc", "scratch", "pve1", "stopped", 1, 256, "", []),
]  # fmt: skip


def state_a() -> dict[str, Any]:
    return {
        "version": "9.2.1",
        "nodes": {
            "pve1": {"ip": "10.0.10.11", "pve": "9.2.1", "kernel": "6.14.8-2-pve",
                     "vlans": [20, 30], "cidr": "10.0.10.11/24", "nfs": "available"},
            "pve2": {"ip": "10.0.10.12", "pve": "9.2.1", "kernel": "6.14.8-2-pve",
                     "vlans": [20], "cidr": "10.0.10.12/24", "nfs": "available"},
        },
        "guests": {g[0]: list(g) for g in GUESTS},
        "jobs": [{"id": "backup-daily-critical", "schedule": "02:30", "enabled": 1, "storage": "nas-nfs",
                  "mode": "snapshot", "vmid": "101,103,104,201,202", "type": "vzdump",
                  "next-run": 1760841000}],
        "uncovered": [102, 105, 106, 110, 111, 203, 204, 205],
        "memory_override": {},
    }  # fmt: skip


def state_b(a: dict[str, Any]) -> dict[str, Any]:
    b = copy.deepcopy(a)
    b["guests"][103][3] = "pve2"  # web01 migrated
    b["guests"][110][4] = "running"  # win11 started
    b["guests"][105][4] = "stopped"  # legacy01 shut down (also unreachable over SSH)
    b["guests"][104][6] = 8192  # db01 memory doubled
    del b["guests"][205]  # scratch container deleted
    b["guests"][201][8] = ["10.0.20.50/24", "2001:db8:20::50/64"]
    b["nodes"]["pve2"] |= {"pve": "9.2.2", "kernel": "6.14.11-1-pve"}
    b["nodes"]["pve1"]["vlans"] = [20, 30, 40]
    b["nodes"]["pve1"]["nfs"] = "unavailable"
    b["jobs"].append({"id": "backup-weekly-desktop", "schedule": "sun 03:00", "enabled": 1,
                      "storage": "nas-nfs", "mode": "snapshot", "vmid": "110,111", "type": "vzdump",
                      "next-run": 1761450000})  # fmt: skip
    b["uncovered"] = [102, 105, 106, 203, 204]
    return b


def _ok(body: Any) -> dict[str, Any]:
    return {"status": 200, "body": {"data": body}}


def render(s: dict[str, Any]) -> dict[str, Any]:
    rec: dict[str, Any] = {}
    nodes = s["nodes"]
    rec[f"{BASE}/version"] = _ok({"version": s["version"], "release": "9.2", "repoid": "0a1b2c3d"})
    rec[f"{BASE}/cluster/status"] = _ok(
        [{"type": "cluster", "id": "cluster", "name": "homelab", "nodes": 2, "quorate": 1, "version": 4}]
        + [{"type": "node", "id": f"node/{n}", "name": n, "nodeid": i, "ip": v["ip"],
            "local": int(i == 1), "online": 1, "level": ""} for i, (n, v) in enumerate(nodes.items(), 1)]
    )  # fmt: skip
    resources: list[dict[str, Any]] = []
    for n in nodes:
        resources.append({"id": f"node/{n}", "type": "node", "node": n, "status": "online", "maxcpu": 12,
                          "maxmem": 68719476736, "mem": 21474836480, "cpu": 0.07, "uptime": 2592000,
                          "level": "", "cgroup-mode": 2})  # fmt: skip
        resources.append({"id": f"storage/{n}/local-lvm", "type": "storage", "storage": "local-lvm",
                          "node": n, "plugintype": "lvmthin", "content": "rootdir,images", "shared": 0,
                          "maxdisk": 499289948160, "disk": 201863462912, "status": "available"})  # fmt: skip
        resources.append({"id": f"storage/{n}/nas-nfs", "type": "storage", "storage": "nas-nfs", "node": n,
                          "plugintype": "nfs", "content": "backup,iso,images", "shared": 1,
                          "maxdisk": 8001563222016, "disk": 4000000000000,
                          "status": nodes[n]["nfs"]})  # fmt: skip
    for vmid, kind, name, node, status, cores, mem, tags, ips in s["guests"].values():
        running = status == "running"
        resources.append({"id": f"{kind}/{vmid}", "type": kind, "vmid": vmid, "name": name, "node": node,
                          "status": status, "maxcpu": cores, "maxmem": mem * 1048576,
                          "cpu": 0.03 if running else 0, "uptime": 86400 if running else 0,
                          "template": int(vmid == 9000), "tags": tags})  # fmt: skip
        base = f"{BASE}/nodes/{node}/{kind}/{vmid}"
        if kind == "qemu":
            cfg: dict[str, Any] = {
                "cores": cores, "sockets": 1, "memory": str(mem), "agent": "1", "onboot": int(vmid != 9000),
                "ostype": "win11" if name == "win11" else "l26", "tags": tags, "scsihw": "virtio-scsi-single",
                "net0": f"virtio={mac(name).upper()},bridge=vmbr0,tag=20,firewall=1",
                "scsi0": f"local-lvm:vm-{vmid}-disk-0,iothread=1,size={64 if cores > 2 else 32}G,ssd=1",
                "ide2": "none,media=cdrom",
                "digest": hashlib.sha1(f"{vmid}{status}".encode()).hexdigest(),
            }  # fmt: skip
            if name == "win11":
                cfg |= {"efidisk0": f"local-lvm:vm-{vmid}-disk-1,efitype=4m,size=4M",
                        "tpmstate0": f"local-lvm:vm-{vmid}-disk-2,size=4M,version=v2.0"}  # fmt: skip
            if name == "docker01":
                cfg["description"] = "Docker host. Initial root password=pve-desc-ATLASFAKE (rotate!)"
            if vmid == 9000:
                cfg["template"] = 1
            rec[f"{base}/config"] = _ok(cfg)
            if running and name == "homeassistant":
                err = {"status": 500, "body": {"data": None, "message": "QEMU guest agent is not running\n"}}
                rec[f"{base}/agent/network-get-interfaces"] = err
                rec[f"{base}/agent/get-osinfo"] = err
            elif running:
                addrs = [{"ip-address": ip.split("/")[0], "ip-address-type": "ipv6" if ":" in ip else "ipv4",
                          "prefix": int(ip.split("/")[1])} for ip in ips]  # fmt: skip
                addrs.append({"ip-address": "fe80::be24:11ff:fe00:1", "ip-address-type": "ipv6", "prefix": 64})
                rec[f"{base}/agent/network-get-interfaces"] = _ok({"result": [
                    {"name": "lo", "hardware-address": "00:00:00:00:00:00",
                     "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}]},
                    {"name": "Ethernet" if name == "win11" else "eth0", "hardware-address": mac(name),
                     "ip-addresses": addrs}]})  # fmt: skip
                pretty = "Microsoft Windows 11 Pro" if name == "win11" else "Debian GNU/Linux 12 (bookworm)"
                rec[f"{base}/agent/get-osinfo"] = _ok({"result": {"pretty-name": pretty, "id": "debian"}})
        else:
            v4 = next((ip for ip in ips if ":" not in ip), "dhcp")
            cfg = {
                "hostname": name, "cores": cores, "memory": mem, "swap": 512, "ostype": "debian",
                "unprivileged": 1, "onboot": int(status == "running"), "tags": tags,
                "net0": f"name=eth0,bridge=vmbr0,gw=10.0.20.1,hwaddr={mac(name).upper()},ip={v4},tag=20,type=veth",
                "rootfs": f"local-lvm:vm-{vmid}-disk-0,size=8G",
                "digest": hashlib.sha1(f"{vmid}".encode()).hexdigest(),
            }  # fmt: skip
            if name == "media01":
                cfg["features"] = "nesting=1,keyctl=1"
            if name == "mediatheque":
                cfg["mp0"] = "nas-nfs:201/vm-201-disk-1.raw,mp=/mnt/media,size=500G"
            rec[f"{base}/config"] = _ok(cfg)
            if running:
                v6 = next((ip for ip in ips if ":" in ip), "fe80::be24:11ff:fe00:2/64")
                rec[f"{base}/interfaces"] = _ok([
                    {"name": "lo", "hwaddr": "00:00:00:00:00:00", "inet": "127.0.0.1/8", "inet6": "::1/128"},
                    {"name": "eth0", "hwaddr": mac(name), "inet": v4, "inet6": v6}])  # fmt: skip
    rec[f"{BASE}/cluster/resources"] = _ok(resources)
    rec[f"{BASE}/cluster/backup"] = _ok(s["jobs"])
    by_id = {g[0]: g for g in s["guests"].values()}
    rec[f"{BASE}/cluster/backup-info/not-backed-up"] = _ok(
        [{"vmid": v, "name": by_id[v][2], "type": by_id[v][1]} for v in s["uncovered"] if v in by_id]
    )
    rec[f"{BASE}/cluster/ha/resources"] = _ok([])
    for n, v in nodes.items():
        rec[f"{BASE}/nodes/{n}/status"] = _ok({
            "pveversion": f"pve-manager/{v['pve']}/5a3b1c2d", "uptime": 2592000, "cpu": 0.07,
            "kversion": f"Linux {v['kernel']} #1 SMP PREEMPT_DYNAMIC PMX x86_64",
            "cpuinfo": {"model": "Intel(R) Core(TM) i5-12500", "cpus": 12, "cores": 6, "sockets": 1},
            "memory": {"total": 68719476736, "used": 21474836480, "free": 47244640256}})  # fmt: skip
        ifaces: list[dict[str, Any]] = [
            {"iface": "eno1", "type": "eth", "active": 1, "autostart": 1, "method": "manual"},
            {"iface": "vmbr0", "type": "bridge", "bridge_ports": "eno1", "bridge_vlan_aware": 1,
             "cidr": v["cidr"], "gateway": "10.0.10.1", "active": 1, "autostart": 1, "method": "static"},
        ]  # fmt: skip
        for vlan in v["vlans"]:
            ifaces.append({"iface": f"vmbr0.{vlan}", "type": "vlan", "vlan-raw-device": "vmbr0",
                           "vlan-id": vlan, "active": 1, "autostart": 1, "method": "manual",
                           "comments": f"VLAN {vlan}"})  # fmt: skip
        rec[f"{BASE}/nodes/{n}/network"] = _ok(ifaces)
    audit = dict.fromkeys(("Sys.Audit", "VM.Audit", "VM.GuestAgent.Audit", "Datastore.Audit", "SDN.Audit", "Pool.Audit", "Mapping.Audit"), 1)  # fmt: skip
    rec[f"{BASE}/access/permissions"] = _ok({"/": audit, "/vms": audit, "/storage": audit, "/nodes": audit})
    return rec
