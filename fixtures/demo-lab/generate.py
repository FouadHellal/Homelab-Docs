"""Generate the synthetic demo lab (SPEC §12): hosts.yaml + recorded probe output, states A/B.

Deterministic: rerun after changing it and commit the result. Every secret is fake and
carries the ATLASFAKE marker. `@@PROBE_SHA256@@` is substituted at load time with the
current probe hash so recordings survive probe edits (one host deliberately runs an old one).

    uv run python fixtures/demo-lab/generate.py
"""

import base64
import copy
import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

import _docker  # sibling modules (script dir is on sys.path)
import _proxmox
import _unifi

HERE = Path(__file__).resolve().parent
PROBE_SHA = "@@PROBE_SHA256@@"
PROBE_VER = "@@PROBE_VERSION@@"
OLD_PROBE_SHA = hashlib.sha256(b"atlas-probe 0.9.0").hexdigest()

BASE_PKGS = {
    "bash": "5.2.15-2+b7", "curl": "7.88.1-10+deb12u8", "libc6": "2.36-9+deb12u9",
    "openssh-server": "1:9.2p1-2+deb12u3", "openssl": "3.0.15-1~deb12u1", "sudo": "1.9.13p3-1+deb12u1",
    "systemd": "252.31-1~deb12u1", "unattended-upgrades": "2.9.1+nmu3", "vim-tiny": "2:9.0.1378-2",
    "less": "590-2.1~deb12u2", "rsync": "3.2.7-1+deb12u2", "tzdata": "2024b-0+deb12u1",
    "ca-certificates": "20230311", "qemu-guest-agent": "1:7.2+dfsg-7+deb12u7",
}
UBUNTU_PKGS = {
    "bash": "5.2.21-2ubuntu4", "curl": "8.5.0-2ubuntu10.4", "libc6": "2.39-0ubuntu8.3",
    "openssh-server": "1:9.6p1-3ubuntu13.5", "openssl": "3.0.13-0ubuntu3.4", "sudo": "1.9.15p5-3ubuntu5",
    "systemd": "255.4-1ubuntu8.4", "unattended-upgrades": "2.9.1+nmu4ubuntu1", "less": "590-2ubuntu2.1",
    "tzdata": "2024a-3ubuntu1.1", "ca-certificates": "20240203",
}
BASE_SERVICES = [
    ("ssh.service", "active", "running", "enabled", "OpenBSD Secure Shell server"),
    ("cron.service", "active", "running", "enabled", "Regular background program processing daemon"),
    ("systemd-journald.service", "active", "running", "static", "Journal Service"),
    ("systemd-timesyncd.service", "active", "running", "enabled", "Network Time Synchronization"),
    ("unattended-upgrades.service", "active", "running", "enabled", "Unattended Upgrades Shutdown"),
]
BASE_USERS = [
    ("root", 0, 0, "/root", "/bin/bash"),
    ("daemon", 1, 1, "/usr/sbin", "/usr/sbin/nologin"),
    ("www-data", 33, 33, "/var/www", "/usr/sbin/nologin"),
    ("nobody", 65534, 65534, "/nonexistent", "/usr/sbin/nologin"),
    ("atlas-ro", 998, 998, "/var/lib/atlas-ro", "/bin/bash"),
    ("ops", 1000, 1000, "/home/ops", "/bin/bash"),
]
BASE_GROUPS = {"root": 0, "daemon": 1, "adm": 4, "sudo": 27, "www-data": 33, "atlas-ro": 998,
               "ops": 1000, "docker": 999, "nogroup": 65534}


def mac(name: str, n: int = 0) -> str:
    h = hashlib.sha256(f"{name}/{n}".encode()).digest()
    return "bc:24:11:" + ":".join(f"{b:02x}" for b in h[:3])


def host_key(name: str) -> str:
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + hashlib.sha256(name.encode()).digest()
    return "ssh-ed25519 " + base64.b64encode(blob).decode()


def host(name: str, ip: str, **kw: Any) -> dict[str, Any]:
    ubuntu = kw.pop("ubuntu", False)
    h: dict[str, Any] = {
        "name": name,
        "hostname": kw.pop("hostname", name),
        "machine_id": hashlib.md5(name.encode()).hexdigest(),
        "os": ("ubuntu", "24.04", "noble", "Ubuntu 24.04.1 LTS") if ubuntu
        else ("debian", "12", "bookworm", "Debian GNU/Linux 12 (bookworm)"),
        "kernel": "6.8.0-48-generic" if ubuntu else "6.1.0-25-amd64",
        "arch": "x86_64",
        "virt": "kvm",
        "uptime": 864000.42,
        "ifaces": [{"name": "eth0", "mac": mac(name), "addrs": [f"{ip}/24"], "kind": None}],
        "veth": 0,
        "routes4": [("default", "10.0.20.1", "eth0"), ("10.0.20.0/24", None, "eth0")],
        "routes6": [],
        "nameservers": ["10.0.20.1"],
        "search": ["lab.example"],
        "sockets": [("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "[::]", 22, "sshd", 812),
                    ("udp", "127.0.0.53%lo", 53, "systemd-resolve", 600)],
        "disks": [("sda", 34359738368, "QEMU HARDDISK", [("sda1", 33285996544, "ext4", "/")])],
        "mounts": [("/", "/dev/sda1", "ext4", 33285996544, 9123456789)],
        "services": list(BASE_SERVICES),
        "timers": [("apt-daily.timer", "apt-daily.service"), ("logrotate.timer", "logrotate.service")],
        "cron": {"/etc/crontab": ["SHELL=/bin/sh", "17 * * * * root cd / && run-parts --report /etc/cron.hourly"]},
        "users": list(BASE_USERS),
        "groups": {**BASE_GROUPS, "members": {"sudo": ["ops"], "adm": ["ops"]}},
        "packages": dict(UBUNTU_PKGS if ubuntu else BASE_PKGS),
        "probe": (PROBE_VER, PROBE_SHA),
        "broken": set(),
    }
    h.update(kw)
    return h


def state_a() -> list[dict[str, Any]]:
    pve = {"virt": "none", "kernel": "6.14.8-2-pve", "packages": {**BASE_PKGS, "proxmox-ve": "9.2.0",
           "pve-manager": "9.2.1", "proxmox-kernel-6.14": "6.14.8-2"}}
    hosts = [
        host("pve1", "10.0.10.11", **copy.deepcopy(pve),
             ifaces=[{"name": "eno1", "mac": mac("pve1"), "addrs": [], "kind": None},
                     {"name": "vmbr0", "mac": mac("pve1"), "addrs": ["10.0.10.11/24"], "kind": "bridge"},
                     {"name": "vmbr0.20", "mac": mac("pve1"), "addrs": ["10.0.20.2/24"], "kind": "vlan", "vlan": 20},
                     {"name": "vmbr0.30", "mac": mac("pve1"), "addrs": [], "kind": "vlan", "vlan": 30}],
             routes4=[("default", "10.0.10.1", "vmbr0"), ("10.0.10.0/24", None, "vmbr0")],
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 900), ("tcp", "*", 8006, "pveproxy worker", 1500),
                      ("tcp", "127.0.0.1", 85, "pvedaemon worke", 1400), ("udp", "0.0.0.0", 111, "rpcbind", 700)]),
        host("pve2", "10.0.10.12", **copy.deepcopy(pve),
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 901), ("tcp", "*", 8006, "pveproxy worker", 1501)]),
        host("docker01", "10.0.20.11", veth=6,
             ifaces=[{"name": "eth0", "mac": mac("docker01"), "addrs": ["10.0.20.11/24"], "kind": None},
                     {"name": "docker0", "mac": mac("docker01", 1), "addrs": ["172.17.0.1/16"], "kind": "bridge"}],
             packages={**BASE_PKGS, "docker-ce": "5:27.3.1-1~debian.12~bookworm",
                       "containerd.io": "1.7.22-1", "linux-image-amd64": "6.1.106-3",
                       "linux-image-6.1.0-25-amd64": "6.1.106-3"},
             users=[*BASE_USERS], groups={**BASE_GROUPS, "members": {"sudo": ["ops"], "docker": ["ops"]}},
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "0.0.0.0", 443, "docker-proxy", 2100),
                      ("tcp", "0.0.0.0", 2283, "docker-proxy", 2200)]),
        host("docker02", "10.0.20.12", ubuntu=True, veth=3,
             ifaces=[{"name": "eth0", "mac": mac("docker02"), "addrs": ["10.0.20.12/24", "2001:db8:20::12/64"], "kind": None},
                     {"name": "docker0", "mac": mac("docker02", 1), "addrs": ["172.17.0.1/16"], "kind": "bridge"}],
             routes6=[("default", "fe80::1", "eth0"), ("2001:db8:20::/64", None, "eth0")],
             packages={**UBUNTU_PKGS, "docker-ce": "5:27.3.1-1~ubuntu.24.04~noble"}),
        host("web01", "10.0.20.21", ubuntu=True,
             services=[*BASE_SERVICES, ("nginx.service", "active", "running", "enabled", "A high performance web server")],
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "0.0.0.0", 80, "nginx", 1200),
                      ("tcp", "0.0.0.0", 443, "nginx", 1200), ("tcp", "[::]", 443, "nginx", 1200)],
             packages={**UBUNTU_PKGS, "nginx": "1.24.0-2ubuntu7.1"}),
        host("db01", "10.0.20.31",
             probe=("0.9.0", OLD_PROBE_SHA),
             services=[*BASE_SERVICES, ("postgresql@15-main.service", "active", "running", "enabled",
                                        "PostgreSQL Cluster 15-main")],
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "10.0.20.31", 5432, "postgres", 3000)],
             packages={**BASE_PKGS, "postgresql-15": "15.8-0+deb12u1"},
             cron={"/etc/crontab": ["SHELL=/bin/sh"],
                   "/var/spool/cron/crontabs/postgres": [
                       "# m h dom mon dow command",
                       "30 2 * * * PGPASSWORD=pg-ATLASFAKE-backup pg_dumpall -h 127.0.0.1 -U postgres | gzip > /srv/dump.gz"]}),
        host("mediatheque", "10.0.20.50", hostname="médiathèque", broken={"lsblk"},
             mounts=[("/", "/dev/sda1", "ext4", 33285996544, 9123456789)]),
        host("backup01", "10.0.20.40",
             # Something no catalog entry knows: shows up under "Unrecognised ports" (ADR-034).
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "[::]", 22, "sshd", 812),
                      ("udp", "127.0.0.53%lo", 53, "systemd-resolve", 600),
                      ("tcp", "0.0.0.0", 8077, "labelmaker", 1400)],
             cron={"/etc/crontab": ["SHELL=/bin/sh"],
                   "/etc/cron.d/restic": [
                       "RESTIC_PASSWORD=rp-ATLASFAKE-2026a",
                       "0 3 * * * root restic -r s3:https://s3.example/backups backup /srv --password-file /run/secrets/restic",
                       "15 3 * * * root curl -fsS 'https://hc.example/ping/abc?token=hc-ATLASFAKE-0001' >/dev/null"]},
             packages={**BASE_PKGS, "restic": "0.14.0-1+b5"}),
        host("pi-garage", "10.0.20.60", virt="none", arch="aarch64", kernel="6.6.51+rpt-rpi-v8",
             # A generic interpreter on a port: named per machine, by port (ADR-034).
             sockets=[("tcp", "0.0.0.0", 22, "sshd", 812), ("tcp", "[::]", 22, "sshd", 812),
                      ("udp", "127.0.0.53%lo", 53, "systemd-resolve", 600),
                      ("tcp", "0.0.0.0", 5000, "python3", 1500)],
             packages={**BASE_PKGS, "raspberrypi-kernel": "1:1.20241008-1", "linux-image-rpi-v8": "1:6.6.51-1+rpt3"}),
        host("media01", "10.0.20.55", virt="lxc", veth=1,
             ifaces=[{"name": "eth0", "mac": mac("media01"), "addrs": ["10.0.20.55/24"], "kind": None},
                     {"name": "docker0", "mac": mac("media01", 1), "addrs": ["172.17.0.1/16"], "kind": "bridge"}],
             packages={**BASE_PKGS, "docker-ce": "5:26.1.5-1~debian.12~bookworm"},
             mounts=[("/", "/dev/mapper/pve-vm--204--disk--0", "ext4", 8589934592, 3221225472),
                     ("/mnt/media", "nas.lab.example:/media", "nfs4", 8001563222016, 4000000000000)]),
        host("legacy01", "10.0.20.70", ubuntu=True, kernel="5.15.0-122-generic",
             os=("ubuntu", "22.04", "jammy", "Ubuntu 22.04.5 LTS")),
        host("ipv6only01", "2001:db8:20::80",
             ifaces=[{"name": "eth0", "mac": mac("ipv6only01"), "addrs": ["2001:db8:20::80/64", "fe80::be24:11ff:fe00:80/64"], "kind": None}],
             routes4=[], routes6=[("default", "fe80::1", "eth0"), ("2001:db8:20::/64", None, "eth0")],
             nameservers=["2001:db8:20::1"],
             sockets=[("tcp", "[::]", 22, "sshd", 812), ("tcp", "[::]", 443, "caddy", 1300),
                      ("udp", "[fe80::be24:11ff:fe00:80%eth0]", 546, "systemd-network", 400)]),
    ]
    return hosts


def state_b(a: list[dict[str, Any]]) -> list[dict[str, Any]]:
    b = copy.deepcopy(a)
    by = {h["name"]: h for h in b}
    for h in b:  # volatile churn everywhere: must not produce events
        h["uptime"] += 86400.0
        h["veth"] += 1 if h["veth"] else 0
        h["sockets"] = [(p, a_, port, proc, pid + 7) for p, a_, port, proc, pid in h["sockets"]]
        h["mounts"] = [(t, s, f, size, used + 4096) for t, s, f, size, used in h["mounts"]]

    d1 = by["docker01"]
    d1["kernel"] = "6.1.0-26-amd64"
    d1["packages"]["linux-image-amd64"] = "6.1.112-1"
    d1["packages"]["linux-image-6.1.0-26-amd64"] = "6.1.112-1"

    d2 = by["docker02"]
    d2["ifaces"].append(
        {
            "name": "br-1a2b3c4d5e6f",
            "mac": mac("docker02", 2),
            "addrs": ["172.18.0.1/16"],
            "kind": "bridge",
        }
    )

    w = by["web01"]
    w["sockets"].append(("tcp", "0.0.0.0", 8443, "nginx", 1207))
    w["users"].append(("deploy", 1001, 1001, "/home/deploy", "/bin/bash"))
    w["groups"]["deploy"] = 1001
    w["groups"]["members"] = {**w["groups"]["members"], "docker": ["ops"]}

    p2 = by["pve2"]
    p2["kernel"] = "6.14.11-1-pve"
    p2["packages"] |= {"pve-manager": "9.2.2", "proxmox-kernel-6.14": "6.14.11-1"}

    db = by["db01"]
    db["probe"] = (PROBE_VER, PROBE_SHA)
    db["services"] = [s if s[0] != "postgresql@15-main.service" else (s[0], "failed", "failed", s[3], s[4])
                      for s in db["services"]]

    bk = by["backup01"]
    bk["cron"]["/etc/cron.d/restic"][0] = "RESTIC_PASSWORD=rp-ATLASFAKE-2026b"
    bk["packages"]["openssh-server"] = "1:9.2p1-2+deb12u4"
    # Non-key packages: folded into a single packages.changed event.
    for p, v in (
        ("tzdata", "2025a-0+deb12u1"),
        ("rsync", "3.2.7-1+deb12u3"),
        ("less", "590-2.1~deb12u3"),
    ):
        bk["packages"][p] = v

    m = by["mediatheque"]
    m["ifaces"][0]["addrs"].append("2001:db8:20::50/64")
    m["mounts"].append(
        ("/mnt/media", "nas.lab.example:/media", "nfs4", 8001563222016, 4000000000000)
    )

    by["pi-garage"]["nameservers"] = ["10.0.10.53"]
    return [h for h in b if h["name"] != "legacy01"]  # legacy01 goes offline


# ------------------------------------------------------------------ renderers


def frame(name: str, section: str, parts: list[tuple[str, str, int]]) -> bytes:
    bnd = hashlib.sha256(f"{name}/{section}".encode()).hexdigest()[:24]
    out = [f"ATLAS-PROBE 1 {section} {bnd}\n"]
    for pname, content, rc in parts:
        out.append(f"--{bnd} part {pname}\n{content}\n--{bnd} rc {rc}\n")
    out.append(f"--{bnd} end\n")
    return "".join(out).encode()


def render(h: dict[str, Any]) -> dict[str, bytes]:
    n = h["name"]
    os_id, ver, code, pretty = h["os"]
    osrel = f'PRETTY_NAME="{pretty}"\nNAME="{pretty.split(" ")[0]}"\nVERSION_ID="{ver}"\nVERSION_CODENAME={code}\nID={os_id}\n'
    addr, link = [], []
    lo = {"ifindex": 1, "ifname": "lo", "mtu": 65536, "operstate": "UNKNOWN", "link_type": "loopback",
          "address": "00:00:00:00:00:00", "addr_info": [
              {"family": "inet", "local": "127.0.0.1", "prefixlen": 8, "scope": "host"},
              {"family": "inet6", "local": "::1", "prefixlen": 128, "scope": "host"}]}
    addr.append(lo)
    link.append({"ifname": "lo"})
    for i, iface in enumerate(h["ifaces"], start=2):
        infos = []
        for a in iface["addrs"]:
            ip, plen = a.split("/")
            fam = "inet6" if ":" in ip else "inet"
            scope = "link" if ip.startswith("fe80") else "global"
            infos.append({"family": fam, "local": ip, "prefixlen": int(plen), "scope": scope})
        addr.append({"ifindex": i, "ifname": iface["name"], "mtu": 1500, "operstate": "UP",
                     "link_type": "ether", "address": iface["mac"], "addr_info": infos})
        li: dict[str, Any] = {"ifname": iface["name"]}
        if iface["kind"]:
            li["linkinfo"] = {"info_kind": iface["kind"]}
            if iface["kind"] == "vlan":
                li["linkinfo"]["info_data"] = {"protocol": "802.1Q", "id": iface["vlan"]}
        link.append(li)
    for v in range(h["veth"]):
        vname = f"veth{hashlib.sha256(f'{n}{v}{h["uptime"]}'.encode()).hexdigest()[:7]}"
        addr.append({"ifindex": 100 + v, "ifname": vname, "mtu": 1500, "operstate": "UP",
                     "address": mac(n, 50 + v), "addr_info": [], "master": "docker0"})
        link.append({"ifname": vname, "linkinfo": {"info_kind": "veth"}})
    r4 = [{"dst": d, **({"gateway": g} if g else {}), "dev": dev, "protocol": "static" if g else "kernel"}
          for d, g, dev in h["routes4"]]
    r6 = [{"dst": d, **({"gateway": g} if g else {}), "dev": dev, "protocol": "ra" if g else "kernel", "metric": 1024}
          for d, g, dev in h["routes6"]]
    neigh = [{"dst": "10.0.20.1", "dev": "eth0", "lladdr": "e4:38:83:00:00:01", "state": ["REACHABLE"]},
             {"dst": "10.0.20.99", "dev": "eth0", "lladdr": "aa:bb:cc:00:00:99", "state": ["STALE"]}]
    resolv = "\n".join(
        [f"nameserver {x}" for x in h["nameservers"]] + [f"search {' '.join(h['search'])}"]
    )
    ss = []
    for proto, ad, port, proc, pid in h["sockets"]:
        state = "LISTEN" if proto == "tcp" else "UNCONN"
        peer = "[::]:*" if ad.startswith("[") else "0.0.0.0:*"
        ss.append(
            f'{proto}   {state} 0      4096   {ad}:{port}   {peer}    users:(("{proc}",pid={pid},fd=3))'
        )
    blk = {"blockdevices": [
        {"name": d, "type": "disk", "size": size, "fstype": None, "mountpoint": None, "model": model,
         "children": [{"name": p, "type": "part", "size": ps, "fstype": fs, "mountpoint": mp, "model": None}
                      for p, ps, fs, mp in parts]}
        for d, size, model, parts in h["disks"]] + [
        {"name": "loop0", "type": "loop", "size": 1, "fstype": None, "mountpoint": None, "model": None}]}
    mnts = [{"target": t, "source": s, "fstype": f, "size": size, "used": used, "avail": size - used}
            for t, s, f, size, used in h["mounts"]]
    fm = {"filesystems": [{**mnts[0], "children": [
        {"target": "/proc", "source": "proc", "fstype": "proc", "size": 0, "used": 0, "avail": 0},
        {"target": "/run", "source": "tmpfs", "fstype": "tmpfs", "size": 1, "used": 1, "avail": 0},
        *mnts[1:]]}]}
    units = [
        {"unit": u, "load": "loaded", "active": a, "sub": s, "description": d}
        for u, a, s, _, d in h["services"]
    ]
    files_ = [{"unit_file": u, "state": e, "preset": "enabled"} for u, _, _, e, _ in h["services"]]
    timers = [{"next": 1760850000000000, "left": 3600000000, "last": None, "passed": None,
               "unit": t, "activates": act} for t, act in h["timers"]]
    groups = {k: v for k, v in h["groups"].items() if k != "members"}
    members = h["groups"]["members"]
    passwd = "\n".join(
        f"{u}:x:{uid}:{gid}:{u.title()} ATLASFAKE GECOS,,,:{home}:{sh}"
        for u, uid, gid, home, sh in h["users"]
    )
    group = "\n".join(
        f"{g}:x:{gid}:{','.join(members.get(g, []))}"
        for g, gid in sorted(groups.items(), key=lambda x: x[1])
    )
    dpkg = "\n".join(f"{p}\t{v}\tii " for p, v in sorted(h["packages"].items()))
    lsblk_text = "{ this is not json" if "lsblk" in h["broken"] else json.dumps(blk)
    return {
        "version": frame(n, "version", [("version", h["probe"][0], 0),
                                        ("sha256", f"{h['probe'][1]}  /usr/local/libexec/atlas-probe", 0)]),
        "os": frame(n, "os", [("os-release", osrel, 0), ("kernel", h["kernel"], 0), ("arch", h["arch"], 0),
                              ("hostname", h["hostname"], 0), ("machine-id", h["machine_id"], 0),
                              ("uptime", f"{h['uptime']:.2f} 1234567.89", 0),
                              ("virt", h["virt"], 1 if h["virt"] == "none" else 0),
                              ("timezone", "Europe/Paris", 0)]),
        "net": frame(n, "net", [("addr", json.dumps(addr), 0), ("link", json.dumps(link), 0),
                                ("route4", json.dumps(r4), 0), ("route6", json.dumps(r6), 0),
                                ("neigh", json.dumps(neigh), 0), ("resolv", resolv, 0)]),
        "ports": frame(n, "ports", [("listen", "\n".join(ss), 0)]),
        "storage": frame(n, "storage", [("lsblk", lsblk_text, 0), ("findmnt", json.dumps(fm), 0)]),
        "services": frame(n, "services", [("units", json.dumps(units), 0), ("unit-files", json.dumps(files_), 0),
                                          ("timers", json.dumps(timers), 0)]),
        "cron": frame(n, "cron", [(f"cron:{src}", "\n".join(lines), 0) for src, lines in sorted(h["cron"].items())]),
        "users": frame(n, "users", [("passwd", passwd, 0), ("group", group, 0)]),
        "packages": frame(n, "packages", [("dpkg", dpkg, 0)]),
    }


def procs_frame(h: dict[str, Any]) -> bytes:
    """ps -eo pid=,ppid=,user=,pcpu=,pmem=,rss=,etimes=,comm=,args= (top CPU first)."""
    rows = [(1, 0, "root", 0.0, 0.1, 12000, "systemd", "/sbin/init")]
    pid = 300
    for unit, active, _sub, _en, _desc in h["services"]:
        if active != "active":
            continue
        pid += 37
        comm = unit.removesuffix(".service").split("@")[0][:15]
        rows.append((pid, 1, "root", 0.1, 0.2, 9000 + pid, comm, f"/usr/sbin/{comm}"))
    for _proto, _ad, port, proc, ppid in h["sockets"]:
        args = f"{proc} worker" if proc.startswith("pve") else f"/usr/bin/{proc} --port {port}"
        rows.append((ppid, 1, "root" if port < 1024 else "app", 0.3, 0.5, 20000 + port, proc[:15], args))
    if h["name"] in DOCKER_HOSTS:
        rows.append((900, 1, "root", 1.2, 2.5, 80000, "dockerd", "/usr/bin/dockerd -H fd://"))
        rows.append((901, 900, "root", 0.4, 0.8, 30000, "containerd", "/usr/bin/containerd"))
    rows.append((50, 2, "root", 0.0, 0.0, 0, "kworker/0:1", "[kworker/0:1-events]"))  # kernel thread
    seen, lines = set(), []
    for r in sorted(rows, key=lambda r: (-r[3], r[0])):
        if r[0] in seen:
            continue
        seen.add(r[0])
        lines.append(f"{r[0]:>7} {r[1]:>7} {r[2]:<8} {r[3]:>4} {r[4]:>4} {r[5]:>8} {864000 - r[0]:>8} {r[7]}")
    return frame(h["name"], "procs", [("ps", "\n".join(lines), 0)])


def pve_frame(h: dict[str, Any]) -> bytes:
    """/etc/pve as a cluster node sees it (cluster-wide configs, own running state)."""
    s = h.get("pve")
    if s is None:  # not a Proxmox VE node
        return frame(h["name"], "pve", [("pveversion", "", 127), ("qemu-running", "", 2),
                                        ("lxc-running", "", 2)])
    nodes = s["nodes"]
    members = {"nodename": h["name"], "version": 7,
               "cluster": {"name": "homelab", "version": 2, "nodes": len(nodes), "quorate": 1},
               "nodelist": {n: {"id": i + 1, "online": 1, "ip": v["ip"]}
                            for i, (n, v) in enumerate(sorted(nodes.items()))}}
    guests = sorted(s["guests"].values(), key=lambda g: g[0])
    vmlist = {"version": 9, "ids": {str(g[0]): {"node": g[3], "type": g[1], "version": 1} for g in guests}}
    parts = [("pveversion", f"pve-manager/{nodes[h['name']]['pve']}/abc123 (running kernel: {h['kernel']})", 0),
             ("pve:/etc/pve/.members", json.dumps(members, indent=1), 0),
             ("pve:/etc/pve/.vmlist", json.dumps(vmlist, indent=1), 0)]
    for vmid, kind, name, node, _status, cores, mem, tags, _ips in guests:
        m = _proxmox.mac(name).upper()
        if kind == "qemu":
            body = [f"name: {name}", f"cores: {cores}", f"memory: {mem}", "ostype: l26", "agent: 1",
                    f"net0: virtio={m},bridge=vmbr0,tag=20,firewall=1", "scsi0: local-lvm:vm-disk-0,size=32G",
                    "onboot: 1", "cipassword: $5$ATLASFAKEsalt$ATLASFAKEhashATLASFAKEhashATLASFAKEhash0000"]
            path = f"/etc/pve/nodes/{node}/qemu-server/{vmid}.conf"
        else:
            body = [f"hostname: {name}", f"cores: {cores}", f"memory: {mem}", "ostype: debian", "unprivileged: 1",
                    f"net0: name=eth0,bridge=vmbr0,hwaddr={m},ip=dhcp,tag=20,type=veth",
                    "rootfs: local-lvm:vm-disk-0,size=8G"]
            path = f"/etc/pve/nodes/{node}/lxc/{vmid}.conf"
        if tags:
            body.append(f"tags: {tags}")
        body += ["", "[before-upgrade]", f"name: {name}-old", "memory: 1"]  # snapshot section is ignored
        parts.append((f"pve:{path}", "\n".join(body), 0))
    own = [g for g in guests if g[3] == h["name"] and g[4] == "running"]
    parts.append(("qemu-running", "\n".join(f"{g[0]}.pid\n{g[0]}.qmp" for g in own if g[1] == "qemu"), 0))
    parts.append(("lxc-running", "\n".join(str(g[0]) for g in own if g[1] == "lxc"), 0))
    return frame(h["name"], "pve", parts)


DOCKER_HOSTS = {"docker01", "docker02", "media01"}


def pi_frame(label: str) -> bytes:
    """vcgencmd output; B: under-voltage and throttling have occurred since boot (0x50000)."""
    throttled, temp = ("0x0", "51.0") if label == "state-A" else ("0x50000", "63.2")
    return frame("pi-garage", "pi", [
        ("model", "Raspberry Pi 5 Model B Rev 1.0\x00", 0),
        ("temp", f"temp={temp}'C", 0),
        ("throttled", f"throttled={throttled}", 0),
        ("thermal", str(int(float(temp) * 1000)), 0),
    ])


def hosts_yaml(hosts: list[dict[str, Any]]) -> str:
    lines = [
        "# Synthetic demo lab -- generated by fixtures/demo-lab/generate.py. Nothing here is real.",
        "version: 1",
        "defaults:",
        "  ssh: { user: atlas-ro, key: ssh_atlas_demo }",
        "sources:",
        "  proxmox:",
        "    - name: homelab",
        '      url: "https://pve1.lab.example:8006/api2/json"',
        "      credential: proxmox_auditor",
        "      tls: { ca_file: pve-root-ca.pem }",
        "  unifi:",
        "    - name: ucg",
        '      url: "https://ucg.lab.example/proxy/network/integration"',
        "      credential: unifi_api_key",
        "      tls: { ca_file: ucg.pem, check_hostname: false }",
        "  unas:",
        "    - name: unas",
        '      url: "https://unas.lab.example"',
        "      credential: unas_api_key",
        "      drive_api: true",
        "      tls: { ca_file: unas.pem }",
        "hosts:",
    ]
    for h in [*hosts, host("ghost01", "10.0.20.99")]:
        ip = next(i["addrs"][0] for i in h["ifaces"] if i["addrs"]).split("/")[0]
        kind = (
            "pi"
            if h["name"].startswith("pi-")
            else "proxmox-node"
            if h["name"].startswith("pve")
            else "linux"
        )
        lines += [
            f"  - name: {h['name']}",
            f'    address: "{ip}"',
            f"    type: {kind}",
            f"    collectors: [{', '.join(['linux-ssh', *(['docker'] if h['name'] in DOCKER_HOSTS else []), *(['pi'] if h['name'].startswith('pi-') else [])])}]",
            "    ssh:",
            f'      host_keys: ["{host_key(h["name"])} {h["name"]}"]',
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    a = state_a()
    b = state_b(a)
    da = _docker.state_a()
    docker = {"state-A": da, "state-B": _docker.state_b(da)}
    pa = _proxmox.state_a()
    pve = {"state-A": pa, "state-B": _proxmox.state_b(pa)}
    ua = _unifi.state_a(mac)
    ucg = {"state-A": ua, "state-B": _unifi.state_b(ua)}
    for label, hosts in (("state-A", a), ("state-B", b)):
        root = HERE / label
        shutil.rmtree(root, ignore_errors=True)
        for h in hosts:
            d = root / h["name"]
            d.mkdir(parents=True)
            for section, data in render(h).items():
                (d / f"{section}.out").write_bytes(data)
            h["pve"] = pve[label] if h["name"] in ("pve1", "pve2") else None
            (d / "procs.out").write_bytes(procs_frame(h))
            (d / "pve.out").write_bytes(pve_frame(h))
            if h["name"] in docker[label]:
                (d / "docker.out").write_bytes(_docker.render(h["name"], docker[label][h["name"]], frame))
            if h["name"] == "pi-garage":
                (d / "pi.out").write_bytes(pi_frame(label))
        api = root / "_api"
        api.mkdir()
        for name, rec in (("homelab", _proxmox.render(pve[label])),
                          ("ucg", _unifi.render(ucg[label], mac)),
                          ("unas", _unifi.unas(label[-1]))):
            (api / f"{name}.json").write_bytes((json.dumps(rec, indent=1, sort_keys=True) + "\n").encode())
    (HERE / "hosts.yaml").write_bytes(hosts_yaml(a).encode())
    print(f"state-A: {len(a)} hosts, state-B: {len(b)} hosts (+ ghost01 never answers)")


if __name__ == "__main__":
    main()
