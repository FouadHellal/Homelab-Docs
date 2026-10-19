"""Parsers: framed probe output → linux fact fragments.

Every parser is total: it never raises on hostile or malformed input. It returns what it
could parse plus error strings (no raw content in errors).
"""

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import Any, Final, Literal

from homelab_atlas.collectors.linux_ssh.frame import Frame
from homelab_atlas.models.linux import (
    BlockDevice,
    CronEntry,
    Interface,
    IpAddress,
    ListeningSocket,
    LocalUser,
    Mount,
    Neighbor,
    OsInfo,
    Package,
    ProbeInfo,
    Process,
    PveGuestRef,
    PveMember,
    PveNodeSummary,
    Route,
    Service,
    Timer,
)

MAX_ITEMS: Final = 20_000
MACHINE_ID_RE: Final = re.compile(r"[0-9a-f]{32}")
MAC_RE: Final = re.compile(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}")
SS_PROC_RE: Final = re.compile(r'users:\(\("([^"]{1,64})",pid=(\d+)')
PSEUDO_FS: Final = frozenset(
    {
        "proc", "sysfs", "cgroup", "cgroup2", "devtmpfs", "tmpfs", "devpts", "overlay",
        "squashfs", "nsfs", "tracefs", "debugfs", "securityfs", "pstore", "bpf", "autofs",
        "mqueue", "hugetlbfs", "configfs", "fusectl", "binfmt_misc", "efivarfs", "ramfs",
        "rpc_pipefs", "fuse.lxcfs", "fuse.gvfsd-fuse", "fuse.portal", "selinuxfs",
    }
)  # fmt: skip


@dataclass(slots=True)
class Parsed:
    values: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _json(frame: Frame, part: str, out: Parsed) -> Any:
    text = frame.text(part)
    if text is None:
        out.errors.append(f"{part}: missing or failed")
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        out.errors.append(f"{part}: invalid JSON")
        return None


def _str(v: Any, limit: int = 512) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _int(v: Any) -> int | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.isdigit():
        return int(v)
    return None


def norm_mac(v: Any) -> str | None:
    if not isinstance(v, str):
        return None
    mac = v.strip().lower()
    return mac if MAC_RE.fullmatch(mac) and mac != "00:00:00:00:00:00" else None


def norm_ip(v: str) -> str:
    """Canonical text form of an IP or prefix (compressed IPv6, no zone)."""
    v = v.split("%", 1)[0]
    try:
        if "/" in v:
            iface = ipaddress.ip_interface(v)
            return f"{iface.ip.compressed}/{iface.network.prefixlen}"
        return ipaddress.ip_address(v).compressed
    except ValueError:
        return v


# ------------------------------------------------------------------ version / os


def parse_version(frame: Frame, expected_sha256: str) -> Parsed:
    out = Parsed()
    version = (frame.text("version") or "").strip()
    sha = (frame.text("sha256") or "").split(" ", 1)[0].strip()
    if version and sha == "inline":
        # Password mode: atlas streamed its own bundled probe, so there is nothing to pin.
        out.values["probe"] = ProbeInfo(
            version=version[:32], sha256="inline", expected_sha256=expected_sha256, matches=True
        )
        return out
    if not version or not re.fullmatch(r"[0-9a-f]{64}", sha):
        out.errors.append("version: unreadable")
        return out
    out.values["probe"] = ProbeInfo(
        version=version[:32], sha256=sha, expected_sha256=expected_sha256,
        matches=sha == expected_sha256,
    )  # fmt: skip
    return out


def parse_os_release(text: str) -> dict[str, str]:
    data: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if not sep or not re.fullmatch(r"[A-Z0-9_]{1,64}", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        data[key] = value[:256]
    return data


def parse_os(frame: Frame) -> Parsed:
    out = Parsed()
    hostname = (frame.text("hostname") or "").strip()
    if not hostname:
        out.errors.append("hostname: missing")
        return out
    rel = parse_os_release(frame.text("os-release") or "")
    mid = (frame.text("machine-id") or "").strip().lower()
    uptime_text = (frame.text("uptime") or "").split(" ", 1)[0]
    try:
        uptime: float | None = float(uptime_text)
    except ValueError:
        uptime = None
    virt = (frame.parts["virt"].content.strip() if "virt" in frame.parts else "") or None
    out.values["os"] = OsInfo(
        hostname=hostname[:253],
        machine_id=mid if MACHINE_ID_RE.fullmatch(mid) else None,
        os_id=rel.get("ID"),
        os_version_id=rel.get("VERSION_ID"),
        os_codename=rel.get("VERSION_CODENAME"),
        os_pretty=rel.get("PRETTY_NAME"),
        kernel=_str((frame.text("kernel") or "").strip(), 128),
        arch=_str((frame.text("arch") or "").strip(), 32),
        # systemd-detect-virt exits 1 and prints "none" on bare metal.
        virtualization=virt,
        timezone=_str((frame.text("timezone") or "").strip(), 64),
        uptime_s=uptime,
    )
    if out.values["os"].machine_id is None:
        out.errors.append("machine-id: missing or malformed")
    return out


# ------------------------------------------------------------------ net


def parse_net(frame: Frame) -> Parsed:
    out = Parsed()
    addrs = _json(frame, "addr", out)
    links = _json(frame, "link", out)
    kinds: dict[str, tuple[str | None, int | None]] = {}
    if isinstance(links, list):
        for link in links[:MAX_ITEMS]:
            if not isinstance(link, dict) or not isinstance(link.get("ifname"), str):
                continue
            raw_info = link.get("linkinfo")
            info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
            raw_data = info.get("info_data")
            data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}
            kinds[link["ifname"]] = (_str(info.get("info_kind"), 32), _int(data.get("id")))
    interfaces: list[Interface] = []
    veth = 0
    if isinstance(addrs, list):
        for item in addrs[:MAX_ITEMS]:
            if not isinstance(item, dict) or not isinstance(item.get("ifname"), str):
                continue
            name = item["ifname"][:64]
            kind, vlan_id = kinds.get(name, (None, None))
            if kind == "veth":
                veth += 1  # container plumbing: churns on every restart, never diffed
                continue
            ips = []
            for a in item.get("addr_info") or []:
                if not isinstance(a, dict) or a.get("family") not in ("inet", "inet6"):
                    continue
                local, plen = a.get("local"), _int(a.get("prefixlen"))
                if isinstance(local, str) and plen is not None:
                    ips.append(
                        IpAddress(address=norm_ip(f"{local}/{plen}"), family=a["family"],
                                  scope=_str(a.get("scope"), 16))
                    )  # fmt: skip
            interfaces.append(
                Interface(
                    name=name, mac=norm_mac(item.get("address")), mtu=_int(item.get("mtu")),
                    state=_str(item.get("operstate"), 16), kind=kind, vlan_id=vlan_id,
                    master=_str(item.get("master"), 64), addresses=ips,
                )
            )  # fmt: skip
    out.values["interfaces"] = interfaces
    out.values["veth_count"] = veth

    routes: list[Route] = []
    families: tuple[tuple[str, Literal["inet", "inet6"]], ...] = (
        ("route4", "inet"),
        ("route6", "inet6"),
    )
    for part, family in families:
        route_data = _json(frame, part, out)
        if not isinstance(route_data, list):
            continue
        for r in route_data[:MAX_ITEMS]:
            if not isinstance(r, dict) or not isinstance(r.get("dst"), str):
                continue
            dst = r["dst"] if r["dst"] == "default" else norm_ip(r["dst"])
            gw = r.get("gateway")
            routes.append(
                Route(family=family, dst=dst, gateway=norm_ip(gw) if isinstance(gw, str) else None,
                      dev=_str(r.get("dev"), 64), metric=_int(r.get("metric")),
                      protocol=_str(r.get("protocol"), 16))
            )  # fmt: skip
    out.values["routes"] = routes

    neighbors: list[Neighbor] = []
    neigh = _json(frame, "neigh", out)
    if isinstance(neigh, list):
        for n in neigh[:MAX_ITEMS]:
            if (
                isinstance(n, dict)
                and isinstance(n.get("dst"), str)
                and isinstance(n.get("dev"), str)
            ):
                state = n.get("state")
                neighbors.append(
                    Neighbor(ip=norm_ip(n["dst"]), dev=n["dev"][:64], mac=norm_mac(n.get("lladdr")),
                             state=",".join(state) if isinstance(state, list) else None)
                )  # fmt: skip
    out.values["neighbors"] = neighbors

    ns: list[str] = []
    search: list[str] = []
    for line in (frame.text("resolv") or "").splitlines():
        words = line.split()
        if len(words) >= 2 and words[0] == "nameserver":
            ns.append(norm_ip(words[1]))
        elif words and words[0] in ("search", "domain"):
            search.extend(w[:253] for w in words[1:7])
    out.values["nameservers"] = ns
    out.values["search_domains"] = search
    return out


# ------------------------------------------------------------------ ports


def _split_endpoint(text: str) -> tuple[str, int] | None:
    host, sep, port = text.rpartition(":")
    if not sep or not port.isdigit():
        return None
    host = host.split("%", 1)[0].strip("[]")
    return ("*" if host in ("*", "") else norm_ip(host)), int(port)


def parse_ports(frame: Frame) -> Parsed:
    out = Parsed()
    text = frame.text("listen")
    if text is None:
        out.errors.append("listen: missing or failed")
        return out
    seen: dict[tuple[str, str, int], ListeningSocket] = {}
    for line in text.splitlines()[:MAX_ITEMS]:
        cols = line.split(None, 6)
        if len(cols) < 6 or cols[0] not in ("tcp", "udp"):
            continue
        ep = _split_endpoint(cols[4])
        if ep is None:
            out.errors.append("listen: unparsable endpoint")
            continue
        proc = SS_PROC_RE.search(cols[6]) if len(cols) > 6 else None
        key = (cols[0], ep[0], ep[1])
        if key not in seen:
            seen[key] = ListeningSocket(
                proto=cols[0], address=ep[0], port=ep[1],  # type: ignore[arg-type]
                process=proc.group(1) if proc else None,
                pid=int(proc.group(2)) if proc else None,
            )  # fmt: skip
    out.values["sockets"] = list(seen.values())
    return out


# ------------------------------------------------------------------ storage


def _flatten(nodes: Any, key: str = "children") -> list[dict[str, Any]]:
    flat: list[dict[str, Any]] = []
    stack = list(nodes) if isinstance(nodes, list) else []
    while stack and len(flat) < MAX_ITEMS:
        node = stack.pop(0)
        if isinstance(node, dict):
            flat.append(node)
            children = node.get(key)
            if isinstance(children, list):
                stack[0:0] = children
    return flat


def parse_storage(frame: Frame) -> Parsed:
    out = Parsed()
    lsblk = _json(frame, "lsblk", out)
    devices = []
    if isinstance(lsblk, dict):
        for d in _flatten(lsblk.get("blockdevices")):
            if isinstance(d.get("name"), str) and d.get("type") not in ("loop", "rom"):
                devices.append(
                    BlockDevice(name=d["name"][:64], type=_str(d.get("type"), 16) or "?",
                                size_bytes=_int(d.get("size")), fstype=_str(d.get("fstype"), 32),
                                model=_str((d.get("model") or "").strip(), 64),
                                mountpoint=_str(d.get("mountpoint"), 256))
                )  # fmt: skip
    out.values["block_devices"] = devices
    fm = _json(frame, "findmnt", out)
    mounts = []
    if isinstance(fm, dict):
        for m in _flatten(fm.get("filesystems")):
            fstype = m.get("fstype")
            if (
                not isinstance(fstype, str)
                or fstype in PSEUDO_FS
                or not isinstance(m.get("target"), str)
            ):
                continue
            mounts.append(
                Mount(target=m["target"][:512], source=_str(m.get("source"), 512) or "?",
                      fstype=fstype[:32], size_bytes=_int(m.get("size")),
                      used_bytes=_int(m.get("used")), avail_bytes=_int(m.get("avail")))
            )  # fmt: skip
    out.values["mounts"] = mounts
    return out


# ------------------------------------------------------------------ services


def parse_services(frame: Frame) -> Parsed:
    out = Parsed()
    units = _json(frame, "units", out)
    files_ = _json(frame, "unit-files", out)
    enabled: dict[str, str] = {}
    if isinstance(files_, list):
        for f in files_[:MAX_ITEMS]:
            if isinstance(f, dict) and isinstance(f.get("unit_file"), str):
                enabled[f["unit_file"]] = _str(f.get("state"), 32) or "?"
    services = []
    if not isinstance(units, list):
        units = _units_text(frame.text("units-text"))
        if units:
            out.errors = [e for e in out.errors if not e.startswith("units:")]
    if isinstance(units, list):
        for u in units[:MAX_ITEMS]:
            if not isinstance(u, dict) or not isinstance(u.get("unit"), str):
                continue
            name = u["unit"][:256]
            services.append(
                Service(unit=name, load=_str(u.get("load"), 16), active=_str(u.get("active"), 16),
                        sub=_str(u.get("sub"), 16), enabled=enabled.get(name),
                        description=_str(u.get("description"), 256))
            )  # fmt: skip
    out.values["services"] = services
    timers = []
    data = _json(frame, "timers", out)
    if isinstance(data, list):
        for t in data[:MAX_ITEMS]:
            if isinstance(t, dict) and isinstance(t.get("unit"), str):
                timers.append(Timer(unit=t["unit"][:256], activates=_str(t.get("activates"), 256)))
    out.values["timers"] = timers
    return out


def _units_text(text: str | None) -> list[dict[str, str]] | None:
    """`systemctl list-units --plain --no-legend`: UNIT LOAD ACTIVE SUB DESCRIPTION."""
    if not text:
        return None
    units = []
    for raw in text.splitlines()[:MAX_ITEMS]:
        cols = raw.split(None, 4)
        if len(cols) >= 4 and cols[0].endswith(".service"):
            units.append(
                {
                    "unit": cols[0],
                    "load": cols[1],
                    "active": cols[2],
                    "sub": cols[3],
                    "description": cols[4] if len(cols) > 4 else "",
                }
            )
    return units or None


# ------------------------------------------------------------------ processes

MAX_PROCS: Final = 600


def parse_procs(frame: Frame) -> Parsed:
    """`ps -eo pid=,ppid=,user=,pcpu=,pmem=,rss=,etimes=,args=`; args last (it has spaces)."""
    out = Parsed()
    text = frame.text("ps")
    if text is None:
        out.errors.append("ps: missing or failed")
        return out
    procs = []
    for raw in text.splitlines():
        cols = raw.split(None, 7)
        if len(cols) < 8 or not cols[0].isdigit():
            continue
        pid, ppid = int(cols[0]), int(cols[1]) if cols[1].isdigit() else None
        args = cols[7]
        if pid == 2 or ppid == 2 or args.startswith("["):
            continue  # kernel threads
        comm = args.split()[0].rsplit("/", 1)[-1].rstrip(":")[:64] or "?"
        procs.append(
            Process(
                pid=pid,
                ppid=ppid,
                user=cols[2][:32],
                comm=comm,
                args=args[:512],
                cpu_pct=_float(cols[3]),
                mem_pct=_float(cols[4]),
                rss_kb=int(cols[5]) if cols[5].isdigit() else None,
                elapsed_s=int(cols[6]) if cols[6].isdigit() else None,
            )
        )
        if len(procs) >= MAX_PROCS:
            break
    out.values["processes"] = procs
    return out


def _float(v: str) -> float | None:
    try:
        return round(float(v), 1)
    except ValueError:
        return None


# ------------------------------------------------------------------ Proxmox VE node (ADR-028)

PVE_CONF_RE: Final = re.compile(
    r"/etc/pve/nodes/([A-Za-z0-9._-]{1,64})/(qemu-server|lxc)/(\d{1,9})\.conf"
)
PVE_VERSION_RE: Final = re.compile(r"pve-manager/([0-9][0-9A-Za-z.~+-]{0,31})")
PVE_NIC_MAC_RE: Final = re.compile(
    r"(?:^|,)(?:[a-z0-9]+=|hwaddr=)([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})"
)


def pve_conf(text: str) -> dict[str, str]:
    """`key: value` lines of a guest config, current section only (snapshots follow `[name]`)."""
    cfg: dict[str, str] = {}
    for raw in text.splitlines()[:2000]:
        line = raw.strip()
        if line.startswith("["):
            break
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition(":")
        if sep and re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", key):
            cfg[key] = value.strip()[:2048]
    return cfg


def parse_pve(frame: Frame) -> Parsed:
    """Values: `pve` (PveNodeSummary or None), `_pve_guests` (this node's own guests) and
    `_pve_peers` (guests of the other cluster nodes: pmxcfs shares every node's configs)."""
    out = Parsed()
    members_text = frame.text("pve:/etc/pve/.members")
    confs = {
        m.groups(): part.content
        for name, part in frame.parts.items()
        if part.rc == 0 and (m := PVE_CONF_RE.fullmatch(name.removeprefix("pve:")))
    }
    if members_text is None and not confs:
        out.values["pve"] = None  # not a Proxmox VE node
        return out
    try:
        members = json.loads(members_text) if members_text else {}
    except json.JSONDecodeError:
        out.errors.append(".members: invalid JSON")
        members = {}
    members = members if isinstance(members, dict) else {}
    node = _str(members.get("nodename"), 64) or next((n for n, _, _ in confs), None)
    if node is None:
        out.values["pve"] = None
        return out
    cl_raw, nl_raw = members.get("cluster"), members.get("nodelist")
    cluster: dict[str, Any] = cl_raw if isinstance(cl_raw, dict) else {}
    nodelist: dict[str, Any] = nl_raw if isinstance(nl_raw, dict) else {}
    member_rows = [
        PveMember(name=str(n)[:64], ip=_str(v.get("ip"), 64), online=bool(v.get("online")))
        for n, v in sorted(nodelist.items())
        if isinstance(v, dict)
    ]
    running_qemu = {
        x.split(".")[0] for x in (frame.text("qemu-running") or "").split() if x.endswith(".pid")
    }
    running_lxc = {x for x in (frame.text("lxc-running") or "").split() if x.isdigit()}
    refs: list[PveGuestRef] = []
    own: list[dict[str, Any]] = []
    peers: list[dict[str, Any]] = []
    for (gnode, kind_dir, vmid), text in sorted(confs.items(), key=lambda kv: int(kv[0][2])):
        cfg = pve_conf(text)
        kind: Literal["qemu", "lxc"] = "qemu" if kind_dir == "qemu-server" else "lxc"
        name = _str(cfg.get("name") or cfg.get("hostname"), 128) or f"{kind}-{vmid}"
        macs = sorted(
            {
                m.lower()
                for k, v in cfg.items()
                if re.fullmatch(r"net\d{1,2}", k)
                for m in PVE_NIC_MAC_RE.findall(v)
            }
        )
        running = None
        if gnode == node:  # running state is only visible on the guest's own node
            running = vmid in (running_qemu if kind == "qemu" else running_lxc)
        (own if gnode == node else peers).append(
            {
                "vmid": int(vmid),
                "type": kind,
                "name": name,
                "node": gnode,
                "running": running,
                "template": cfg.get("template") == "1",
                "cfg": cfg,
            }
        )
        refs.append(
            PveGuestRef(
                vmid=int(vmid), type=kind, name=name, node=gnode, macs=macs, running=running
            )
        )
    version = PVE_VERSION_RE.search(frame.text("pveversion") or "")
    self_ip = next((m.ip for m in member_rows if m.name == node), None)
    out.values["pve"] = PveNodeSummary(
        node=node,
        cluster=_str(cluster.get("name"), 64),
        version=version.group(1) if version else None,
        ip=self_ip,
        members=member_rows,
        cluster_guests=refs[:2000],
    )
    out.values["_pve_guests"] = own
    out.values["_pve_peers"] = peers[:2000]
    return out


# ------------------------------------------------------------------ cron / users / packages


def parse_cron(frame: Frame) -> Parsed:
    out = Parsed()
    entries = []
    for name, part in frame.parts.items():
        if not name.startswith("cron:") or part.rc != 0:
            continue
        for raw in part.content.splitlines()[:MAX_ITEMS]:
            line = raw.strip()
            if line and not line.startswith("#"):
                entries.append(CronEntry(source=name[5:], line=line[:1024]))
    out.values["cron"] = entries
    return out


def parse_users(frame: Frame) -> Parsed:
    out = Parsed()
    passwd = frame.text("passwd")
    if passwd is None:
        out.errors.append("passwd: missing or failed")
        return out
    members: dict[str, list[str]] = {}
    gid_name: dict[int, str] = {}
    for line in (frame.text("group") or "").splitlines()[:MAX_ITEMS]:
        f = line.split(":")
        if len(f) == 4 and f[2].isdigit():
            gid_name[int(f[2])] = f[0]
            for user in filter(None, f[3].split(",")):
                members.setdefault(user, []).append(f[0])
    users = []
    for line in passwd.splitlines()[:MAX_ITEMS]:
        f = line.split(":")
        # name:x:uid:gid:gecos:home:shell; GECOS (PII) is deliberately dropped.
        if len(f) != 7 or not f[2].isdigit() or not f[3].isdigit():
            continue
        groups = set(members.get(f[0], []))
        if int(f[3]) in gid_name:
            groups.add(gid_name[int(f[3])])
        users.append(
            LocalUser(name=f[0][:64], uid=int(f[2]), gid=int(f[3]), home=f[5][:256],
                      shell=f[6][:128], groups=sorted(groups))
        )  # fmt: skip
    out.values["users"] = users
    return out


def parse_packages(frame: Frame) -> Parsed:
    out = Parsed()
    text = frame.text("dpkg")
    if text is None:
        out.errors.append("dpkg: missing or failed")
        return out
    pkgs = []
    for line in text.splitlines()[:MAX_ITEMS]:
        f = line.split("\t")
        if len(f) == 3 and f[2].strip().startswith("ii"):
            pkgs.append(Package(name=f[0][:128], version=f[1][:128]))
    out.values["packages"] = pkgs
    return out
