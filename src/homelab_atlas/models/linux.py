"""Facts collected by the linux-ssh collector (Debian/Ubuntu)."""

from typing import Literal

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class ProbeInfo(Fact):
    version: str
    sha256: str
    expected_sha256: str
    matches: bool


class OsInfo(Fact):
    hostname: str
    machine_id: str | None = None
    os_id: str | None = None
    os_version_id: str | None = None
    os_codename: str | None = None
    os_pretty: str | None = None
    kernel: str | None = None
    arch: str | None = None
    virtualization: str | None = None
    timezone: str | None = None
    uptime_s: float | None = volatile()


class IpAddress(Fact):
    address: str  # with prefix, e.g. 10.0.20.11/24 or 2001:db8::11/64
    family: Literal["inet", "inet6"]
    scope: str | None = None


class Interface(Fact):
    name: str
    mac: str | None = None
    mtu: int | None = None
    state: str | None = volatile()
    kind: str | None = None  # bridge, vlan, bond, wireguard, ... (None = physical/unknown)
    vlan_id: int | None = None
    master: str | None = None
    addresses: list[IpAddress] = keyed("address")


class Route(Fact):
    family: Literal["inet", "inet6"]
    dst: str
    gateway: str | None = None
    dev: str | None = None
    metric: int | None = None
    protocol: str | None = None


class Neighbor(Fact):
    ip: str
    dev: str
    mac: str | None = None
    state: str | None = None


class ListeningSocket(Fact):
    proto: Literal["tcp", "udp"]
    address: str
    port: int
    process: str | None = None
    pid: int | None = volatile()


class BlockDevice(Fact):
    name: str
    type: str
    size_bytes: int | None = None
    fstype: str | None = None
    model: str | None = None
    mountpoint: str | None = None


class Mount(Fact):
    target: str
    source: str
    fstype: str
    size_bytes: int | None = None
    used_bytes: int | None = volatile()
    avail_bytes: int | None = volatile()


class Service(Fact):
    unit: str
    load: str | None = None
    active: str | None = None
    sub: str | None = volatile()
    enabled: str | None = None
    description: str | None = None


class Timer(Fact):
    unit: str
    activates: str | None = None


class CronEntry(Fact):
    source: str
    line: str  # redacted before storage


class LocalUser(Fact):
    name: str
    uid: int
    gid: int
    home: str
    shell: str
    groups: list[str] = Field(default_factory=list)


class Package(Fact):
    name: str
    version: str


class Process(Fact):
    """A running process (snapshot; never diffed: PIDs and CPU change all the time)."""

    pid: int
    ppid: int | None = None
    user: str | None = None
    comm: str
    args: str | None = None  # redacted before storage
    cpu_pct: float | None = None
    mem_pct: float | None = None
    rss_kb: int | None = None
    elapsed_s: int | None = None


class PveMember(Fact):
    name: str
    ip: str | None = None
    online: bool | None = None


class PveGuestRef(Fact):
    """A guest anywhere in the cluster, as this node's /etc/pve sees it."""

    vmid: int
    type: Literal["qemu", "lxc"]
    name: str
    node: str
    macs: list[str] = Field(default_factory=list)
    running: bool | None = None  # only known for this node's own guests


class PveNodeSummary(Fact):
    """This host is a Proxmox VE node (probe section `pve`, ADR-028)."""

    node: str
    cluster: str | None = None
    version: str | None = volatile()  # upgrades are reported once, on the PVE node entity
    ip: str | None = None
    members: list[PveMember] = volatile(factory=list)
    cluster_guests: list[PveGuestRef] = volatile(factory=list)


class LinuxHostFacts(Fact):
    probe: ProbeInfo | None = None
    os: OsInfo | None = None
    interfaces: list[Interface] = keyed("name")
    veth_count: int | None = volatile()
    routes: list[Route] = keyed("family", "dst", "gateway", "dev")
    nameservers: list[str] = Field(default_factory=list)
    search_domains: list[str] = Field(default_factory=list)
    neighbors: list[Neighbor] = volatile(factory=list)  # used for reconciliation, never diffed
    sockets: list[ListeningSocket] = keyed("proto", "address", "port")
    block_devices: list[BlockDevice] = keyed("name")
    mounts: list[Mount] = keyed("target")
    services: list[Service] = keyed("unit")
    timers: list[Timer] = keyed("unit")
    cron: list[CronEntry] = keyed("source", "line")
    users: list[LocalUser] = keyed("name")
    packages: list[Package] = keyed("name")
    processes: list[Process] = volatile(factory=list)
    pve: PveNodeSummary | None = None
    section_errors: dict[str, list[str]] = volatile(factory=dict)
