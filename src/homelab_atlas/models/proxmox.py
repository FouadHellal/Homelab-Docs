"""Facts collected by the proxmox API collector."""

from typing import Literal

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class BackupJob(Fact):
    id: str
    enabled: bool = True
    schedule: str | None = None
    storage: str | None = None
    mode: str | None = None
    all: bool = False
    vmids: list[str] = Field(default_factory=list)
    node: str | None = None
    comment: str | None = None


class HaResource(Fact):
    sid: str
    state: str | None = None
    group: str | None = None


class PveClusterFacts(Fact):
    name: str
    standalone: bool
    quorate: bool | None = None
    version: str | None = None
    node_names: list[str] = Field(default_factory=list)
    backup_jobs: list[BackupJob] = keyed("id")
    not_backed_up: list[str] = Field(default_factory=list)  # "qemu/110" style
    ha_resources: list[HaResource] = keyed("sid")
    section_errors: list[str] = volatile(factory=list)


class NodeInterface(Fact):
    iface: str
    type: str | None = None
    cidr: str | None = None
    cidr6: str | None = None
    gateway: str | None = None
    bridge_ports: list[str] = Field(default_factory=list)
    vlan_aware: bool = False
    vlan_id: int | None = None
    vlan_raw_device: str | None = None
    autostart: bool = False
    comments: str | None = None
    active: bool | None = volatile()


class Storage(Fact):
    storage: str
    type: str | None = None
    content: list[str] = Field(default_factory=list)
    shared: bool = False
    total_bytes: int | None = None
    status: str | None = None
    used_bytes: int | None = volatile()


class PveNodeFacts(Fact):
    name: str
    online: bool
    ip: str | None = None
    pve_version: str | None = None
    kernel: str | None = None
    cpu_model: str | None = None
    cpu_cores: int | None = None
    memory_bytes: int | None = None
    interfaces: list[NodeInterface] = keyed("iface")
    storages: list[Storage] = keyed("storage")
    uptime_s: int | None = volatile()
    cpu_load: float | None = volatile()


class GuestNic(Fact):
    slot: str
    model: str | None = None
    mac: str | None = None
    bridge: str | None = None
    vlan_tag: int | None = None
    firewall: bool = False
    link_down: bool = False


class GuestDisk(Fact):
    slot: str
    storage: str | None = None
    volume: str | None = None
    size: str | None = None
    mountpoint: str | None = None


class GuestIp(Fact):
    address: str
    iface: str | None = None


class PveGuestFacts(Fact):
    vmid: int
    type: Literal["qemu", "lxc"]
    name: str
    node: str
    status: str
    template: bool = False
    tags: list[str] = Field(default_factory=list)
    cores: int | None = None
    sockets: int | None = None
    memory_mb: int | None = None
    onboot: bool = False
    ostype: str | None = None
    agent_enabled: bool = False
    agent_os: str | None = None
    unprivileged: bool | None = None
    features: str | None = None
    ha_state: str | None = None
    backed_up: bool | None = None
    description: str | None = None
    nics: list[GuestNic] = keyed("slot")
    disks: list[GuestDisk] = keyed("slot")
    ips: list[GuestIp] = keyed("address")
    notes: list[str] = volatile(factory=list)  # e.g. "guest agent not running"
    cpu_load: float | None = volatile()
    uptime_s: int | None = volatile()
