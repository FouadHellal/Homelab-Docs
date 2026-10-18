"""Proxmox VE endpoints: the complete allowlist for the proxmox collector (ADR-004).

Every entry is GET. The privilege column was verified against the PVE source (2026-10-18,
master): pve-manager PVE/API2/{Cluster,Backup,Cluster/BackupInfo,Network}.pm, qemu-server
src/PVE/API2/Qemu/Agent.pm, pve-container src/PVE/API2/LXC.pm, pve-access-control
src/PVE/API2/AccessControl.pm. All are covered by the built-in PVEAuditor role, whose
privileges are the `audit` group of every category (AccessControl.pm create_roles()).
"""

from typing import Final

from homelab_atlas.security.allowlist import Endpoint

NODE: Final = r"[A-Za-z0-9][A-Za-z0-9.-]{0,62}"
VMID: Final = r"[1-9][0-9]{2,8}"

VERSION = Endpoint("pve.version", "GET", "/version")
CLUSTER_STATUS = Endpoint("pve.cluster.status", "GET", "/cluster/status")
RESOURCES = Endpoint("pve.cluster.resources", "GET", "/cluster/resources")
BACKUP_JOBS = Endpoint("pve.cluster.backup", "GET", "/cluster/backup")
NOT_BACKED_UP = Endpoint("pve.backup.not_backed_up", "GET", "/cluster/backup-info/not-backed-up")
HA_RESOURCES = Endpoint("pve.cluster.ha.resources", "GET", "/cluster/ha/resources")
NODE_STATUS = Endpoint("pve.node.status", "GET", "/nodes/{node}/status", {"node": NODE})
NODE_NETWORK = Endpoint("pve.node.network", "GET", "/nodes/{node}/network", {"node": NODE})
_GUEST = {"node": NODE, "vmid": VMID}
QEMU_CONFIG = Endpoint("pve.qemu.config", "GET", "/nodes/{node}/qemu/{vmid}/config", _GUEST)
QEMU_AGENT_IFACES = Endpoint(
    "pve.qemu.agent.ifaces", "GET", "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces", _GUEST
)
QEMU_AGENT_OSINFO = Endpoint(
    "pve.qemu.agent.osinfo", "GET", "/nodes/{node}/qemu/{vmid}/agent/get-osinfo", _GUEST
)
LXC_CONFIG = Endpoint("pve.lxc.config", "GET", "/nodes/{node}/lxc/{vmid}/config", _GUEST)
LXC_INTERFACES = Endpoint("pve.lxc.ifaces", "GET", "/nodes/{node}/lxc/{vmid}/interfaces", _GUEST)
PERMISSIONS = Endpoint("pve.access.permissions", "GET", "/access/permissions")

#: endpoint -> privilege it needs (documentation + `atlas doctor`).
PRIVILEGES: Final[dict[Endpoint, str]] = {
    VERSION: "any authenticated user",
    CLUSTER_STATUS: "Sys.Audit on /",
    RESOURCES: "per-object filter: VM.Audit, Sys.Audit, Datastore.Audit, SDN.Audit",
    BACKUP_JOBS: "Sys.Audit on /",
    NOT_BACKED_UP: "Sys.Audit on / (filtered by VM.Audit)",
    HA_RESOURCES: "Sys.Audit on /",
    NODE_STATUS: "Sys.Audit on /nodes/{node}",
    NODE_NETWORK: "any user; bridges need SDN access (SDN.Audit, in PVEAuditor)",
    QEMU_CONFIG: "VM.Audit on /vms/{vmid}",
    QEMU_AGENT_IFACES: "VM.GuestAgent.Audit on /vms/{vmid} (PVE 9; was VM.Monitor)",
    QEMU_AGENT_OSINFO: "VM.GuestAgent.Audit on /vms/{vmid}",
    LXC_CONFIG: "VM.Audit on /vms/{vmid}",
    LXC_INTERFACES: "VM.Audit on /vms/{vmid}",
    PERMISSIONS: "own permissions: any user/token",
}
COLLECT: Final = frozenset(PRIVILEGES) - {PERMISSIONS}
DOCTOR: Final = frozenset({VERSION, PERMISSIONS})
#: Privileges a read-only token may hold. Anything else makes `atlas doctor` fail.
AUDIT_PRIVILEGES: Final = frozenset(
    {
        "VM.Audit",
        "VM.GuestAgent.Audit",
        "Sys.Audit",
        "Datastore.Audit",
        "SDN.Audit",
        "Pool.Audit",
        "Mapping.Audit",
    }
)
