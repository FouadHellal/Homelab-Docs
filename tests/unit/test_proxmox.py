"""Proxmox collector: parsers, endpoint safety, degraded API answers, doctor checks."""

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from homelab_atlas.cli import app
from homelab_atlas.collectors.base import CollectContext
from homelab_atlas.collectors.proxmox import endpoints as ep
from homelab_atlas.collectors.proxmox import parse
from homelab_atlas.collectors.proxmox.collector import ProxmoxCollector
from homelab_atlas.inventory.hosts import load_inventory
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.models.proxmox import PveGuestFacts
from homelab_atlas.runtime import auth_header, live_http, replay_http
from homelab_atlas.security.allowlist import DENIED_SEGMENTS
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.security.secrets import SecretDir, SecretResolver
from homelab_atlas.security.ssh import SshRunner
from tests.helpers import MemoryAudit

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"


def test_all_endpoints_are_get_and_avoid_denied_segments() -> None:
    for e in ep.PRIVILEGES:
        assert e.method == "GET"
        assert not set(e.path_template.lower().split("/")) & DENIED_SEGMENTS
    assert ep.PERMISSIONS not in ep.COLLECT


def test_property_strings() -> None:
    nic = parse.qemu_nic("net0", "virtio=BC:24:11:AA:BB:CC,bridge=vmbr0,tag=20,firewall=1")
    assert (nic.model, nic.mac, nic.bridge, nic.vlan_tag, nic.firewall) == (
        "virtio",
        "bc:24:11:aa:bb:cc",
        "vmbr0",
        20,
        True,
    )
    lxc = parse.lxc_nic("net0", "name=eth0,bridge=vmbr1,hwaddr=BC:24:11:00:00:01,ip=dhcp,type=veth")
    assert (lxc.mac, lxc.bridge, lxc.vlan_tag) == ("bc:24:11:00:00:01", "vmbr1", None)
    assert parse.disk("ide2", "none,media=cdrom") is None
    d = parse.disk("mp0", "nas-nfs:201/vm-201-disk-1.raw,mp=/mnt/media,size=500G")
    assert d is not None
    assert (d.storage, d.size, d.mountpoint) == ("nas-nfs", "500G", "/mnt/media")


def test_guest_config_and_node_status() -> None:
    cfg = parse.guest_config(
        "qemu",
        {
            "cores": 4,
            "memory": "8192",
            "agent": "enabled=1,fstrim_cloned_disks=1",
            "tags": "prod;web",
            "net0": "virtio=AA:AA:AA:AA:AA:AA,bridge=vmbr0",
            "scsi0": "local-lvm:vm-1-disk-0,size=32G",
            "evil": {"x": 1},
        },
    )
    assert cfg["agent_enabled"] is True
    assert cfg["tags"] == ["prod", "web"]
    assert [d.slot for d in cfg["disks"]] == ["scsi0"]
    st = parse.node_status(
        {"data": {"pveversion": "pve-manager/9.2.1/abc", "kversion": "Linux 6.14.8-2-pve #1"}}
    )
    assert (st["pve_version"], st["kernel"]) == ("9.2.1", "6.14.8-2-pve")
    assert parse.node_status({"data": "garbage"})["pve_version"] is None


def test_agent_ips_skip_loopback_and_link_local() -> None:
    payload = {
        "data": {
            "result": [
                {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "prefix": 8}]},
                {
                    "name": "eth0",
                    "ip-addresses": [
                        {"ip-address": "10.0.20.11", "prefix": 24},
                        {"ip-address": "fe80::1", "prefix": 64},
                        {"ip-address": "2001:0db8::11", "prefix": 64},
                    ],
                },
            ]
        }
    }
    assert [i.address for i in parse.agent_ips(payload)] == ["10.0.20.11/24", "2001:db8::11/64"]


async def collect(state: str, mutate: Any = None) -> Any:
    inv, ssh = load_lab(state, LAB)
    recs = load_api_recordings(state, LAB)
    if mutate:
        mutate(recs["homelab"])
    audit = MemoryAudit()
    ctx = CollectContext(
        inventory=inv, ssh=SshRunner(transport=ssh, audit=audit), http=replay_http(recs)(audit)
    )
    return await ProxmoxCollector().collect("homelab", ctx), audit


async def test_full_collection_shape() -> None:
    result, audit = await collect("A")
    kinds = [f.kind for f in result.facets]
    assert kinds.count("pve-cluster") == 1
    assert kinds.count("pve-node") == 2
    assert kinds.count("pve-vm") + kinds.count("pve-lxc") == 14
    guests = {f.model.name: f.model for f in result.facets if isinstance(f.model, PveGuestFacts)}
    assert guests["homeassistant"].notes == ["guest agent not answering (HTTP 500)"]
    assert guests["docker01"].ips[0].address == "10.0.20.11/24"
    assert guests["debian-12-template"].template is True
    assert guests["win11"].backed_up is False
    assert guests["web01"].backed_up is True
    assert result.status == "ok"
    assert all(e.op.startswith("GET ") for e in audit.events)


async def test_unreachable_when_first_call_fails() -> None:
    result, _ = await collect("A", lambda r: r.pop("/api2/json/version"))
    assert result.status == "failed"
    assert result.facets == []


async def test_optional_calls_degrade_to_partial() -> None:
    def break_some(r: dict[str, Any]) -> None:
        r["/api2/json/cluster/backup"] = (403, b'{"data":null}')
        r["/api2/json/nodes/pve1/network"] = (500, b"{}")

    result, _ = await collect("A", break_some)
    assert result.status == "partial"
    assert "backup jobs: HTTP 403" in result.errors
    assert result.complete is True


async def test_token_that_sees_nothing_is_explained_and_removes_nothing() -> None:
    """Privilege separation without a token ACL: 200 OK, empty lists (the classic mistake)."""

    def blind(r: dict[str, Any]) -> None:
        r["/api2/json/cluster/status"] = (200, b'{"data":[]}')
        r["/api2/json/cluster/resources"] = (200, b'{"data":[]}')

    result, _ = await collect("A", blind)
    assert result.status == "partial"
    assert any("give the TOKEN itself the PVEAuditor role" in e for e in result.errors)
    assert result.complete is False  # an empty answer must not mark every guest removed


async def test_hostile_node_names_cannot_reach_other_paths() -> None:
    def evil(r: dict[str, Any]) -> None:
        body = json.loads(r["/api2/json/cluster/resources"][1])
        body["data"].append(
            {"type": "qemu", "vmid": 777, "node": "../../access/users", "status": "running"}
        )
        r["/api2/json/cluster/resources"] = (200, json.dumps(body).encode())

    result, audit = await collect("A", evil)
    assert "qemu 777 config: SecurityRefusal" in result.errors
    assert any(e.outcome == "refused" for e in audit.events)
    assert not any("access/users" in e.op for e in audit.events)


def test_auth_header_validation() -> None:
    good = auth_header(
        "pve-token", SecretStr("atlas@pve!collector=0a1b2c3d-1234-5678-9abc-def012345678")
    )
    assert good.value.get_secret_value().startswith("PVEAPIToken=atlas@pve!collector=")
    for bad in (
        "root@pam",
        "atlas@pve!x=not-a-uuid",
        "PVEAPIToken=a@b!c=" + "0" * 36,
        "a@b!c=" + "0" * 36 + "\n",
    ):
        with pytest.raises(SecurityRefusal):
            auth_header("pve-token", SecretStr(bad))


def test_live_http_requires_pinned_ca(tmp_path: Path) -> None:
    (tmp_path / "proxmox_auditor").write_text("atlas@pve!c=0a1b2c3d-1234-5678-9abc-def012345678")
    inv = load_inventory(LAB / "hosts.yaml")
    factory = live_http(SecretResolver([SecretDir(tmp_path, False)]), [tmp_path])(MemoryAudit())
    with pytest.raises(SecurityRefusal, match="CA/anchor file missing"):
        factory(ProxmoxCollector.source(inv, "homelab"), ep.COLLECT)


@pytest.mark.parametrize(
    ("perms", "ok", "text"),
    [
        (None, True, "read-only"),
        (
            {"/": {"Sys.Audit": 1, "VM.Audit": 1, "VM.Allocate": 1}},
            False,
            "NOT read-only: VM.Allocate",
        ),
        ({"/": {"Sys.Audit": 1}}, False, "missing"),
    ],
)
def test_doctor_token_privileges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, perms: Any, ok: bool, text: str
) -> None:
    lab = tmp_path / "lab"
    import shutil  # noqa: PLC0415

    shutil.copytree(LAB, lab)
    if perms is not None:
        f = lab / "state-B" / "_api" / "homelab.json"
        rec = json.loads(f.read_text("utf-8"))
        rec["/api2/json/access/permissions"]["body"]["data"] = perms
        f.write_text(json.dumps(rec), encoding="utf-8")
    monkeypatch.setenv("ATLAS_LAB_DIR", str(lab))
    monkeypatch.setenv("COLUMNS", "200")
    res = CliRunner().invoke(
        app, ["doctor", "--lab", "demo:B", "--host", "homelab", "--data-dir", str(tmp_path / "d")]
    )
    assert (res.exit_code == 0) is ok, res.output
    assert text in res.output


@pytest.mark.parametrize(
    ("path", "kind", "old", "new", "expected"),
    [
        (("online",), "changed", True, False, "node.offline"),
        (("online",), "changed", False, True, "node.online"),
        (("quorate",), "changed", True, False, "cluster.quorum_lost"),
        (("storages", "nas-nfs"), "removed", {}, None, "storage.removed"),
        (("backup_jobs", "daily", "enabled"), "changed", True, False, "backup.job_disabled"),
        (("backup_jobs", "daily", "schedule"), "changed", "02:30", "03:00", "backup.job_changed"),
        (("nics", "net0", "mac"), "changed", "aa", "bb", "guest.mac_changed"),
        (("nics", "net0", "vlan_tag"), "changed", 20, 30, "guest.nic_changed"),
        (("disks", "scsi0", "size"), "changed", "32G", "64G", "guest.disk_changed"),
        (("interfaces", "vmbr0", "cidr"), "changed", "a", "b", "network.iface_changed"),
        (("node_names", "pve3"), "added", None, "pve3", "cluster.node_added"),
        (("ha_state",), "changed", "started", "error", "ha.state_changed"),
        (("tags", "web"), "added", None, "web", "guest.tags_changed"),
        (("weird",), "changed", 1, 2, "facts.changed"),
    ],
)
def test_proxmox_event_rules(
    path: tuple[str, ...], kind: Any, old: Any, new: Any, expected: str
) -> None:
    from homelab_atlas.collectors.proxmox.events import proxmox_events  # noqa: PLC0415
    from homelab_atlas.engine.diff import Change  # noqa: PLC0415

    (event,) = proxmox_events("k", "x", [Change(path, kind, old, new)])
    assert event.type == expected


def test_guest_ip_events_suppressed_when_power_state_changes() -> None:
    from homelab_atlas.collectors.proxmox.events import proxmox_events  # noqa: PLC0415
    from homelab_atlas.engine.diff import Change  # noqa: PLC0415

    changes = [
        Change(("status",), "changed", "running", "stopped"),
        Change(("ips", "10.0.20.11/24"), "removed", {}, None),
        Change(("agent_os",), "changed", "Debian", None),
    ]
    assert [e.type for e in proxmox_events("k", "x", changes)] == ["guest.stopped"]
