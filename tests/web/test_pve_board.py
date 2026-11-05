"""ADR-045: Topology → Proxmox board, honest counts when the Proxmox API fails."""

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from homelab_atlas.collectors.proxmox import parse as pve_parse
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import CollectorRun, Scan
from homelab_atlas.web import command, views
from tests.helpers import scanned_lab


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    return scanned_lab(tmp_path_factory.mktemp("board"))


def test_board_groups_guests_under_their_node_with_usage(rt: Runtime) -> None:
    with rt.sessions() as s:
        board = views.proxmox_board(s)
    names = {b["node"]["short"]: b for b in board["nodes"]}
    assert set(names) == {"pve1", "pve2"}
    pve1 = {g["name"]: g for g in names["pve1"]["guests"]}
    assert "docker01" in pve1 and "docker01" not in {g["name"] for g in names["pve2"]["guests"]}
    d = pve1["docker01"]
    assert d["type"] == "VM" and d["vmid"] == 101 and not d["inferred"]
    assert d["usage"]["mem_max"] == 8192 * 1048576 and 0 < d["usage"]["mem_pct"] < 100
    assert d["usage"]["disk_max"] and d["usage"]["disk_pct"] is not None
    node = names["pve1"]
    assert (
        node["mem"]["pct"]
        and node["rootfs"]["total"]
        and node["cpu"]["loadavg"] == [0.42, 0.37, 0.31]
    )
    assert {st["name"] for st in node["storages"]} >= {"local-lvm", "nas-nfs"}
    # Every machine once.
    keys = [g["key"] for b in board["nodes"] for g in b["guests"]] + [
        g["key"] for g in board["unplaced"] + board["others"]
    ]
    assert len(keys) == len(set(keys))
    assert board["problem"] is None


def test_node_and_guest_usage_parsing_is_total() -> None:
    assert (
        pve_parse.guest_usage({"mem": 5, "maxmem": "10", "disk": None, "maxcpu": 2})[
            "mem_max_bytes"
        ]
        == 10
    )
    st = pve_parse.node_status({"data": {"loadavg": ["0.5", "x", "1e9"], "rootfs": "junk"}})
    assert st["loadavg"] == [0.5] and st["rootfs_total_bytes"] is None


def _cards_like_owner_lab() -> list[dict[str, Any]]:
    """The owner's lab with the Proxmox API failing: nodes and VMs seen over SSH only."""

    def host(name: str, ip: str, mac: str, uplink: str, apps: list[str]) -> dict[str, Any]:
        return {
            "key": f"host:name:{name}", "name": name, "short": name, "kind": "linux-host",
            "status": "known", "node": None, "vmid": None, "cores": None, "ips": [ip],
            "os": "Ubuntu",
            "mac": mac, "uplink": uplink, "vlan": 1000, "documented": True, "containers": 0,
            "apps": [{"name": a, "category": "x"} for a in apps], "usage": {}, "pve": None,
        }  # fmt: skip

    return [
        host("PVE1", "10.10.10.100", "a4:bb:6d:97:1d:8e", "USW-Fouad · port 2", ["Proxmox VE"]),
        host("PVE2", "10.10.10.101", "20:88:10:73:25:b3", "USW-Fouad · port 3", ["Proxmox VE"]),
        host("Taskora", "10.10.10.40", "bc:24:11:80:c0:56", "USW-Fouad · port 2", ["Docker"]),
        host("Jellyfin", "10.10.10.175", "bc:24:11:91:9b:e3", "USW-Fouad · port 3", ["Jellyfin"]),
        host("Netbox", "10.10.10.67", "bc:24:11:ed:15:d0", "USW-Fouad", ["Docker"]),
        host("RaspBerry-PI", "10.10.10.125", "2c:cf:67:4a:49:87", "USW-Fouad · port 7", []),
    ]


def test_api_failing_places_vms_by_switch_port_and_says_so(
    rt: Runtime, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(views, "machines", lambda _s: _cards_like_owner_lab())
    empty = Runtime.open(tmp_path, mode="demo")
    with empty.sessions() as s:
        scan = Scan(mode="demo", status="done")
        s.add(scan)
        s.flush()
        err = "HTTP 403: the token lacks permission: give it the PVEAuditor role on /"
        s.add(CollectorRun(scan_id=scan.id, target="HomeLab", collector="proxmox",
                           status="failed", errors=[err]))  # fmt: skip
        s.commit()
        board = views.proxmox_board(s)
        cards = command.summary(s, _cards_like_owner_lab(), {})
    nodes = {b["node"]["short"]: [g["name"] for g in b["guests"]] for b in board["nodes"]}
    assert nodes == {"PVE1": ["Taskora"], "PVE2": ["Jellyfin"]}
    assert all(g["inferred"] for b in board["nodes"] for g in b["guests"])
    assert [g["name"] for g in board["unplaced"]] == ["Netbox"]  # Proxmox NIC, no port known
    assert [g["name"] for g in board["others"]] == ["RaspBerry-PI"]
    assert board["problem"] and "403" in board["problem"]
    by_id = {c["id"]: c for c in cards}
    assert by_id["nodes"]["n"] == 2  # not 0: seen over SSH
    assert by_id["pve-vm"]["n"] == "?" and "403" in by_id["pve-vm"]["parts"][0]["label"]


def test_board_page_renders(rt: Runtime, tmp_path: Path) -> None:
    from fastapi.testclient import TestClient  # noqa: PLC0415

    from homelab_atlas.web import auth  # noqa: PLC0415
    from homelab_atlas.web.app import WebConfig, create_app  # noqa: PLC0415
    from tests.web.test_v8 import PASSWORD, _login  # noqa: PLC0415

    with rt.sessions() as s:
        if not s.scalars(select(CollectorRun).limit(1)).first():
            pytest.skip("no scans")
        try:
            auth.create_user(s, "admin", PASSWORD)
            s.commit()
        except Exception:  # noqa: BLE001 - created by an earlier test module
            s.rollback()
    app = create_app(
        WebConfig(sessions=rt.sessions, annotations_dir=tmp_path, allowed_hosts=["testserver"])
    )
    with TestClient(app, base_url="https://testserver") as c:
        _login(c)
        html = c.get("/topology").text
        assert 'class="pb-node"' in html and "docker01" in html and "nas-nfs" in html
        assert "cytoscape" not in html  # the board needs no graph library
        assert "cytoscape" in c.get("/topology?view=physical").text
