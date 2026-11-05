"""ADR-044: cloned VMs sharing /etc/machine-id are all kept, each under its own key."""

from pathlib import Path

from homelab_atlas.collectors.base import CollectorResult, FacetResult
from homelab_atlas.engine.scan import separate_shared_ids
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import Entity, Facet, Scan

MID = "d20f1233ced9447d8582057f761fb045"
KEY = f"host:{MID}"


def ssh(target: str) -> CollectorResult:
    return CollectorResult("linux-ssh", target, "ok", [FacetResult(KEY, "linux-host", target)])


def docker(target: str) -> CollectorResult:
    return CollectorResult(
        "docker",
        target,
        "ok",
        [
            FacetResult(KEY, "linux-host", target),
            FacetResult(f"ctr:{KEY}/n8n/n8n/1", "container", f"{target}/n8n", None, KEY),
            FacetResult(f"compose:{KEY}/n8n", "compose-project", f"{target}/n8n", None, KEY),
        ],
    )


def test_clones_in_one_scan_get_their_own_keys(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    results = [ssh("Jellyfin"), ssh("Automation-VM"), docker("Jellyfin"), docker("Automation-VM")]
    with rt.sessions() as s:
        separate_shared_ids(s, results, ["Automation-VM", "Jellyfin"])
    owner_ssh, owner_docker = results[1], results[3]
    assert owner_ssh.facets[0].entity_key == KEY and owner_ssh.errors == []
    assert owner_docker.facets[1].entity_key == f"ctr:{KEY}/n8n/n8n/1"
    clone_ssh, clone_docker = results[0], results[2]
    assert clone_ssh.facets[0].entity_key == "host:name:Jellyfin"
    assert [f.entity_key for f in clone_docker.facets] == [
        "host:name:Jellyfin",
        "ctr:host:name:Jellyfin/n8n/n8n/1",
        "compose:host:name:Jellyfin/n8n",
    ]
    assert {f.parent_key for f in clone_docker.facets[1:]} == {"host:name:Jellyfin"}
    assert "machine-id shared with Automation-VM" in clone_ssh.errors[0]
    assert clone_ssh.status == "ok"  # a note, not a failure


def _stored_owner(rt: Runtime, target: str) -> None:
    with rt.sessions() as s:
        scan = Scan(mode="demo", status="done")
        s.add(scan)
        s.flush()
        s.add(Entity(key=KEY, kind="linux-host", display_name=target))
        s.add(Facet(entity_key=KEY, collector="linux-ssh", target=target, scan_id=scan.id, data={}))
        s.commit()


def test_the_current_owner_keeps_the_key_even_when_scanned_alone_or_later(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    _stored_owner(rt, "Zabbix-VM")
    both = [ssh("Automation-VM"), ssh("Zabbix-VM")]
    alone = [ssh("Automation-VM")]
    with rt.sessions() as s:
        separate_shared_ids(s, both, ["Automation-VM", "Zabbix-VM"])
        separate_shared_ids(s, alone, ["Automation-VM", "Zabbix-VM"])
    assert both[1].facets[0].entity_key == KEY  # history stays where it is
    assert both[0].facets[0].entity_key == "host:name:Automation-VM"
    assert alone[0].facets[0].entity_key == "host:name:Automation-VM"  # no takeover


def test_a_removed_owner_releases_the_key_and_unique_ids_are_untouched(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    _stored_owner(rt, "Old-VM")  # no longer in the inventory
    alone = [ssh("Automation-VM")]
    unique = [
        CollectorResult("linux-ssh", "PVE1", "ok", [FacetResult("host:abc", "linux-host", "PVE1")])
    ]
    with rt.sessions() as s:
        separate_shared_ids(s, alone + unique, ["Automation-VM", "PVE1"])
    assert alone[0].facets[0].entity_key == KEY and alone[0].errors == []
    assert unique[0].facets[0].entity_key == "host:abc"
