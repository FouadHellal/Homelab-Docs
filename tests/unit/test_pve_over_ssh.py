"""Proxmox VE nodes and guests documented over SSH alone (/etc/pve, ADR-028)."""

import asyncio
from pathlib import Path

from sqlalchemy import select

from homelab_atlas.collectors.linux_ssh.frame import parse_frame
from homelab_atlas.collectors.linux_ssh.parse import parse_procs, parse_pve, pve_conf
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.runtime import Inputs, Runtime, replay_http
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import Entity, Facet
from homelab_atlas.web.views import machines

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


def _scan_without_pve_api(tmp: Path) -> Runtime:
    rt = Runtime.open(tmp, mode="demo")
    for state in ("A", "B"):
        inv, ssh = load_lab(state, LAB)
        inv = inv.model_copy(update={"sources": inv.sources.model_copy(update={"proxmox": ()})})
        asyncio.run(
            rt.scan_engine(
                Inputs(inv, ssh, replay_http(load_api_recordings(state, LAB)), LAB)
            ).run()
        )
    return rt


def test_nodes_guests_and_links_from_ssh(tmp_path: Path) -> None:
    rt = _scan_without_pve_api(tmp_path / "d")
    with rt.sessions() as s:
        ents = {e.key: e for e in s.scalars(select(Entity))}
        nodes = {k for k, e in ents.items() if e.kind == "pve-node" and e.status != "gone"}
        assert nodes == {"pve:node:homelab/pve1", "pve:node:homelab/pve2"}
        vm = ents["pve:vm:homelab/101"]
        assert vm.display_name == "docker01 (VM 101)"
        assert vm.parent_key == "pve:node:homelab/pve1"
        assert (
            ents["pve:vm:homelab/103"].parent_key == "pve:node:homelab/pve2"
        )  # web01 migrated in B
        ct = s.get(Facet, ("pve:lxc:homelab/201", "pve-ssh"))  # from its own node
        assert ct is not None
        assert ct.data["status"] == "running"
        assert ct.data["nics"][0]["mac"]
        # The other node sees the same guest through the shared /etc/pve, state unknown.
        peer = s.get(Facet, ("pve:lxc:homelab/201", "pve-ssh-peer"))
        assert peer is not None
        assert peer.data["status"] == "unknown"
        # Nothing Proxmox-shaped is stored under linux-ssh (that is the host inside the guest).
        assert not [f for f in s.scalars(select(Facet).where(Facet.collector == "linux-ssh"))
                    if f.entity_key.startswith("pve:")]  # fmt: skip
        # Readers get one "proxmox" view per guest, from the strongest source.
        views = [v for v in facet_views(s.scalars(select(Facet)))
                 if v.entity_key == "pve:lxc:homelab/201"]  # fmt: skip
        assert [(v.collector, v.source) for v in views if v.collector != "reconcile"] == [
            ("proxmox", "pve-ssh")
        ]
        # The SSH host inside VM 101 is the same machine; the PVE1 host is the node.
        docker01 = next(
            e for e in ents.values() if e.kind == "linux-host" and e.display_name == "docker01"
        )
        assert docker01.same_as == "pve:vm:homelab/101"
        pve1 = next(e for e in ents.values() if e.kind == "linux-host" and e.display_name == "pve1")
        assert pve1.same_as == "pve:node:homelab/pve1"
        # No Proxmox API facets were written.
        assert not list(s.scalars(select(Facet).where(Facet.collector == "proxmox")))


def test_api_source_wins(tmp_path: Path) -> None:
    from tests.helpers import scanned_lab  # noqa: PLC0415

    rt = scanned_lab(tmp_path / "d")  # lab inventory has a Proxmox API source
    with rt.sessions() as s:
        # SSH data is kept as a fallback, but the API is what readers see.
        assert s.get(Facet, ("pve:vm:homelab/101", "pve-ssh")) is not None
        guests = [v for v in facet_views(s.scalars(select(Facet))) if v.collector == "proxmox"
                  and "vmid" in v.data]  # fmt: skip
        assert guests
        assert {v.source for v in guests} == {"proxmox"}
        cards = {m["short"]: m for m in machines(s)}
        assert cards["docker01"]["node"] == "pve1"


def test_pve_parser_reads_cluster_and_ignores_snapshots() -> None:
    frame = parse_frame((LAB / "state-B" / "pve1" / "pve.out").read_bytes(), ProbeSection.PVE)
    parsed = parse_pve(frame)
    pve = parsed.values["pve"]
    assert (pve.node, pve.cluster, pve.ip) == ("pve1", "homelab", "10.0.10.11")
    assert {m.name for m in pve.members} == {"pve1", "pve2"}
    refs = {g.vmid: g for g in pve.cluster_guests}
    assert refs[102].node == "pve2"
    assert refs[102].running is None  # another node's guest: state unknown here
    assert refs[101].running is True
    own = {g["vmid"] for g in parsed.values["_pve_guests"]}
    assert 101 in own
    assert 102 not in own
    assert pve_conf("name: a\nmemory: 2\n[snap]\nname: b\n") == {"name": "a", "memory": "2"}
    # A non-PVE host yields nothing.
    other = parse_frame((LAB / "state-B" / "docker01" / "pve.out").read_bytes(), ProbeSection.PVE)
    assert parse_pve(other).values["pve"] is None


def test_procs_parser_handles_spaces_and_skips_kernel_threads() -> None:
    frame = parse_frame((LAB / "state-B" / "pve1" / "procs.out").read_bytes(), ProbeSection.PROCS)
    procs = parse_procs(frame).values["processes"]
    names = {p.comm for p in procs}
    assert "pveproxy" in names
    assert not any(p.args and p.args.startswith("[") for p in procs)
    assert all(p.pid != 2 for p in procs)


def test_probe_never_reads_pve_secrets() -> None:
    probe = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "homelab_atlas"
        / "probe"
        / "templates"
        / "atlas-probe.sh"
    ).read_text(encoding="utf-8")
    section = probe[probe.index("    pve)") : probe.index(";;", probe.index("    pve)"))]
    reads = [ln for ln in section.splitlines() if ln.strip().startswith(("part ", "files "))]
    assert reads
    for ln in reads:
        assert "priv" not in ln, ln  # keys, API tokens, shadow.cfg (pmxcfs docs)
        assert "storage.cfg" not in ln, ln
        assert "user.cfg" not in ln, ln


def test_pve_guest_secrets_are_redacted(tmp_path: Path) -> None:
    rt = _scan_without_pve_api(tmp_path)
    with rt.sessions() as s:
        blobs = [str(f.data) for f in s.scalars(select(Facet)).all()]
    assert blobs
    assert not any("ATLASFAKEhash" in b for b in blobs)  # the cipassword hash never lands
