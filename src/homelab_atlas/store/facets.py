"""Read-side view of facets: one Proxmox fact per entity, whichever source knows best.

A Proxmox guest or node can be described three times (ADR-031):

* `proxmox`: the API (authoritative: running state, backups, HA, agent IPs);
* `pve-ssh`: the node's own `/etc/pve` read over SSH (its guests, their running state);
* `pve-ssh-peer`: another node's view of it through the shared pmxcfs (config only).

Readers (UI, exports, MCP) see a single `proxmox` facet: the strongest one present, with
`source` saying where it came from. Writers keep all three, so nothing is lost when the API
token is missing or wrong.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, Final

from homelab_atlas.store.tables import Facet

PVE_SSH: Final = "pve-ssh"
PVE_SSH_PEER: Final = "pve-ssh-peer"
#: Where a Proxmox guest/node fact is read from, strongest first.
PVE_FACETS: Final = ("proxmox", PVE_SSH, PVE_SSH_PEER)
SOURCE_LABELS: Final = {
    "proxmox": "Proxmox API",
    PVE_SSH: "the node, over SSH (/etc/pve)",
    PVE_SSH_PEER: "another cluster node, over SSH (/etc/pve)",
}


@dataclass(frozen=True, slots=True)
class FacetView:
    entity_key: str
    collector: str
    target: str
    scan_id: int
    data: dict[str, Any]
    source: str  # the stored facet name (differs from `collector` for Proxmox-over-SSH)


def facet_views(rows: Iterable[Facet]) -> list[FacetView]:
    """Plain, read-only copies of `rows` with Proxmox facets collapsed (see module doc)."""
    out: list[FacetView] = []
    best: dict[str, tuple[int, Facet]] = {}
    for f in rows:
        if f.collector in PVE_FACETS:
            rank = PVE_FACETS.index(f.collector)
            if f.entity_key not in best or rank < best[f.entity_key][0]:
                best[f.entity_key] = (rank, f)
            continue
        out.append(FacetView(f.entity_key, f.collector, f.target, f.scan_id, f.data, f.collector))
    for _, f in best.values():
        out.append(FacetView(f.entity_key, "proxmox", f.target, f.scan_id, f.data, f.collector))
    return out
