"""linux-ssh collector: one SSH session per host, one probe section at a time."""

import time
from collections.abc import Callable
from typing import Final

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh import parse
from homelab_atlas.collectors.linux_ssh.frame import Frame, FrameError, parse_frame
from homelab_atlas.collectors.proxmox import parse as pve_parse
from homelab_atlas.collectors.proxmox.events import proxmox_events
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, linux_events
from homelab_atlas.inventory.hosts import Inventory
from homelab_atlas.models.linux import LinuxHostFacts
from homelab_atlas.models.proxmox import PveGuestFacts, PveNodeFacts
from homelab_atlas.probe.render import probe_sha256
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import SecurityRefusal, TransportError
from homelab_atlas.store.facets import PVE_SSH, PVE_SSH_PEER

S = ProbeSection
EXIT_HINTS: Final = {
    1: "sudo refused (is /etc/sudoers.d/atlas-ro installed?)",
    3: "section not implemented by the installed probe",
    64: "gate refused the request (gate or probe out of date?)",
    126: "probe not executable",
    127: "probe or gate not installed",
}


def _parsers(expected_sha: str) -> list[tuple[ProbeSection, Callable[[Frame], parse.Parsed]]]:
    return [
        (S.VERSION, lambda f: parse.parse_version(f, expected_sha)),
        (S.OS, parse.parse_os),
        (S.NET, parse.parse_net),
        (S.PORTS, parse.parse_ports),
        (S.STORAGE, parse.parse_storage),
        (S.SERVICES, parse.parse_services),
        (S.CRON, parse.parse_cron),
        (S.USERS, parse.parse_users),
        (S.PACKAGES, parse.parse_packages),
        (S.PROCS, parse.parse_procs),
        (S.PVE, parse.parse_pve),
    ]


def _guest_facet(
    g: dict[str, object], cname: str, node_key: str, store_as: str, status: str
) -> FacetResult:
    kind = "vm" if g["type"] == "qemu" else "lxc"
    cfg = pve_parse.guest_config(str(g["type"]), g["cfg"])
    model = PveGuestFacts(
        vmid=int(str(g["vmid"])),
        type="qemu" if g["type"] == "qemu" else "lxc",
        name=str(g["name"]),
        node=str(g["node"]),
        template=bool(g["template"]),
        status=status,
        **cfg,
    )
    return FacetResult(
        f"pve:{kind}:{cname}/{model.vmid}",
        f"pve-{kind}",
        f"{model.name} ({kind.upper()} {model.vmid})",
        model,
        node_key,
        store_as=store_as,
    )


def _pve_facets(
    facts: LinuxHostFacts, guests: list[dict[str, object]], peers: list[dict[str, object]]
) -> list[FacetResult]:
    """This node and its guests (`pve-ssh`), plus the other nodes and their guests as this
    node's /etc/pve sees them (`pve-ssh-peer`: weaker, running state unknown). ADR-028/031."""
    pve = facts.pve
    assert pve is not None  # noqa: S101 - checked by the caller
    cname = pve.cluster or pve.node
    node_key = f"pve:node:{cname}/{pve.node}"
    node = PveNodeFacts(
        name=pve.node,
        online=True,
        ip=pve.ip,
        pve_version=pve.version,
        kernel=facts.os.kernel if facts.os else None,
    )
    out = [FacetResult(node_key, "pve-node", f"{pve.node} (PVE node)", node, store_as=PVE_SSH)]
    for g in guests:
        status = "running" if g["running"] else "stopped"
        out.append(_guest_facet(g, cname, node_key, PVE_SSH, status))
    members = {m.name: m for m in pve.members}
    for name in sorted({str(g["node"]) for g in peers} | (set(members) - {pve.node})):
        m = members.get(name)
        peer = PveNodeFacts(name=name, online=bool(m and m.online), ip=m.ip if m else None)
        out.append(
            FacetResult(
                f"pve:node:{cname}/{name}",
                "pve-node",
                f"{name} (PVE node)",
                peer,
                store_as=PVE_SSH_PEER,
            )
        )
    for g in peers:
        out.append(_guest_facet(g, cname, f"pve:node:{cname}/{g['node']}", PVE_SSH_PEER, "unknown"))
    return out


def host_key(machine_id: str | None, name: str) -> str:
    """Stable host identity shared by every SSH collector (SPEC §5)."""
    return f"host:{machine_id}" if machine_id else f"host:name:{name}"


class LinuxSshCollector:
    name = "linux-ssh"
    kind = "linux-host"
    requires = frozenset(
        {
            S.VERSION,
            S.OS,
            S.NET,
            S.PORTS,
            S.STORAGE,
            S.SERVICES,
            S.CRON,
            S.USERS,
            S.PACKAGES,
            S.PROCS,
            S.PVE,
        }
    )
    endpoints: frozenset[Endpoint] = frozenset()
    #: Facet names this collector also stores under (stale ones are removed per target).
    extra_facets: frozenset[str] = frozenset({PVE_SSH, PVE_SSH_PEER})

    def targets(self, inventory: Inventory) -> list[str]:
        return [h.name for h in inventory.hosts if self.name in h.collectors]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        if key.startswith("pve:"):  # node/guest facets from /etc/pve (ADR-028)
            return proxmox_events(key, name, changes)
        return linux_events(key, name, changes)

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        host = ctx.inventory.host(target)
        result = CollectorResult(self.name, host.name, "failed")
        values: dict[str, object] = {}
        section_errors: dict[str, list[str]] = {}
        try:
            ssh_target = ctx.inventory.ssh_target(host, self.requires)
            async with ctx.ssh.session(ssh_target) as session:
                for section, parser in _parsers(probe_sha256()):
                    errs = section_errors.setdefault(section.value, [])
                    try:
                        out = await session.run(section)
                    except SecurityRefusal as exc:
                        errs.append(f"refused: {exc.reason.value}")
                        continue
                    except TransportError as exc:
                        errs.append(f"transport: {type(exc).__name__}")
                        continue
                    if out.exit_status != 0:
                        errs.append(EXIT_HINTS.get(out.exit_status, f"exit {out.exit_status}"))
                        continue
                    try:
                        frame = parse_frame(out.stdout, section)
                    except FrameError as exc:
                        errs.append(f"frame: {exc}")
                        continue
                    parsed = parser(frame)
                    values.update(parsed.values)
                    errs.extend(frame.errors + parsed.errors)
        except SecurityRefusal as exc:
            result.status = "refused"
            result.errors = [f"refused: {exc.reason.value}: {exc.detail}"]
            return self._done(result, start)
        except TransportError as exc:
            result.errors = [f"unreachable: {exc}"]
            return self._done(result, start)

        section_errors = {k: v for k, v in section_errors.items() if v}
        raw_guests = values.pop("_pve_guests", [])
        raw_peers = values.pop("_pve_peers", [])
        pve_guests: list[dict[str, object]] = raw_guests if isinstance(raw_guests, list) else []
        pve_peers: list[dict[str, object]] = raw_peers if isinstance(raw_peers, list) else []
        if not values:
            result.errors = [f"{k}: {'; '.join(v)}" for k, v in sorted(section_errors.items())]
            return self._done(result, start)
        facts = LinuxHostFacts.model_validate({**values, "section_errors": section_errors})
        mid = facts.os.machine_id if facts.os else None
        key = host_key(mid, host.name)
        result.facets = [FacetResult(key, self.kind, host.name, facts)]
        # A Proxmox VE node documents the cluster from /etc/pve. These facets are stored next
        # to the API's (pve-ssh, pve-ssh-peer): the API wins where it answers, SSH fills in
        # when it is missing or misconfigured (ADR-031).
        if facts.pve is not None:
            result.facets.extend(_pve_facets(facts, pve_guests, pve_peers))
        result.complete = True
        result.status = "partial" if section_errors else "ok"
        result.errors = [f"{k}: {'; '.join(v)}" for k, v in sorted(section_errors.items())]
        return self._done(result, start)

    @staticmethod
    def _done(result: CollectorResult, start: float) -> CollectorResult:
        result.duration_ms = int((time.monotonic() - start) * 1000)
        return result
