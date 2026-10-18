"""CLI: scan, diff, doctor, targets, db. Registered on the main app in cli.py."""

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from sqlalchemy import select

from homelab_atlas.collectors import nas as nas_mod
from homelab_atlas.collectors.base import ApiSource, HttpFactory
from homelab_atlas.collectors.linux_ssh.collector import EXIT_HINTS
from homelab_atlas.collectors.linux_ssh.frame import FrameError, parse_frame
from homelab_atlas.collectors.linux_ssh.parse import parse_version
from homelab_atlas.collectors.proxmox import endpoints as pve_ep
from homelab_atlas.collectors.proxmox.collector import ProxmoxCollector
from homelab_atlas.collectors.unifi import endpoints as unifi_ep
from homelab_atlas.collectors.unifi import parse as unifi_parse
from homelab_atlas.collectors.unifi.collector import UnifiCollector
from homelab_atlas.engine.scan import ScanLockedError
from homelab_atlas.inventory.hosts import Inventory, InventoryError
from homelab_atlas.lab import LabError, parse_spec
from homelab_atlas.probe.render import PROBE_VERSION, probe_sha256, render_all
from homelab_atlas.runtime import (
    Inputs,
    Runtime,
    default_data_dir,
    lab_inputs,
    live_inputs,
    wipe_lab_data,
)
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError
from homelab_atlas.security.ssh import SshRunner
from homelab_atlas.store.db import make_engine, migrate
from homelab_atlas.store.tables import Entity, Event, Facet, Scan

console = Console()
targets_app = typer.Typer(help="Target-side setup artifacts.", no_args_is_help=True)
db_app = typer.Typer(help="Database maintenance.", no_args_is_help=True)

LabOpt = Annotated[
    str | None, typer.Option("--lab", help="Synthetic demo lab, e.g. demo:A (diff: demo).")
]
LiveOpt = Annotated[
    bool, typer.Option("--live", help="Real targets from $ATLAS_CONFIG_DIR/hosts.yaml.")
]
DataOpt = Annotated[Path | None, typer.Option("--data-dir", help="Override the data dir.")]
SEV_STYLE = {"warning": "bold red", "notice": "yellow", "info": "dim"}


def _fail(message: str) -> typer.Exit:
    console.print(f"[red]error:[/] {message}")
    return typer.Exit(2)


def _inputs(lab: str | None, live: bool) -> tuple[str, Inputs]:
    if bool(lab) == live:
        raise _fail("choose exactly one of --lab demo:A or --live")
    try:
        if lab:
            state = parse_spec(lab)
            if state is None:
                raise _fail("--lab needs a state here, e.g. demo:A")
            return "demo", lab_inputs(state)
        return "live", live_inputs()
    except (LabError, InventoryError, FileNotFoundError) as exc:
        raise _fail(str(exc)) from None


def scan(
    lab: LabOpt = None,
    live: LiveOpt = False,
    data_dir: DataOpt = None,
    host: Annotated[list[str] | None, typer.Option("--host", help="Limit to host(s).")] = None,
    collector: Annotated[list[str] | None, typer.Option("--collector")] = None,
    fresh: Annotated[bool, typer.Option("--fresh", help="Wipe the lab data dir first.")] = False,
) -> None:
    """Run collectors, store redacted snapshots and derive change events."""
    mode, inputs = _inputs(lab, live)
    ddir = data_dir or default_data_dir(lab=mode == "demo")
    if fresh:
        try:
            wipe_lab_data(ddir)
        except ValueError as exc:
            raise _fail(str(exc)) from None
    rt = Runtime.open(ddir, mode=mode)
    engine = rt.scan_engine(inputs)
    try:
        summary = asyncio.run(engine.run(hosts=host, collectors=collector, label=lab or "live"))
    except ScanLockedError as exc:
        raise _fail(str(exc)) from None
    table = Table(title=f"scan #{summary.scan_id} ({lab or 'live'})")
    for col in ("target", "collector", "status", "ms", "notes"):
        table.add_column(col)
    style = {"ok": "green", "partial": "yellow", "failed": "red", "refused": "bold red"}
    for r in sorted(summary.runs, key=lambda r: r.target):
        notes = "; ".join(r.errors)[:80]
        table.add_row(
            r.target, r.collector, f"[{style[r.status]}]{r.status}[/]", str(r.duration_ms), notes
        )
    console.print(table)
    console.print(
        f"{len(summary.events)} events. Show them with: atlas diff{' --lab demo' if lab else ''}"
    )


def diff(
    lab: LabOpt = None,
    data_dir: DataOpt = None,
    scan_id: Annotated[
        int | None, typer.Option("--scan", help="Scan id (default: latest).")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show the change events produced by a scan."""
    ddir = data_dir or default_data_dir(lab=lab is not None)
    rt = Runtime.open(ddir, mode="demo" if lab else "live")
    with rt.sessions() as s:
        if scan_id is None:
            scan_id = s.scalar(select(Scan.id).order_by(Scan.id.desc()).limit(1))
        if scan_id is None:
            raise _fail("no scans yet: run `atlas scan` first")
        scan_row = s.get(Scan, scan_id)
        events = s.scalars(select(Event).where(Event.scan_id == scan_id)).all()
    order = {"warning": 0, "notice": 1, "info": 2}
    events = sorted(events, key=lambda e: (order.get(e.severity, 9), e.summary))
    if as_json:
        typer.echo(
            json.dumps(
                [
                    {
                        "type": e.type,
                        "severity": e.severity,
                        "entity": e.entity_key,
                        "summary": e.summary,
                        "path": e.path,
                        "old": e.old,
                        "new": e.new,
                    }
                    for e in events
                ],
                indent=1,
                ensure_ascii=False,
            )
        )
        return
    label = scan_row.label if scan_row else "?"
    table = Table(title=f"changes in scan #{scan_id} ({label})")
    for col in ("severity", "event", "summary"):
        table.add_column(col)
    for e in events:
        table.add_row(f"[{SEV_STYLE.get(e.severity, '')}]{e.severity}[/]", e.type, e.summary)
    console.print(table if events else f"no changes in scan #{scan_id}")


async def _doctor_proxmox(
    factory: HttpFactory, inventory: Inventory, name: str
) -> tuple[bool, str]:
    """The token may hold *.Audit privileges only (PVEAuditor + privilege separation)."""
    try:
        client = factory(ProxmoxCollector.source(inventory, name), pve_ep.DOCTOR)
        async with client:
            version = (await client.get(pve_ep.VERSION)).json().get("data", {}).get("version")
            perms = (await client.get(pve_ep.PERMISSIONS)).json().get("data", {})
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value} ({exc.detail})"
    except (TransportError, HttpStatusError) as exc:
        return False, f"unreachable: {exc}"
    if not isinstance(perms, dict) or not perms:
        return False, "token has no permissions (ACL missing?)"
    privs = {p for v in perms.values() if isinstance(v, dict) for p in v}
    extra = sorted(privs - pve_ep.AUDIT_PRIVILEGES)
    if extra:
        return False, f"token is NOT read-only: {', '.join(extra[:6])}"
    missing = sorted({"VM.Audit", "Sys.Audit", "Datastore.Audit", "VM.GuestAgent.Audit"} - privs)
    if missing:
        return False, f"PVE {version}: read-only, but missing {', '.join(missing)}"
    return True, f"PVE {version}: token read-only (audit privileges only)"


async def _doctor_unifi(factory: HttpFactory, inventory: Inventory, name: str) -> tuple[bool, str]:
    """Version gate only: an API key cannot be checked for write rights without writing."""
    try:
        async with factory(UnifiCollector.source(inventory, name), unifi_ep.DOCTOR) as client:
            info = (await client.get(unifi_ep.INFO)).json()
            sites = (await client.get(unifi_ep.SITES, query={"offset": 0, "limit": 200})).json()
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value} ({exc.detail})"
    except (TransportError, HttpStatusError) as exc:
        return False, f"unreachable: {exc}"
    version = info.get("applicationVersion") if isinstance(info, dict) else None
    if unifi_parse.version_tuple(version) < unifi_ep.MIN_VERSION:
        return False, f"Network {version}: Integration API needs >= 9.3"
    n = sites.get("totalCount") if isinstance(sites, dict) else "?"
    return True, (
        f"Network {version}, {n} site(s). Key scope is not verifiable: create it as a "
        "view-only admin (SECURITY.md)"
    )


async def _doctor_unas(factory: HttpFactory, inventory: Inventory, name: str) -> tuple[bool, str]:
    src = next(s for s in inventory.sources.unas if s.name == name)
    if src.url is None or src.credential is None:
        return False, "drive_api needs url and credential"
    api = ApiSource(src.name, src.url, src.credential, src.tls, "x-api-key")
    try:
        async with factory(api, nas_mod.ENDPOINTS) as client:
            system = (await client.get(nas_mod.SYSTEM)).json()
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value} ({exc.detail})"
    except (TransportError, HttpStatusError) as exc:
        return False, f"unreachable: {exc}"
    model = (system.get("hardware") or {}).get("shortname") if isinstance(system, dict) else None
    return True, f"UNAS {model}: Drive API answering (undocumented API, best effort)"


async def _doctor_host(runner: SshRunner, inventory: Inventory, name: str) -> tuple[bool, str]:
    host = inventory.host(name)
    target = inventory.ssh_target(host, frozenset({ProbeSection.VERSION}))
    try:
        async with runner.session(target) as session:
            out = await session.run(ProbeSection.VERSION)
    except SecurityRefusal as exc:
        return False, f"refused: {exc.reason.value} ({exc.detail})"
    except TransportError as exc:
        return False, f"unreachable: {exc}"
    if out.exit_status != 0:
        return False, EXIT_HINTS.get(out.exit_status, f"probe exit {out.exit_status}")
    try:
        parsed = parse_version(parse_frame(out.stdout, ProbeSection.VERSION), probe_sha256())
    except FrameError as exc:
        return False, f"bad probe output: {exc}"
    probe = parsed.values.get("probe")
    if probe is None:
        return False, "probe version unreadable"
    if not probe.matches:
        return (
            False,
            f"probe {probe.version} installed, hash differs from {PROBE_VERSION}: "
            "reinstall docs/targets/atlas-probe",
        )
    return True, f"probe {probe.version} OK, gate and sudoers working"


def doctor(
    lab: LabOpt = None,
    live: LiveOpt = False,
    data_dir: DataOpt = None,
    host: Annotated[list[str] | None, typer.Option("--host")] = None,
) -> None:
    """Check inventory and target setup (reachability, pinned keys, gate, sudoers, probe hash)."""
    mode, inputs = _inputs(lab, live)
    inventory = inputs.inventory
    rt = Runtime.open(data_dir or default_data_dir(lab=mode == "demo"), mode=mode)
    runner = SshRunner(transport=inputs.ssh, audit=rt.audit)
    ssh_collectors = {"linux-ssh", "docker", "pi"}
    names = [
        h.name
        for h in inventory.hosts
        if ssh_collectors & set(h.collectors) and (not host or h.name in host)
    ]
    pick = [s.name for s in inventory.sources.proxmox if not host or s.name in host]
    unifi = [s.name for s in inventory.sources.unifi if not host or s.name in host]
    unas = [s.name for s in inventory.sources.unas if s.drive_api and (not host or s.name in host)]
    sources = pick + unifi + unas
    console.print(
        f"inventory OK: {len(inventory.hosts)} hosts ({len(names)} over SSH), "
        f"{len(pick)} Proxmox, {len(unifi)} UniFi, {len(unas)} UNAS source(s)"
    )
    factory = inputs.http(rt.audit)

    async def run_all() -> list[tuple[bool, str]]:
        checks = [_doctor_host(runner, inventory, n) for n in names]
        checks += [_doctor_proxmox(factory, inventory, s) for s in pick]
        checks += [_doctor_unifi(factory, inventory, s) for s in unifi]
        checks += [_doctor_unas(factory, inventory, s) for s in unas]
        return list(await asyncio.gather(*checks))

    table = Table(title="atlas doctor")
    for col in ("host", "result", "detail"):
        table.add_column(col)
    problems = 0
    for name, (ok, detail) in zip([*names, *sources], asyncio.run(run_all()), strict=True):
        problems += not ok
        table.add_row(name, "[green]OK[/]" if ok else "[red]PROBLEM[/]", detail)
    console.print(table)
    if problems:
        console.print(f"{problems} host(s) need attention")
        raise typer.Exit(1)


@targets_app.command("render")
def targets_render(
    out: Annotated[Path, typer.Option("--out")] = Path("docs/targets"),
    check: Annotated[bool, typer.Option("--check", help="Fail if files are stale.")] = False,
) -> None:
    """Render probe, gate, sudoers and authorized_keys from the allowlist."""
    stale = []
    for name, data in render_all().items():
        path = out / name
        if path.is_file() and path.read_bytes() == data:
            continue
        stale.append(name)
        if not check:
            out.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    if check and stale:
        console.print(f"[red]stale:[/] {', '.join(stale)}")
        raise typer.Exit(1)
    console.print(
        f"{out}: {len(stale)} file(s) {'stale' if check else 'written'}, probe {PROBE_VERSION} "
        f"sha256 {probe_sha256()[:16]}…"
    )


@db_app.command("upgrade")
def db_upgrade(lab: LabOpt = None, data_dir: DataOpt = None) -> None:
    """Apply database migrations (scans do this automatically)."""
    ddir = data_dir or default_data_dir(lab=lab is not None)
    migrate(make_engine(ddir / "atlas.db"))
    console.print(f"{ddir / 'atlas.db'}: up to date")


def unknown(
    lab: LabOpt = None,
    data_dir: DataOpt = None,
    as_json: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Devices seen on the network (UniFi clients, ARP) that nothing in the inventory explains."""
    rt = Runtime.open(
        data_dir or default_data_dir(lab=lab is not None), mode="demo" if lab else "live"
    )
    with rt.sessions() as s:
        rows = s.execute(
            select(Entity, Facet)
            .join(Facet, Facet.entity_key == Entity.key)
            .where(Entity.kind == "unknown-device", Entity.status == "unknown")
            .order_by(Entity.first_seen)
        ).all()
    items = [
        {
            "name": e.display_name,
            "first_seen": e.first_seen.isoformat(),
            "last_seen": e.last_seen.isoformat(),
            **f.data,
        }
        for e, f in rows
    ]
    if as_json:
        typer.echo(json.dumps(items, indent=1, ensure_ascii=False))
        return
    table = Table(title=f"{len(items)} unknown device(s)")
    for col in ("name", "mac", "ip", "network", "vlan", "seen via", "last seen"):
        table.add_column(col)
    for i in items:
        table.add_row(
            i["name"],
            i["mac"],
            i.get("ip") or "",
            i.get("network") or "",
            str(i.get("vlan") or ""),
            i.get("uplink") or i.get("seen_via") or "",
            i["last_seen"][:16],
        )
    console.print(table)


def register(app: typer.Typer) -> None:
    app.command("scan")(scan)
    app.command("unknown")(unknown)
    app.command("diff")(diff)
    app.command("doctor")(doctor)
    app.add_typer(targets_app, name="targets")
    app.add_typer(db_app, name="db")
