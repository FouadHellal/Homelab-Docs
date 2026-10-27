"""MCP server (ADR-014, ADR-036), official SDK 2.x (`mcp.server.mcpserver.MCPServer`).

Query tools are pure reads over the read models (annotated readOnly/idempotent/closed-world):
machines, what runs on one, services, Proxmox, changes, scan health, unknown devices and ports.
One opt-in tool, `scan_machine` (`atlas mcp --allow-scan`), asks for a fresh scan of one
machine through the same read-only ScanEngine as the scheduler: atlas's database changes,
targets never do. Results are capped in size and, with `sanitize=True`, pseudonymised like
`atlas export --sanitize` (THREAT-MODEL T-MCP). HTTP transport is Streamable HTTP behind a
constant-time bearer-token check; stdio is meant to be reached over SSH.
"""

import asyncio
import hmac
import ipaddress
import json
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Final

import structlog
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.types import ASGIApp, Receive, Scope, Send

from homelab_atlas import __version__
from homelab_atlas.export.build import sanitizer_from_db
from homelab_atlas.store.tables import Annotation, Entity, Facet
from homelab_atlas.web import queries, views

MAX_RESULT_BYTES: Final = 200_000
FACETS_OMITTED: Final = "omitted: too large, narrow the query"
#: Tool arguments are short identifiers or search terms; refuse anything longer.
Arg = Annotated[str, Field(max_length=128)]
MAX_ROWS: Final = 500
log = structlog.get_logger()
READ_ONLY: Final = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
LIVE_SCAN: Final = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=True
)
SCAN_COOLDOWN_S: Final = 60.0
INSTRUCTIONS: Final = (
    "Inventory of the owner's homelab (Proxmox nodes, VMs and LXCs, UniFi, Linux hosts, Docker, "
    "NAS), collected read-only by atlas over SSH and APIs. Secrets are redacted at collection "
    "time. Start with list_machines. For 'what is running on X' use whats_running(X); for "
    "services across machines list_services; for Proxmox proxmox_overview; for recent changes "
    "what_changed (optionally machine=X); for why a machine is missing or stale scan_status. "
    "Each answer says when the data was collected (last_scan). If scan_machine is available "
    "and the data is old or the user asks for a live check, call scan_machine(X) first, then "
    "whats_running(X)."
)
KIND_WORDS: Final = {
    "pve-node": "Proxmox node",
    "pve-vm": "VM",
    "pve-lxc": "LXC",
    "linux-host": "host",
    "nas": "NAS",
}
Scanner = Callable[[str], Coroutine[Any, Any, dict[str, Any]]]


def _cap(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep responses bounded: trim item lists, then drop facets, until the JSON fits."""
    size = len(json.dumps(payload, default=str, ensure_ascii=False).encode())
    if size <= MAX_RESULT_BYTES:
        return payload
    items = payload.get("items")
    if isinstance(items, list) and items:
        # Always drop at least one item, so the recursion ends even for one huge item.
        keep = min(len(items) - 1, max(1, len(items) * MAX_RESULT_BYTES // size - 1))
        return _cap({**payload, "items": items[:keep], "truncated": True})
    facets = payload.get("facets")
    if isinstance(facets, dict) and any(v != FACETS_OMITTED for v in facets.values()):
        slim = {k: v for k, v in payload.items() if k != "facets"}
        slim["facets"] = dict.fromkeys(facets, FACETS_OMITTED)
        return _cap({**slim, "truncated": True})
    return {"truncated": True, "error": "result too large, narrow the query"}


def find_machine(s: Session, name: str) -> dict[str, Any] | None:
    """A machine card by name (case-insensitive), entity key, IP, or a unique name fragment."""
    q = name.strip().lower()
    if not q:
        return None
    cards = views.machines(s)
    tests: list[Callable[[dict[str, Any]], bool]] = [
        lambda m: str(m["short"]).lower() == q or str(m["key"]).lower() == q,
        lambda m: any(str(ip).split("/")[0] == q for ip in m["ips"]),
        lambda m: str(m.get("target") or "").lower() == q,
    ]
    for test in tests:
        hit = next((m for m in cards if test(m)), None)
        if hit is not None:
            return hit
    partial = [m for m in cards if q in m["short"].lower()]
    return partial[0] if len(partial) == 1 else None


def _machine_row(m: dict[str, Any], health: dict[str, str]) -> dict[str, Any]:
    target = str(m.get("target") or "")
    return {
        "name": m["short"],
        "key": m["key"],
        "kind": KIND_WORDS.get(m["kind"], m["kind"]),
        "status": m["status"],
        "node": m["node"],
        "vmid": m["vmid"],
        "ip": (m["ips"] or [None])[0],
        "os": m["os"],
        "cpu_cores": m["cores"],
        "memory_mb": m["memory_mb"],
        "documented_over_ssh": m["documented"],
        "apps": [a["name"] for a in m["apps"]],
        "services_running": m["services"],
        "containers": m["containers"],
        "last_scan": health.get(target, "never") if target else "not a target",
    }


def build_server(
    sessions: Callable[[], Session],
    *,
    sanitize_key: bytes | None = None,
    scanner: Scanner | None = None,
) -> MCPServer:
    mcp = MCPServer(name="atlas", version=__version__, instructions=INSTRUCTIONS)
    last_scan_request: dict[str, float] = {}

    def out(payload: Any) -> dict[str, Any]:
        if sanitize_key is not None:
            with sessions() as s:
                san = sanitizer_from_db(s, sanitize_key)
            payload = san.data(json.loads(json.dumps(payload, default=str)))
        if isinstance(payload, list):
            payload = {"count": len(payload), "items": payload}
        return _cap(json.loads(json.dumps(payload, default=str)))

    def entity_row(e: Entity) -> dict[str, Any]:
        return {
            "key": e.key,
            "name": e.display_name,
            "kind": e.kind,
            "status": e.status,
            "parent": e.parent_key,
            "same_as": e.same_as,
            "last_seen": e.last_seen.isoformat(),
        }

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_hosts(kind: Arg | None = None, query: Arg | None = None) -> dict[str, Any]:
        """List machines and devices. kind: linux-host, pve-vm, pve-lxc, pve-node, unifi-device,
        nas, container, unknown-device... query: substring of name or key."""
        log.info("mcp.tool", tool="list_hosts", sanitized=sanitize_key is not None)
        with sessions() as s:
            return out([entity_row(e) for e in queries.entities(s, kind, query)[:MAX_ROWS]])

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def get_host(name_or_key: Arg) -> dict[str, Any]:
        """Everything known about one machine: facets per collector (linux-ssh, docker, proxmox,
        unifi, nas, pi), annotation, children, recent changes. Accepts an entity key or a name."""
        log.info("mcp.tool", tool="get_host", sanitized=sanitize_key is not None)
        with sessions() as s:
            key = name_or_key
            if s.get(Entity, key) is None:
                match = s.scalars(select(Entity).where(Entity.display_name == name_or_key)).first()
                if match is None:
                    match = s.scalars(
                        select(Entity).where(Entity.display_name.ilike(f"%{name_or_key[:64]}%"))
                    ).first()
                if match is None:
                    return out({"error": f"no entity matches {name_or_key!r}"})
                key = match.key
            d = queries.entity_detail(s, key)
            assert d is not None  # noqa: S101 - key exists
            a: Annotation | None = d["annotation"]
            return out(
                {
                    **entity_row(d["entity"]),
                    "same_as_entity": entity_row(d["same_as"]) if d["same_as"] else None,
                    "twins": [entity_row(t) for t in d["twins"]],
                    "children": [entity_row(c) for c in d["children"]][:MAX_ROWS],
                    "annotation": {
                        "owner": a.owner,
                        "purpose": a.purpose,
                        "criticality": a.criticality,
                        "tags": a.tags,
                        "notes": a.notes,
                    }
                    # Sanitized answers drop annotations, like sanitized exports (ADR-023).
                    if a and sanitize_key is None
                    else None,
                    "facets": d["facets"],
                    "recent_changes": [
                        {
                            "type": e.type,
                            "severity": e.severity,
                            "summary": e.summary,
                            "at": e.created_at.isoformat(),
                        }
                        for e in d["events"][:20]
                    ],
                }
            )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_containers(host: Arg | None = None, query: Arg | None = None) -> dict[str, Any]:
        """Docker containers with image, status, health, published ports and compose project."""
        log.info("mcp.tool", tool="list_containers", sanitized=sanitize_key is not None)
        with sessions() as s:
            rows = []
            for f in s.scalars(select(Facet).where(Facet.collector == "docker")):
                if host and host.lower() not in f.target.lower():
                    continue
                for c in f.data.get("containers") or []:
                    row = {
                        "host": f.target,
                        "container": c.get("key"),
                        "image": c.get("image"),
                        "status": c.get("status"),
                        "health": c.get("health"),
                        "compose_project": c.get("compose_project"),
                        "env_names": c.get("env_names"),
                        "ports": [
                            f"{p['host_ip']}:{p['host_port']}->{p['container_port']}/{p['proto']}"
                            for p in c.get("ports") or []
                        ],
                        "privileged": c.get("privileged"),
                        "docker_socket": c.get("docker_socket"),
                    }
                    if query and query.lower() not in json.dumps(row).lower():
                        continue
                    rows.append(row)
            return out(rows[:MAX_ROWS])

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def search_ip(ip_or_cidr: Arg) -> dict[str, Any]:
        """Who has this IP, or which IPs fall in a CIDR (e.g. 10.0.30.0/24). Also matches MACs."""
        log.info("mcp.tool", tool="search_ip", sanitized=sanitize_key is not None)
        with sessions() as s:
            rows = queries.ip_table(s)
            try:
                net = ipaddress.ip_network(ip_or_cidr.strip(), strict=False)
                hits = [r for r in rows if _in(r["ip"], net)]
            except ValueError:
                q = ip_or_cidr.lower()[:64]
                hits = [
                    r for r in rows if q in (r["ip"] or "").lower() or q in (r["mac"] or "").lower()
                ]
            return out(hits[:MAX_ROWS])

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def find_service(query: Arg) -> dict[str, Any]:
        """Find a service by port number, process, container, image or systemd unit name."""
        log.info("mcp.tool", tool="find_service", sanitized=sanitize_key is not None)
        q = query.lower().strip()[:64]
        with sessions() as s:
            ports = [
                r
                for r in queries.port_table(s)
                if q == str(r["port"]) or q in str(r["what"]).lower()
            ]
            units = []
            for f in s.scalars(select(Facet).where(Facet.collector == "linux-ssh")):
                for u in f.data.get("services") or []:
                    if q in (u.get("unit") or "").lower():
                        units.append(
                            {
                                "host": f.target,
                                "unit": u.get("unit"),
                                "active": u.get("active"),
                                "enabled": u.get("enabled"),
                            }
                        )
            return out({"ports": ports[:MAX_ROWS], "systemd_units": units[:MAX_ROWS]})

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def what_changed(
        since_hours: int = 24,
        severity: Arg | None = None,
        query: Arg | None = None,
        machine: Arg | None = None,
    ) -> dict[str, Any]:
        """Change events (port opened, image updated, new device on VLAN, host unreachable...)
        from the last `since_hours` hours, newest first. severity: warning | notice | info.
        machine: only that machine, its VM/host twin and its containers."""
        log.info("mcp.tool", tool="what_changed", sanitized=sanitize_key is not None)
        since = datetime.now(UTC) - timedelta(hours=max(1, min(since_hours, 24 * 365)))
        with sessions() as s:
            keys = None
            if machine:
                m = find_machine(s, machine)
                if m is None:
                    return out({"error": f"no machine matches {machine!r}"})
                keys = queries.related_keys(s, m["key"])
            rows = [
                r
                for r in queries.changes(s, severity, query, limit=MAX_ROWS, keys=keys)
                if _aware(r["at"]) >= since
            ]
            return out(
                [
                    {
                        "at": r["at"].isoformat(),
                        "type": r["event"].type,
                        "severity": r["event"].severity,
                        "entity": r["name"],
                        "summary": r["event"].summary,
                    }
                    for r in rows
                ]
            )

    def health_map(s: Session) -> dict[str, str]:
        return {t: queries.target_health(rs) for t, rs in queries.latest_runs(s).items()}

    def runs_of(s: Session, target: str | None) -> list[dict[str, Any]]:
        if not target:
            return []
        return [
            {
                "collector": r["collector"],
                "status": r["status"],
                "errors": r["errors"],
                "at": r["when"].isoformat() if r["when"] else None,
            }
            for r in queries.latest_runs(s).get(target, [])
        ]

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_machines(kind: Arg | None = None, query: Arg | None = None) -> dict[str, Any]:
        """Every machine (Proxmox nodes, VMs, LXCs, Linux hosts, NAS) with IP, OS, size, the
        apps found on it and its last scan result. kind: node | vm | lxc | host | nas.
        query: part of a name, IP, OS or app name."""
        log.info("mcp.tool", tool="list_machines", sanitized=sanitize_key is not None)
        with sessions() as s:
            health = health_map(s)
            rows = [_machine_row(m, health) for m in views.machines(s)]
        if kind:
            k = kind.lower().replace("proxmox ", "")
            rows = [r for r in rows if r["kind"].lower().endswith(k)]
        if query:
            q = query.lower()
            rows = [r for r in rows if q in json.dumps(r).lower()]
        return out(rows[:MAX_ROWS])

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def whats_running(machine: Arg) -> dict[str, Any]:
        """What runs on one machine: recognised apps, running and failed systemd services,
        Docker containers, listening ports and the busiest processes, plus when it was last
        scanned. machine: a name like 'docker01', an IP, or an entity key."""
        log.info("mcp.tool", tool="whats_running", sanitized=sanitize_key is not None)
        with sessions() as s:
            m = find_machine(s, machine)
            if m is None:
                names = sorted(c["short"] for c in views.machines(s))
                return out({"error": f"no machine matches {machine!r}", "machines": names})
            run = views.running(s, m["key"])
            return out(
                {
                    "machine": _machine_row(m, health_map(s)),
                    "last_scan_runs": runs_of(s, m.get("target")),
                    "apps": [
                        {
                            "name": a["name"],
                            "category": a["category_label"],
                            "evidence": a["evidence"],
                            "ports": a["ports"],
                            "web_port": a["web_port"],
                        }
                        for a in run["apps"]
                    ],
                    "services_running": [
                        {
                            "unit": x.get("unit"),
                            "description": x.get("description"),
                            "enabled": x.get("enabled"),
                        }
                        for x in run["services"]
                    ],
                    "services_failed": [x.get("unit") for x in run["failed"]],
                    "containers": [
                        {
                            "name": c.get("name"),
                            "image": c.get("image"),
                            "status": c.get("status"),
                            "health": c.get("health"),
                            "compose_project": c.get("compose_project"),
                        }
                        for c in run["containers"]
                    ],
                    "listening": sorted(
                        {
                            f"{x.get('proto')}/{x.get('port')} {x.get('process') or ''}".strip()
                            for x in run["sockets"]
                        }
                    ),
                    "top_processes": [
                        {
                            "command": p.get("comm"),
                            "cpu_pct": p.get("cpu_pct"),
                            "mem_pct": p.get("mem_pct"),
                            "user": p.get("user"),
                        }
                        for p in run["processes"][:15]
                    ],
                    "timers": [x.get("unit") for x in run["timers"]],
                    "note": None
                    if m["documented"]
                    else "atlas does not log in to this machine (no SSH target), so only "
                    "what Proxmox and UniFi know is available."
                    " Add it on the Targets page.",
                }
            )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_services(
        machine: Arg | None = None,
        state: Arg = "running",
        kind: Arg | None = None,
        query: Arg | None = None,
    ) -> dict[str, Any]:
        """Every systemd unit and Docker container across machines, one row each, with the app
        it belongs to. state: running | failed | inactive | all. kind: systemd | container."""
        log.info("mcp.tool", tool="list_services", sanitized=sanitize_key is not None)
        with sessions() as s:
            name = None
            if machine:
                m = find_machine(s, machine)
                if m is None:
                    return out({"error": f"no machine matches {machine!r}"})
                name = m["short"]
            t = views.service_table(s, machine=name, state=state, kind=kind, q=query)
        rows = [{k: r[k] for k in views.SERVICE_COLUMNS} for r in t["rows"]]
        return out(
            {
                "counts": t["counts"],
                "total": t["total"],
                "count": len(rows),
                "items": rows[:MAX_ROWS],
            }
        )

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def proxmox_overview() -> dict[str, Any]:
        """Proxmox nodes with their VMs and LXCs (state, vmid, cores, memory, IP, OS, bridge),
        plus totals: guests, running, vCPU and RAM allocated."""
        log.info("mcp.tool", tool="proxmox_overview", sanitized=sanitize_key is not None)
        with sessions() as s:
            cards = views.machines(s)
        nodes: dict[str, dict[str, Any]] = {}
        for m in cards:
            if m["kind"] == "pve-node":
                info = m.get("pve") or {}
                nodes[m["short"]] = {
                    "node": m["short"],
                    "ip": (m["ips"] or [None])[0],
                    "version": info.get("version"),
                    "cpu_cores": info.get("cpu_cores"),
                    "memory_gb": info.get("memory_gb"),
                    "guests": [],
                }
        for m in cards:
            if m["kind"] in ("pve-vm", "pve-lxc"):
                row = {
                    "name": m["short"],
                    "type": KIND_WORDS[m["kind"]],
                    "vmid": m["vmid"],
                    "status": m["status"],
                    "cores": m["cores"],
                    "memory_mb": m["memory_mb"],
                    "ip": (m["ips"] or [None])[0],
                    "os": m["os"],
                    "bridges": sorted({n["bridge"] for n in m["nics"] if n["bridge"]}),
                    "documented_over_ssh": m["documented"],
                }
                nodes.setdefault(m["node"] or "?", {"node": m["node"] or "?", "guests": []})
                nodes[m["node"] or "?"]["guests"].append(row)
        for n in nodes.values():
            n["guests"].sort(key=lambda g: g["vmid"] or 0)
        return out({"totals": views.proxmox_summary(cards), "nodes": list(nodes.values())})

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def scan_status() -> dict[str, Any]:
        """Health of atlas's own collection: every target's latest result (ok, partial, failed
        with the reason, or never scanned). Use it when a machine looks missing or stale."""
        log.info("mcp.tool", tool="scan_status", sanitized=sanitize_key is not None)
        with sessions() as s:
            latest = queries.latest_runs(s)
            rows = [
                {"target": t, "health": queries.target_health(rs), "runs": runs_of(s, t)}
                for t, rs in sorted(latest.items())
            ]
        tally: dict[str, int] = {}
        for r in rows:
            h = str(r["health"])
            tally[h] = tally.get(h, 0) + 1
        return out({"summary": tally, "items": rows, "live_scan_available": scanner is not None})

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def unrecognised_ports() -> dict[str, Any]:
        """Listening ports that no recognised app explains, grouped by process, container image
        or port, with the machines they are on."""
        log.info("mcp.tool", tool="unrecognised_ports", sanitized=sanitize_key is not None)
        with sessions() as s:
            groups = views.unrecognised_ports(s)
        return out(
            [
                {"what": g["label"], "ports": g["ports"], "machines": [n for n, _ in g["machines"]]}
                for g in groups
            ]
        )

    if scanner is not None:

        @mcp.tool(annotations=LIVE_SCAN, structured_output=True)
        async def scan_machine(machine: Arg) -> dict[str, Any]:
            """Scan one machine NOW (read-only SSH/API collection, a few seconds to a minute),
            then answer from fresh data with whats_running. At most once a minute per machine."""
            log.info("mcp.tool", tool="scan_machine")
            with sessions() as s:
                m = find_machine(s, machine)
            if m is None or not m.get("target"):
                return out(
                    {
                        "error": f"{machine!r} is not a scan target (add it on the Targets "
                        "page first)"
                    }
                )
            target = str(m["target"])
            now = time.monotonic()
            if now - last_scan_request.get(target, -1e9) < SCAN_COOLDOWN_S:
                return out(
                    {
                        "target": target,
                        "status": "skipped",
                        "reason": "scanned less than a minute ago; use whats_running",
                    }
                )
            last_scan_request[target] = now
            result = await scanner(target)
            return out({"target": target, **result})

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_unknown_devices(include_acknowledged: bool = False) -> dict[str, Any]:
        """Devices seen on the network (UniFi clients, ARP) that no inventory entry explains."""
        log.info("mcp.tool", tool="list_unknown_devices", sanitized=sanitize_key is not None)
        with sessions() as s:
            return out(
                [
                    {k: v for k, v in u.items() if k != "entity"}
                    | {
                        "name": u["entity"].display_name,
                        "status": u["entity"].status,
                        "first_seen": u["entity"].first_seen.isoformat(),
                    }
                    for u in queries.unknown_devices(s, include_ack=include_acknowledged)
                ]
            )

    return mcp


def engine_scanner(make_engine: Callable[[], Any], *, timeout_s: float = 180.0) -> Scanner:
    """`scan_machine`'s backend: one target, same ScanEngine as the scheduler (read-only
    choke points, redaction, audit), on a worker thread so the MCP loop stays responsive."""
    from homelab_atlas.engine.scan import ScanLockedError  # noqa: PLC0415

    def run(target: str) -> dict[str, Any]:
        summary = asyncio.run(make_engine().run(hosts=[target], label=f"mcp:{target}"[:64]))
        return {
            "status": "done",
            "runs": [
                {"collector": r.collector, "status": r.status, "errors": r.errors[:5]}
                for r in summary.runs
            ],
            "changes_found": len(summary.events),
            "next": "call whats_running for the fresh data",
        }

    async def scan(target: str) -> dict[str, Any]:
        try:
            return await asyncio.wait_for(asyncio.to_thread(run, target), timeout_s)
        except ScanLockedError:
            return {"status": "busy", "reason": "another scan is running; try again in a minute"}
        except TimeoutError:
            return {"status": "timeout", "reason": f"no answer within {int(timeout_s)} s"}

    return scan


def _aware(when: datetime) -> datetime:
    return when if when.tzinfo else when.replace(tzinfo=UTC)


def _in(ip: str, net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    try:
        return ipaddress.ip_address(ip) in net
    except (ValueError, TypeError):
        return False


class BearerAuth:
    """ASGI guard for the Streamable HTTP transport: exact bearer token or 401."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        if len(token) < 32:
            raise ValueError("MCP bearer token must be at least 32 characters")
        self.app, self.expected = app, f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "websocket":
            supplied = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                await send({"type": "websocket.close", "code": 1008})
                return
        elif scope["type"] == "http":
            supplied = dict(scope.get("headers") or []).get(b"authorization", b"")
            if not hmac.compare_digest(supplied, self.expected):
                await send(
                    {
                        "type": "http.response.start",
                        "status": 401,
                        "headers": [
                            (b"www-authenticate", b"Bearer"),
                            (b"content-type", b"text/plain"),
                        ],
                    }
                )
                await send({"type": "http.response.body", "body": b"unauthorized"})
                return
        await self.app(scope, receive, send)
