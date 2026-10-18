"""Read-only MCP server (ADR-014), official SDK 2.x (`mcp.server.mcpserver.MCPServer`).

Tools are pure queries over the read models: nothing triggers a scan, writes, or reaches a
target. Every tool is annotated readOnly/idempotent/closed-world. Results are capped in size
and, with `sanitize=True`, pseudonymised like `atlas export --sanitize` (THREAT-MODEL T-MCP).
HTTP transport is Streamable HTTP behind a constant-time bearer-token check.
"""

import hmac
import ipaddress
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.types import ASGIApp, Receive, Scope, Send

from homelab_atlas import __version__
from homelab_atlas.export.build import KIND_PREFIX
from homelab_atlas.export.sanitize import Sanitizer
from homelab_atlas.store.tables import Annotation, Entity, Facet
from homelab_atlas.web import queries

MAX_RESULT_BYTES: Final = 200_000
MAX_ROWS: Final = 500
READ_ONLY: Final = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
INSTRUCTIONS: Final = (
    "Read-only inventory of the owner's homelab (Proxmox, UniFi, Linux, Docker, NAS), "
    "collected by atlas. Secrets are redacted at collection time. Use list_hosts / search_ip / "
    "find_service to locate things, get_host for details, what_changed for recent events."
)


def _cap(payload: dict[str, Any]) -> dict[str, Any]:
    """Keep responses bounded: trim item lists, then drop facets, until the JSON fits."""
    size = len(json.dumps(payload, default=str, ensure_ascii=False).encode())
    if size <= MAX_RESULT_BYTES:
        return payload
    if isinstance(payload.get("items"), list):
        items = payload["items"]
        keep = max(1, len(items) * MAX_RESULT_BYTES // size - 1)
        return _cap({**payload, "items": items[:keep], "truncated": True})
    if isinstance(payload.get("facets"), dict):
        slim = {k: v for k, v in payload.items() if k != "facets"}
        slim["facets"] = dict.fromkeys(payload["facets"], "omitted: too large, narrow the query")
        return _cap({**slim, "truncated": True})
    return {"truncated": True, "error": "result too large, narrow the query"}


def build_server(
    sessions: Callable[[], Session], *, sanitize_key: bytes | None = None
) -> MCPServer:
    mcp = MCPServer(name="atlas", version=__version__, instructions=INSTRUCTIONS)

    def out(payload: Any) -> dict[str, Any]:
        if sanitize_key is not None:
            san = Sanitizer(sanitize_key)
            with sessions() as s:
                for e in s.scalars(select(Entity)):
                    san.register([e.display_name], KIND_PREFIX.get(e.kind, "obj"))
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
    def list_hosts(kind: str | None = None, query: str | None = None) -> dict[str, Any]:
        """List machines and devices. kind: linux-host, pve-vm, pve-lxc, pve-node, unifi-device,
        nas, container, unknown-device... query: substring of name or key."""
        with sessions() as s:
            return out([entity_row(e) for e in queries.entities(s, kind, query)[:MAX_ROWS]])

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def get_host(name_or_key: str) -> dict[str, Any]:
        """Everything known about one machine: facets per collector (linux-ssh, docker, proxmox,
        unifi, nas, pi), annotation, children, recent changes. Accepts an entity key or a name."""
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
                    if a
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
    def list_containers(host: str | None = None, query: str | None = None) -> dict[str, Any]:
        """Docker containers with image, status, health, published ports and compose project."""
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
    def search_ip(ip_or_cidr: str) -> dict[str, Any]:
        """Who has this IP, or which IPs fall in a CIDR (e.g. 10.0.30.0/24). Also matches MACs."""
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
    def find_service(query: str) -> dict[str, Any]:
        """Find a service by port number, process, container, image or systemd unit name."""
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
        since_hours: int = 24, severity: str | None = None, query: str | None = None
    ) -> dict[str, Any]:
        """Change events (port opened, image updated, new device on VLAN, host unreachable...)
        from the last `since_hours` hours, newest first. severity: warning | notice | info."""
        since = datetime.now(UTC) - timedelta(hours=max(1, min(since_hours, 24 * 365)))
        with sessions() as s:
            rows = [
                r for r in queries.changes(s, severity, query, limit=MAX_ROWS) if r["at"] >= since
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

    @mcp.tool(annotations=READ_ONLY, structured_output=True)
    def list_unknown_devices(include_acknowledged: bool = False) -> dict[str, Any]:
        """Devices seen on the network (UniFi clients, ARP) that no inventory entry explains."""
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
        if scope["type"] == "http":
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
