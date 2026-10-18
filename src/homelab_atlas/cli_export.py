"""CLI: `atlas export` and `atlas mcp` (read-only consumers of the database)."""

import hashlib
import hmac
import os
import secrets
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from homelab_atlas.export import build as export
from homelab_atlas.runtime import Runtime, default_data_dir, load_redaction_key
from homelab_atlas.security.errors import SecretError, SecurityRefusal
from homelab_atlas.security.secrets import SecretResolver

console = Console(stderr=True)

LabFlag = Annotated[
    str | None, typer.Option("--lab", help="Demo lab, e.g. demo (uses its data dir).")
]
DataOpt = Annotated[Path | None, typer.Option("--data-dir")]
SanitizeOpt = Annotated[
    bool, typer.Option("--sanitize", help="Pseudonymise names, IPs, MACs; drop notes/owners.")
]
MCP_TOKEN_SECRET = "mcp_token"  # noqa: S105 - a secret *name*


class Format(StrEnum):
    json = "json"
    csv = "csv"
    md = "md"
    mkdocs = "mkdocs"
    mermaid = "mermaid"


def _runtime(lab: str | None, data_dir: Path | None) -> Runtime:
    return Runtime.open(data_dir or default_data_dir(lab=bool(lab)), mode="demo" if lab else "live")


def sanitize_key(rt: Runtime) -> bytes:
    """Derived from the installation key: stable pseudonyms across exports, not reversible."""
    return hmac.new(
        load_redaction_key(rt.data_dir / "redaction.key"), b"atlas-sanitize/1", hashlib.sha256
    ).digest()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode())
    console.print(f"wrote {path}")


def export_cmd(
    fmt: Annotated[Format, typer.Argument(help="json | csv | md | mkdocs | mermaid")],
    out: Annotated[Path, typer.Option("-o", "--out", help="Output directory.")] = Path("exports"),
    sanitize: SanitizeOpt = False,
    lab: LabFlag = None,
    data_dir: DataOpt = None,
) -> None:
    """Export the current inventory. Redacted at collection time; --sanitize for sharing."""
    rt = _runtime(lab, data_dir)
    with rt.sessions() as s:
        doc = export.build(s)
    if sanitize:
        doc = export.sanitize(doc, sanitize_key(rt))
    suffix = "-sanitized" if sanitize else ""
    match fmt:
        case Format.json:
            _write(out / f"atlas{suffix}.json", export.to_json(doc))
        case Format.csv:
            for name, text in export.to_csv(doc).items():
                _write(out / f"csv{suffix}" / name, text)
        case Format.md:
            _write(out / f"atlas{suffix}.md", export.to_markdown(doc))
        case Format.mermaid:
            _write(out / f"physical{suffix}.mmd", export.to_mermaid(doc["topology"]["physical"]))
            _write(out / f"logical{suffix}.mmd", export.to_mermaid(doc["topology"]["logical"]))
        case Format.mkdocs:
            written = export.write_mkdocs(doc, out / f"mkdocs{suffix}")
            console.print(f"wrote {len(written)} files under {out / f'mkdocs{suffix}'}")


def lab_mcp_token(rt: Runtime) -> str:
    """Lab only: a random bearer token in a 0600 file next to the demo login."""
    path = rt.data_dir / "mcp-token.txt"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    console.print(f"lab MCP bearer token written to {path}")
    return token


def mcp_cmd(
    http: Annotated[bool, typer.Option("--http", help="Streamable HTTP instead of stdio.")] = False,
    host: Annotated[str, typer.Option(help="HTTP bind address (keep it private).")] = "127.0.0.1",
    port: int = 8765,
    allowed_host: Annotated[
        list[str] | None, typer.Option(help="Accepted Host header(s) for HTTP.")
    ] = None,
    sanitize: SanitizeOpt = False,
    lab: LabFlag = None,
    data_dir: DataOpt = None,
) -> None:
    """Read-only MCP server over the inventory (stdio by default)."""
    from homelab_atlas.mcp_server import BearerAuth, build_server  # noqa: PLC0415

    rt = _runtime(lab, data_dir)
    server = build_server(rt.sessions, sanitize_key=sanitize_key(rt) if sanitize else None)
    if not http:
        server.run("stdio")
        return

    import uvicorn  # noqa: PLC0415
    from mcp.server.transport_security import TransportSecuritySettings  # noqa: PLC0415

    if lab:
        token = lab_mcp_token(rt)
    else:
        try:
            token = SecretResolver().resolve(MCP_TOKEN_SECRET).get_secret_value()
        except (SecretError, SecurityRefusal) as exc:
            console.print(f"[red]error:[/] secret {MCP_TOKEN_SECRET!r} unavailable: {exc}")
            raise typer.Exit(2) from None
    hosts = allowed_host or [f"127.0.0.1:{port}", f"localhost:{port}"]
    app = server.streamable_http_app(
        host=host,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=[]
        ),
    )
    console.print(f"atlas MCP (read-only) on http://{host}:{port}/mcp")
    uvicorn.run(
        BearerAuth(app, token),
        host=host,
        port=port,
        server_header=False,
        date_header=False,
        log_level="warning",
    )


def register(app: typer.Typer) -> None:
    app.command("export")(export_cmd)
    app.command("mcp")(mcp_cmd)
