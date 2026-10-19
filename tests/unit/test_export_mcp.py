"""Exports (all formats, --sanitize leak checks) and the read-only MCP server."""

import asyncio
import ipaddress
import json
import re
from collections.abc import MutableMapping
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient
from typer.testing import CliRunner

from homelab_atlas.cli import app as cli_app
from homelab_atlas.export import build as export
from homelab_atlas.export.sanitize import Sanitizer
from homelab_atlas.mcp_server import MAX_RESULT_BYTES, BearerAuth, _cap, build_server
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import Annotation, Entity
from tests.helpers import scanned_lab

KEY = b"k" * 32
MAC_RE = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
NOTE = "ATLASFAKE private note: rack key is under the plant"


def _docker01(s: Session) -> str:
    key = s.scalar(
        select(Entity.key).where(Entity.kind == "linux-host", Entity.display_name == "docker01")
    )
    assert key is not None
    return key


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("data"))
    with runtime.sessions() as s:
        s.add(
            Annotation(
                entity_key=_docker01(s),
                owner="ATLASFAKE-owner",
                purpose="ATLASFAKE purpose",
                notes=NOTE,
                links=["https://wiki.internal.example/docker01"],
                source_file="docker01.yaml",
            )
        )
        s.commit()
    return runtime


@pytest.fixture(scope="module")
def doc(rt: Runtime) -> dict[str, Any]:
    with rt.sessions() as s:
        return export.build(s)


def _sensitive(doc: dict[str, Any]) -> dict[str, set[str]]:
    raw = export.to_json(doc)
    ips = {
        ip
        for ip in IPV4_RE.findall(raw)
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_global
    }
    ips -= {ip for ip in ips if ip.startswith("127.") or ip == "0.0.0.0"}
    v6 = set()
    for e in doc["ips"]:
        try:
            a = ipaddress.IPv6Address((e["ip"] or "").split("/")[0])
        except ValueError:
            continue
        if not (a.is_loopback or a.is_link_local):
            v6.add(a.compressed)
    facet_names: set[str] = set()
    for e in doc["entities"]:
        for f in e["facets"].values():
            if not isinstance(f, dict):
                continue
            if isinstance(f.get("os"), dict) and f["os"].get("hostname"):
                facet_names.add(f["os"]["hostname"])
            facet_names |= {x.get("name") or "" for x in f.get("ssids") or []}
            facet_names |= {x.get("name") or "" for x in f.get("clients") or []}
            facet_names |= set(f.get("search_domains") or [])
    return {
        "facet_name": {n for n in facet_names if len(n) >= 4},
        "mac": {m.lower() for m in MAC_RE.findall(raw)},
        "ipv4": ips,
        "ipv6": v6,
        "name": {e["name"] for e in doc["entities"] if len(e["name"]) >= 4},
    }


# ------------------------------------------------------------------ export


def test_build_document_shape(doc: dict[str, Any]) -> None:
    assert doc["schema"] == "atlas-export/1"
    kinds = {e["kind"] for e in doc["entities"]}
    assert {"linux-host", "pve-vm", "container", "unifi-device", "unknown-device"} <= kinds
    assert doc["ips"] and doc["ports"] and doc["vlans"] and doc["changes"]
    assert doc["topology"]["physical"] and doc["topology"]["logical"]
    assert json.loads(export.to_json(doc))["schema"] == "atlas-export/1"


def test_exports_never_contain_lab_secrets(doc: dict[str, Any]) -> None:
    """Fixture secrets carry ATLASFAKE; redaction at collection means none reach an export."""
    blob = export.to_json(doc) + export.to_markdown(doc) + "".join(export.to_csv(doc).values())
    hits = set(re.findall(r"ATLASFAKE[\w-]*", blob))
    # Only the annotation this test module wrote itself may appear (unsanitized export).
    assert hits <= {"ATLASFAKE", "ATLASFAKE-owner"}, hits


def test_csv_markdown_mermaid(doc: dict[str, Any]) -> None:
    csvs = export.to_csv(doc)
    assert set(csvs) == {
        "hosts.csv",
        "ips.csv",
        "ports.csv",
        "vlans.csv",
        "containers.csv",
        "unknown.csv",
    }
    assert all(text.count("\n") >= 2 for text in csvs.values())
    md = export.to_markdown(doc)
    assert md.startswith("#") and "```mermaid" in md
    mm = export.to_mermaid(doc["topology"]["physical"])
    assert mm.startswith("flowchart")
    assert all(
        re.fullmatch(r"[A-Za-z0-9_]+", line.split("[")[0].strip())
        for line in mm.splitlines()[1:]
        if "[" in line and "-->" not in line
    )


@pytest.mark.parametrize(
    "payload", ['=HYPERLINK("http://x")', "+1+cmd", "-2+3", "@SUM(A1)", "\t=1"]
)
def test_csv_formula_injection_neutralised(payload: str) -> None:
    import csv  # noqa: PLC0415
    import io  # noqa: PLC0415

    doc: dict[str, Any] = {
        "entities": [
            {
                "key": "k",
                "name": payload,
                "kind": "linux-host",
                "status": payload,
                "facets": {},
                "annotation": None,
            }
        ],
        "ips": [],
        "ports": [],
        "vlans": [],
        "unknown": [],
    }
    rows = list(csv.DictReader(io.StringIO(export.to_csv(doc)["hosts.csv"])))
    cells = [v for row in rows for v in row.values() if v and payload in v]
    assert cells
    assert all(v.startswith("'") for v in cells), cells


def test_mkdocs_site(doc: dict[str, Any], tmp_path: Path) -> None:
    written = export.write_mkdocs(doc, tmp_path)
    assert (tmp_path / "mkdocs.yml").is_file() and (tmp_path / "docs" / "index.md").is_file()
    assert len(list((tmp_path / "docs" / "hosts").glob("*.md"))) >= 10
    assert all(p.resolve().is_relative_to(tmp_path.resolve()) for p in written)


@pytest.mark.parametrize("fmt", ["json", "md", "csv", "mermaid", "mkdocs"])
def test_sanitized_exports_leak_nothing(doc: dict[str, Any], tmp_path: Path, fmt: str) -> None:
    san = export.sanitize(doc, KEY)
    match fmt:
        case "json":
            text = export.to_json(san)
        case "md":
            text = export.to_markdown(san)
        case "csv":
            text = "".join(export.to_csv(san).values())
        case "mermaid":
            text = export.to_mermaid(san["topology"]["physical"]) + export.to_mermaid(
                san["topology"]["logical"]
            )
        case _:
            text = "".join(
                p.read_text(encoding="utf-8") for p in export.write_mkdocs(san, tmp_path)
            )
    low = text.lower()
    for label, values in _sensitive(doc).items():
        # Names compare case-sensitively: "UCG-Ultra" as a vendor *model* string is fine.
        leaked = sorted(
            v for v in values if (v in text if label.endswith("name") else v.lower() in low)
        )
        assert not leaked, f"{fmt}: {label} leaked: {leaked[:10]}"
    assert NOTE not in text and "ATLASFAKE-owner" not in text and "wiki.internal" not in text


def test_sanitize_is_deterministic_and_keyed(doc: dict[str, Any]) -> None:
    a = export.to_json(export.sanitize(doc, KEY))
    b = export.to_json(export.sanitize(doc, KEY))
    c = export.to_json(export.sanitize(doc, b"x" * 32))
    strip = re.compile(r'"generated_at": "[^"]+"')
    assert strip.sub("", a) == strip.sub("", b)
    assert strip.sub("", a) != strip.sub("", c)


def test_sanitizer_preserves_structure() -> None:
    s = Sanitizer(KEY)
    a, b, c = s.ipv4("192.168.10.5"), s.ipv4("192.168.10.77"), s.ipv4("192.168.20.5")
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0] != c.rsplit(".", 1)[0]
    assert a.startswith("10.") and a.endswith(".5")
    assert s.text("listen 127.0.0.1:80 and 0.0.0.0:22") == "listen 127.0.0.1:80 and 0.0.0.0:22"
    v6 = s.text("addr 2a01:cb00:1234:5678:be24:11ff:fe6c:fcfe/64")
    assert "2001:db8:" in v6 and "2a01" not in v6 and "fe6c" not in v6 and v6.endswith("/64")
    mac = s.mac("BC:24:11:6C:FC:FE")
    assert int(mac[:2], 16) & 0x02 and mac == s.mac("bc:24:11:6c:fc:fe")


def test_sanitizer_mac_inside_keys_and_ipv6_untouched_by_mac_pass() -> None:
    s = Sanitizer(KEY)
    out = s.text("net:mac:84:f7:03:5f:2a:01 unifi:dev:e4:38:83:00:00:06")
    assert "84:f7:03" not in out and "e4:38:83" not in out
    # Eight groups: a MAC regex must not clip the last six; the IPv6 pass rewrites it whole.
    out6 = s.text("fd00:1:2:3:aa:bb:cc:dd")
    assert out6.startswith("2001:db8:")
    ipaddress.IPv6Address(out6)


def test_sanitizer_names_longest_first() -> None:
    s = Sanitizer(KEY)
    s.register(["docker01", "docker01-backup"], "host")
    out = s.text("docker01-backup replicates docker01")
    assert "docker01" not in out
    assert out.split()[0] != out.split()[-1]


def test_cli_export_sanitize(rt: Runtime, tmp_path: Path) -> None:
    res = CliRunner().invoke(
        cli_app,
        ["export", "json", "--sanitize", "--data-dir", str(rt.data_dir), "-o", str(tmp_path)],
    )
    assert res.exit_code == 0, res.output
    data = json.loads((tmp_path / "atlas-sanitized.json").read_text(encoding="utf-8"))
    assert data["sanitized"] is True
    assert all(e["annotation"] is None for e in data["entities"])


# ------------------------------------------------------------------ MCP


def _call(server: Any, name: str, **args: Any) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args))
    assert not res.is_error, res.content
    out: dict[str, Any] = res.structured_content
    return out


def test_mcp_tools_are_all_read_only(rt: Runtime) -> None:
    tools = asyncio.run(build_server(rt.sessions).list_tools())
    assert {t.name for t in tools} == {
        "list_hosts",
        "get_host",
        "list_containers",
        "search_ip",
        "find_service",
        "what_changed",
        "list_unknown_devices",
    }
    for t in tools:
        a = t.annotations
        assert a is not None
        assert (a.read_only_hint, a.destructive_hint, a.idempotent_hint, a.open_world_hint) == (
            True,
            False,
            True,
            False,
        )


def test_mcp_queries(rt: Runtime) -> None:
    srv = build_server(rt.sessions)
    hosts = _call(srv, "list_hosts", kind="linux-host")
    assert hosts["count"] >= 5 and all(h["kind"] == "linux-host" for h in hosts["items"])
    host = _call(srv, "get_host", name_or_key="docker01")
    with rt.sessions() as s:
        key = _docker01(s)
    assert host["key"] == key
    assert "linux-ssh" in host["facets"]
    assert host["annotation"]["notes"] == NOTE  # unsanitized: the owner's own data
    assert "error" in _call(srv, "get_host", name_or_key="no-such-host-xyz")
    ctrs = _call(srv, "list_containers", host="docker01")
    assert ctrs["count"] >= 3 and all(c["host"] == "docker01" for c in ctrs["items"])
    for c in ctrs["items"]:
        assert all("=" not in n for n in c["env_names"] or [])
    vlan30 = _call(srv, "search_ip", ip_or_cidr="10.0.30.0/24")
    assert vlan30["count"] >= 1
    assert all(
        ipaddress.ip_address(r["ip"]) in ipaddress.ip_network("10.0.30.0/24")
        for r in vlan30["items"]
    )
    assert _call(srv, "find_service", query="22")["ports"]
    assert _call(srv, "what_changed", since_hours=24)["count"] >= 1
    assert _call(srv, "list_unknown_devices")["count"] >= 1


def test_mcp_sanitized_leaks_nothing(rt: Runtime, doc: dict[str, Any]) -> None:
    srv = build_server(rt.sessions, sanitize_key=KEY)
    blob = json.dumps(
        [
            _call(srv, "list_hosts"),
            _call(srv, "get_host", name_or_key="docker01"),
            _call(srv, "list_containers"),
            _call(srv, "search_ip", ip_or_cidr="0.0.0.0/0"),
            _call(srv, "what_changed", since_hours=24),
            _call(srv, "list_unknown_devices", include_acknowledged=True),
        ]
    )
    low = blob.lower()
    sens = _sensitive(doc)
    for label in ("mac", "ipv4", "name"):
        leaked = sorted(
            v for v in sens[label] if (v in blob if label == "name" else v.lower() in low)
        )
        assert not leaked, f"{label} leaked: {leaked[:10]}"
    assert NOTE not in blob


def test_mcp_result_cap() -> None:
    big = {"count": 10_000, "items": [{"x": "y" * 100} for _ in range(10_000)]}
    capped = _cap(big)
    assert capped["truncated"] is True and capped["count"] == 10_000
    assert len(json.dumps(capped).encode()) <= MAX_RESULT_BYTES
    facets = _cap({"key": "k", "facets": {"docker": "z" * (MAX_RESULT_BYTES + 1)}})
    assert facets["truncated"] and facets["facets"]["docker"].startswith("omitted")


def _guarded(token: str) -> TestClient:
    inner = Starlette(routes=[Route("/mcp", lambda r: PlainTextResponse("ok"), methods=["POST"])])
    return TestClient(BearerAuth(inner, token))


def test_bearer_auth() -> None:
    token = "t" * 40
    c = _guarded(token)
    assert c.post("/mcp").status_code == 401
    assert c.post("/mcp", headers={"Authorization": "Bearer " + "t" * 39}).status_code == 401
    assert c.post("/mcp", headers={"Authorization": f"bearer {token}"}).status_code == 401
    r = c.post("/mcp", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.text == "ok"
    challenge = c.post("/mcp", headers={"Authorization": "Bearer "}).headers["www-authenticate"]
    assert challenge == "Bearer"
    with pytest.raises(ValueError, match="32"):
        BearerAuth(Starlette(), "short")


def test_bearer_guards_real_streamable_app(rt: Runtime) -> None:
    app = build_server(rt.sessions).streamable_http_app()
    with TestClient(BearerAuth(app, "s" * 40)) as c:
        r = c.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        assert r.status_code == 401


EVIL = '<script>alert(1)</script> [x](javascript:alert(1)) `code` "q\\" ** _e_ |pipe\n# heading'


def _evil_doc() -> dict[str, Any]:
    ent = {
        "key": "host:evil`key",
        "name": EVIL,
        "kind": "linux-host",
        "status": "ok",
        "parent": None,
        "same_as": None,
        "annotation": {
            "owner": EVIL,
            "purpose": None,
            "criticality": None,
            "tags": [EVIL],
            "notes": EVIL,
        },
        "facets": {"linux-ssh": {"os": {"os_pretty": EVIL, "kernel": EVIL}}},
    }
    return {
        "schema": "atlas-export/1",
        "generated_at": "now",
        "atlas_version": "t",
        "entities": [ent],
        "ips": [{"ip": "10.0.0.1", "name": EVIL}],
        "vlans": [],
        "ports": [],
        "unknown": [],
        "changes": [{"at": "now", "severity": "info", "type": "t", "summary": EVIL}],
        "topology": {"physical": [{"data": {"id": "host:evil", "label": EVIL}}], "logical": []},
    }


def _assert_inert(text: str) -> None:
    assert "<script" not in text
    assert not re.search(r"(?<!\\)\]\(javascript:", text)  # brackets stay escaped
    assert "\n# heading" not in text  # no injected blocks
    assert "`code`" not in text


def test_markdown_escapes_target_data() -> None:
    md = export.to_markdown(_evil_doc())
    _assert_inert(md)
    assert "&lt;script&gt;" in md


def test_mkdocs_escapes_and_nav_is_valid_yaml(tmp_path: Path) -> None:
    import yaml  # noqa: PLC0415

    written = export.write_mkdocs(_evil_doc(), tmp_path)
    for p in written:
        if p.suffix == ".md":
            _assert_inert(p.read_text(encoding="utf-8"))
    cfg = yaml.safe_load(
        (tmp_path / "mkdocs.yml").read_text(encoding="utf-8").replace("!!python/name:", "")
    )
    assert cfg["site_name"] == "Homelab inventory"


def test_mcp_refuses_oversized_arguments(rt: Runtime) -> None:
    from mcp.server.mcpserver.exceptions import ToolError  # noqa: PLC0415

    with pytest.raises(ToolError, match="at most 128 characters"):
        asyncio.run(build_server(rt.sessions).call_tool("get_host", {"name_or_key": "x" * 500}))


async def test_bearer_guards_websocket_scopes() -> None:
    sent: list[MutableMapping[str, Any]] = []
    reached: list[bool] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        reached.append(True)

    async def send(msg: MutableMapping[str, Any]) -> None:
        sent.append(msg)

    async def receive() -> dict[str, Any]:
        return {"type": "websocket.connect"}

    guard = BearerAuth(inner, "w" * 40)
    await guard({"type": "websocket", "headers": []}, receive, send)
    assert sent == [{"type": "websocket.close", "code": 1008}]
    assert reached == []
    await guard(
        {"type": "websocket", "headers": [(b"authorization", b"Bearer " + b"w" * 40)]},
        receive,
        send,
    )
    assert reached == [True]
