"""MCP for assistants (ADR-036): machine-level tools, opt-in live scan, stdio hygiene."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from homelab_atlas.mcp_server import build_server, engine_scanner, find_machine
from homelab_atlas.runtime import Runtime
from tests.helpers import scanned_lab

REPO = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    return scanned_lab(tmp_path_factory.mktemp("mcp2"))


def _call(server: Any, name: str, **args: Any) -> dict[str, Any]:
    res = asyncio.run(server.call_tool(name, args))
    assert not res.is_error, res.content
    out: dict[str, Any] = res.structured_content
    return out


def test_find_machine_by_name_ip_key_and_fragment(rt: Runtime) -> None:
    with rt.sessions() as s:
        assert find_machine(s, "docker01")["key"] == "pve:vm:homelab/101"  # type: ignore[index]
        assert find_machine(s, "DOCKER01")["key"] == "pve:vm:homelab/101"  # type: ignore[index]
        assert find_machine(s, "10.0.20.11")["short"] == "docker01"  # type: ignore[index]
        assert find_machine(s, "pve:vm:homelab/101")["short"] == "docker01"  # type: ignore[index]
        assert find_machine(s, "garage")["short"] == "pi-garage"  # type: ignore[index]
        assert find_machine(s, "docker") is None  # ambiguous: docker01, docker02
        assert find_machine(s, "") is None


def test_whats_running(rt: Runtime) -> None:
    srv = build_server(rt.sessions)
    r = _call(srv, "whats_running", machine="docker01")
    assert r["machine"]["name"] == "docker01"
    assert r["machine"]["kind"] == "VM"
    assert r["machine"]["last_scan"] == "ok"
    assert {"Docker", "Immich", "Vaultwarden"} <= {a["name"] for a in r["apps"]}
    assert {c["name"] for c in r["containers"]} >= {"immich_server", "traefik"}
    assert any(u["unit"] == "ssh.service" for u in r["services_running"])
    assert "tcp/2283 docker-proxy" in r["listening"]
    assert r["note"] is None
    db = _call(srv, "whats_running", machine="db01")
    assert "postgresql@15-main.service" in db["services_failed"]
    missing = _call(srv, "whats_running", machine="nope-xyz")
    assert "error" in missing
    assert "docker01" in missing["machines"]
    undocumented = _call(srv, "whats_running", machine="win11")
    assert undocumented["note"]  # not an SSH target: says so


def test_list_machines_and_filters(rt: Runtime) -> None:
    srv = build_server(rt.sessions)
    every = _call(srv, "list_machines")
    names = {m["name"] for m in every["items"]}
    assert {"pve1", "pve2", "docker01", "pi-garage", "unas"} <= names
    vms = _call(srv, "list_machines", kind="vm")
    assert vms["items"]
    assert all(m["kind"] == "VM" for m in vms["items"])
    nodes = _call(srv, "list_machines", kind="node")
    assert {m["name"] for m in nodes["items"]} == {"pve1", "pve2"}
    immich = _call(srv, "list_machines", query="immich")
    assert [m["name"] for m in immich["items"]] == ["docker01"]


def test_list_services_and_proxmox_and_scan_status(rt: Runtime) -> None:
    srv = build_server(rt.sessions)
    failed = _call(srv, "list_services", state="failed")
    assert failed["items"]
    assert all(r["state"] == "failed" for r in failed["items"])
    one = _call(srv, "list_services", machine="docker01", state="all", kind="container")
    assert {r["machine"] for r in one["items"]} == {"docker01"}
    assert "error" in _call(srv, "list_services", machine="nope-xyz")
    pve = _call(srv, "proxmox_overview")
    assert pve["totals"]["nodes"] == 2
    by_node = {n["node"]: n for n in pve["nodes"]}
    assert "docker01" in {g["name"] for g in by_node["pve1"]["guests"]}
    assert all("vmbr0" in g["bridges"] for g in by_node["pve1"]["guests"] if g["bridges"])
    st = _call(srv, "scan_status")
    assert st["summary"]["failed"] >= 1
    assert st["live_scan_available"] is False
    ghost = next(i for i in st["items"] if i["target"] == "ghost01")
    assert ghost["health"] == "failed"
    assert ghost["runs"][0]["errors"]
    ports = _call(srv, "unrecognised_ports")
    assert {"process labelmaker", "port 5000 (python3)"} <= {p["what"] for p in ports["items"]}


def test_what_changed_per_machine(rt: Runtime) -> None:
    srv = build_server(rt.sessions)
    every = _call(srv, "what_changed", since_hours=24 * 30)
    mine = _call(srv, "what_changed", since_hours=24 * 30, machine="docker01")
    assert 0 < mine["count"] < every["count"]
    assert "error" in _call(srv, "what_changed", machine="nope-xyz")


def test_scan_machine_is_opt_in_rate_limited_and_honest(rt: Runtime) -> None:
    seen: list[str] = []

    async def fake_scan(target: str) -> dict[str, Any]:
        seen.append(target)
        return {"status": "done", "runs": []}

    plain = asyncio.run(build_server(rt.sessions).list_tools())
    assert "scan_machine" not in {t.name for t in plain}
    srv = build_server(rt.sessions, scanner=fake_scan)
    tool = next(t for t in asyncio.run(srv.list_tools()) if t.name == "scan_machine")
    a = tool.annotations
    assert a is not None
    # It changes atlas's database and reaches the network: not "read-only".
    assert (a.read_only_hint, a.destructive_hint, a.open_world_hint) == (False, False, True)
    first = _call(srv, "scan_machine", machine="docker01")
    assert first["status"] == "done"
    assert seen == ["docker01"]
    again = _call(srv, "scan_machine", machine="docker01")
    assert again["status"] == "skipped"
    assert seen == ["docker01"]  # one scan per machine per minute
    assert "error" in _call(srv, "scan_machine", machine="win11")  # not a target
    assert _call(srv, "scan_status")["live_scan_available"] is True


def test_engine_scanner_runs_one_target(rt: Runtime) -> None:
    from homelab_atlas.runtime import lab_inputs  # noqa: PLC0415

    scan = engine_scanner(lambda: rt.scan_engine(lab_inputs("B")))
    result = asyncio.run(scan("web01"))
    assert result["status"] == "done"
    assert {r["collector"] for r in result["runs"]} == {"linux-ssh"}
    assert all(r["status"] == "ok" for r in result["runs"])


def test_stdio_session_end_to_end(tmp_path: Path) -> None:
    """A real `atlas mcp --allow-scan` process: stdout carries only the protocol."""
    from mcp import ClientSession, StdioServerParameters  # noqa: PLC0415
    from mcp.client.stdio import stdio_client  # noqa: PLC0415

    data = tmp_path / "lab"
    scanned_lab(data)
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "homelab_atlas", "mcp", "--lab", "demo", "--data-dir", str(data),
              "--allow-scan"],
        env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        cwd=str(REPO),
    )  # fmt: skip

    async def session() -> tuple[set[str], dict[str, Any], dict[str, Any]]:
        async with stdio_client(params) as (read, write), ClientSession(read, write) as c:
            await c.initialize()
            tools = {t.name for t in (await c.list_tools()).tools}
            scan = await c.call_tool("scan_machine", {"machine": "web01"})
            run = await c.call_tool("whats_running", {"machine": "web01"})
            return tools, json.loads(scan.content[0].text), json.loads(run.content[0].text)  # type: ignore[union-attr]

    tools, scan, run = asyncio.run(asyncio.wait_for(session(), 120))
    assert {"whats_running", "scan_machine", "list_machines"} <= tools
    assert scan["status"] == "done"
    assert "Nginx" in {a["name"] for a in run["apps"]}
