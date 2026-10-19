"""v2 UI read models and pages: machines, Running, grouped IPs, Proxmox topology (ADR-029/030)."""

import ipaddress
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from homelab_atlas.runtime import Runtime
from homelab_atlas.web import auth, views
from homelab_atlas.web.app import WebConfig, create_app
from tests.helpers import scanned_lab

PASSWORD = "v2-pages-ATLASFAKE-pw"  # test value for the app under test


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("v2"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


@pytest.fixture
def web(rt: Runtime, tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path,
            allowed_hosts=["testserver"],
            lab=True,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        page = c.get("/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
        assert token is not None
        r = c.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


def _card(cards: list[dict[str, Any]], short: str) -> dict[str, Any]:
    return next(m for m in cards if m["short"] == short)


# ------------------------------------------------------------------ read models


def test_machines_merge_vm_and_inner_host(rt: Runtime) -> None:
    with rt.sessions() as s:
        cards = views.machines(s)
    keys = [m["key"] for m in cards]
    assert len(keys) == len(set(keys))
    assert {m["kind"] for m in cards} <= set(views.MACHINE_KINDS)
    docker01 = _card(cards, "docker01")
    assert docker01["kind"] == "pve-vm"
    assert docker01["node"] == "pve1"
    assert docker01["documented"] is True  # atlas logs in to it over SSH
    assert docker01["containers"] >= 8
    assert docker01["services"] > 0
    assert "Docker" in {a["name"] for a in docker01["apps"]}
    # Proxmox ostype codes are shown as words.
    assert all(m["os"] not in set(views.OSTYPES) for m in cards if m["os"])
    # Hypervisors first, then guests, then the rest.
    assert cards[0]["kind"] == "pve-node"


def test_running_on_one_machine(rt: Runtime) -> None:
    with rt.sessions() as s:
        run = views.running(s, "pve:vm:homelab/101")
    names = {c["name"] for c in run["containers"]}
    assert {"immich_server", "traefik", "vaultwarden"} <= names
    assert run["services"]
    assert run["process_count"] >= len(run["processes"])
    assert len(run["processes"]) <= 60
    units = [x["unit"] for x in run["services"]]
    assert units == sorted(units)


def test_everything_running_filters(rt: Runtime) -> None:
    with rt.sessions() as s:
        everything = views.everything_running(s)
        immich = views.everything_running(s, "immich")
    assert everything["machines"]
    assert everything["apps_by_category"]
    assert len(immich["containers"]) < len(everything["containers"])
    assert immich["containers"]
    assert all("immich" in str(c).lower() for c in immich["containers"])


def test_ip_groups_one_row_per_device(rt: Runtime) -> None:
    with rt.sessions() as s:
        default = views.ip_groups(s)
        full = views.ip_groups(s, everything=True)
        only = views.ip_groups(s, "10.0.30")
    keys = [g["key"] for g in default["groups"]]
    assert len(keys) == len(set(keys))
    # A MAC belongs to one device row (no "unifi client + unknown" duplicates).
    macs = Counter(m for g in default["groups"] for m in g["macs"])
    assert [m for m, n in macs.items() if n > 1] == []
    for g in default["groups"]:
        assert g["primary"] == (g["ips"][0]["ip"] if g["ips"] else None)
        for ip in g["ips"]:
            a = ipaddress.ip_address(ip["ip"].split("/")[0])
            assert not (a.is_link_local or a.is_loopback), ip
            assert not views.INTERNAL_IFACE_RE.match(ip["iface"] or ""), ip
    assert full["hidden"] == 0
    assert default["hidden"] > 0
    assert sum(len(g["ips"]) for g in full["groups"]) > sum(
        len(g["ips"]) for g in default["groups"]
    )
    assert only["groups"]
    assert all("10.0.30" in str(g) for g in only["groups"])


def test_discovered_not_documented_is_infrastructure_only(rt: Runtime) -> None:
    with rt.sessions() as s:
        found = views.discovered_not_documented(s)
        cards = views.machines(s)
    documented = {ip.split("/")[0] for m in cards if m["documented"] for ip in m["ips"]}
    for d in found:
        assert d["category"] not in {"phone", "iot", "tv", "printer"}, d
        assert d["ip"] not in documented, d
        assert d["type"] in {"pi", "linux"}


# ------------------------------------------------------------------ pages


def test_dashboard_v2(web: TestClient) -> None:
    body = web.get("/").text
    assert "apps recognised" in body
    assert "Pi-hole, NetBox, Jellyfin" not in body  # computed, not a placeholder
    assert "docker01" in body
    assert 'data-filter-target="machines"' in body or "data-filter-target" in body


def test_running_page_and_htmx_filter(web: TestClient) -> None:
    r = web.get("/running")
    assert r.status_code == 200
    assert "immich-server" in r.text
    r = web.get("/running?q=vaultwarden")
    assert r.status_code == 200
    assert "vaultwarden" in r.text
    assert web.get("/running?q=" + "x" * 65).status_code == 422


def test_entity_page_has_running_panel(web: TestClient) -> None:
    body = web.get("/entity?key=pve:vm:homelab/101").text
    assert "data-tabset" in body
    assert "immich-server" in body
    # A device atlas does not log in to has no Running panel.
    unknown = web.get("/entity?key=net:mac:84:f7:03:5f:2a:01")
    assert unknown.status_code == 200
    assert "data-tabset" not in unknown.text


def test_ips_page_grouped(web: TestClient) -> None:
    body = web.get("/ips").text
    assert "link-local / container-network addresses hidden" in body
    assert "show them" in body
    every = web.get("/ips?everything=true").text
    assert "Hide link-local" in every
    partial = web.get("/ips?q=10.0.30", headers={"HX-Request": "true"})
    assert "10.0.30.41" in partial.text


def test_topology_proxmox_view(web: TestClient) -> None:
    data = web.get("/api/topology?view=logical").json()
    nodes = {e["data"]["id"]: e["data"] for e in data["elements"] if "source" not in e["data"]}
    edges = [e["data"] for e in data["elements"] if "source" in e["data"]]
    kinds = Counter(n.get("kind") for n in nodes.values())
    assert kinds["pve-cluster"] == 1
    assert kinds["pve-node"] == 2
    assert kinds["container"] >= 8
    assert "group:other" in nodes
    for n in nodes.values():
        if n.get("parent"):
            assert n["parent"] in nodes, n
        if n.get("kind") in {"pve-vm", "pve-lxc"}:
            assert nodes[n["parent"]]["kind"] == "pve-node", n
        if n.get("kind") == "container":
            assert n["host"] in nodes, n
    runs = [e for e in edges if e.get("kind") == "runs"]
    assert len(runs) == kinds["container"]
    assert all(nodes[e["target"]]["kind"] == "container" for e in runs)
    docker01 = nodes["pve:vm:homelab/101"]
    assert docker01["ip"]  # second label line
