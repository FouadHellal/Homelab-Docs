"""v6: sidebar shell, login autofill markup, app pages and knowledge, topology dedupe."""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from homelab_atlas.collectors.base import CollectorResult
from homelab_atlas.collectors.docker import collector as docker_collector
from homelab_atlas.collectors.proxmox.collector import http_hint
from homelab_atlas.engine.apps import CATALOG
from homelab_atlas.engine.knowledge import ABOUT, search_links
from homelab_atlas.engine.reconcile import _own_node
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import Facet
from homelab_atlas.web import auth, topology, views
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit, scanned_lab

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
PASSWORD = "v6-pages-ATLASFAKE-pw"  # test value for the app under test


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("v6"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


@pytest.fixture
def web(rt: Runtime, tmp_path: Path) -> Iterator[TestClient]:
    inv, _ = load_lab("B", LAB)
    svc = TargetsService(config_dir=tmp_path / "cfg", data_dir=tmp_path / "data", vault=None,
                         audit=MemoryAudit(), readonly_inventory=inv)  # fmt: skip
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path,
            allowed_hosts=["testserver"],
            lab=True,
            targets=svc,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
        assert token is not None
        r = c.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


# ------------------------------------------------------------------ shell and login


def test_login_form_is_recognisable_by_password_managers(rt: Runtime, tmp_path: Path) -> None:
    app = create_app(WebConfig(sessions=rt.sessions, annotations_dir=tmp_path,
                               allowed_hosts=["testserver"]))  # fmt: skip
    with TestClient(app, base_url="https://testserver") as c:
        html = c.get("/login").text
    assert 'method="post"' in html and 'action="/login"' in html
    assert re.search(
        r'<input id="username" name="username" type="text" autocomplete="username"', html
    )
    assert 'id="password" name="password" type="password" autocomplete="current-password"' in html
    assert '<label for="username">' in html and '<label for="password">' in html


def test_sidebar_shell_marks_the_current_page(web: TestClient) -> None:
    html = web.get("/services").text
    assert '<aside class="side" id="side"' in html
    assert re.search(r'class="nav-item" href="/services"[^>]*aria-current="page"', html)
    assert 'id="side-open"' in html and 'class="scrim"' in html  # phone drawer
    assert html.count("<svg") >= 15  # icons inline, no icon font
    assert web.get("/static/logo.svg").text.lstrip().startswith("<svg")
    font = web.get("/static/vendor/fonts/geist-latin-wght-normal.woff2")
    assert font.status_code == 200 and font.content[:4] == b"wOF2"


# ------------------------------------------------------------------ app pages


def test_every_builtin_app_has_notes() -> None:
    assert {a.name for a in CATALOG} <= set(ABOUT)
    for a in ABOUT.values():
        assert a.url.startswith("https://") and a.summary.endswith(".")


def test_search_links_are_for_the_browser_only() -> None:
    links = dict(search_links("Action1 agent homelab"))
    assert links["Search the web"] == "https://duckduckgo.com/?q=Action1+agent+homelab"


def test_app_page_for_an_agent(web: TestClient) -> None:
    r = web.get("/app", params={"name": "Action1 agent"})
    assert r.status_code == 200
    assert "cloud RMM" in r.text and "Action1 Corporation" in r.text
    assert "web01" in r.text and "action1_agent" in r.text
    assert 'href="https://duckduckgo.com/?q=Action1+agent+homelab"' in r.text
    assert 'rel="noopener noreferrer"' in r.text


def test_app_page_for_a_plain_unit_uses_its_description(web: TestClient) -> None:
    r = web.get("/app", params={"name": "cron"})
    assert r.status_code == 200
    assert "Regular background program processing daemon" in r.text
    assert "service / container" in r.text


def test_app_page_shows_package_versions(rt: Runtime) -> None:
    with rt.sessions() as s:
        d = views.app_detail(s, "nginx")
    web01 = next(h for h in d["hosts"] if h["short"] == "web01")
    assert web01["version"] == "1.24.0-2ubuntu7.1"


def test_app_page_rejects_overlong_names(web: TestClient) -> None:
    assert web.get("/app", params={"name": "x" * 97}).status_code == 422


def test_chips_and_units_link_to_app_pages(web: TestClient) -> None:
    running = web.get("/running").text
    assert 'href="/app?name=Docker"' in running
    services = web.get("/services", params={"state": "all"}).text
    assert 'href="/app?name=cron"' in services
    dash = web.get("/").text
    assert '<a class="machine"' in dash and '<a class="chip"' not in dash  # no nested links


# ------------------------------------------------------------------ topology + collectors


def _node_facet(key: str, name: str, ip: str | None) -> Facet:
    return Facet(entity_key=key, collector="linux-ssh", target="t", scan_id=1,
                 data={"name": name, "ip": ip, "pve_version": "8.2"})  # fmt: skip


def test_pve_host_is_linked_to_its_own_node_without_an_ip() -> None:
    nodes = [_node_facet("pve:node:pve1/pve1", "pve1", None),
             _node_facet("pve:node:pve2/pve2", "pve2", None)]  # fmt: skip
    host: dict[str, Any] = {"pve": {"node": "pve2", "cluster": None}, "os": {"hostname": "x"}}
    assert _own_node(host, nodes, set()) == "pve:node:pve2/pve2"
    assert _own_node({"os": {"hostname": "PVE1.lan"}}, nodes, set()) == "pve:node:pve1/pve1"
    assert _own_node({"os": {"hostname": "other"}}, nodes, set()) is None


def test_proxmox_view_shows_each_node_once_with_its_guests(rt: Runtime) -> None:
    with rt.sessions() as s:
        els = topology.build(s, "logical")
    boxes = [e["data"] for e in els if e["data"].get("kind") == "pve-node"]
    assert sorted(b["label"].split("  ·  ")[0] for b in boxes) == ["pve1", "pve2"]
    other = {e["data"]["id"] for e in els if e["data"].get("parent") == "group:other"}
    assert not any(k.startswith("pve:") for k in other)
    parents = {e["data"]["label"]: e["data"].get("parent") for e in els if "vmid" in e["data"]}
    assert parents["docker01"] == "pve:node:homelab/pve1"
    assert parents["docker02"] == "pve:node:homelab/pve2"


async def test_docker_not_installed_is_not_a_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(*_a: Any, **_k: Any) -> CollectorResult:
        r = CollectorResult("docker", "zabbix", "failed")
        r.errors = [docker_collector.NOT_INSTALLED]
        return r

    monkeypatch.setattr(docker_collector, "collect_section", fake)
    res = await docker_collector.DockerCollector().collect("zabbix", None)  # type: ignore[arg-type]
    assert res.status == "ok"
    assert res.errors == ["docker is not installed on this machine"]


async def test_docker_unreadable_says_what_to_do(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(*_a: Any, **_k: Any) -> CollectorResult:
        r = CollectorResult("docker", "utils", "failed")
        r.errors = [docker_collector.UNREADABLE]
        return r

    monkeypatch.setattr(docker_collector, "collect_section", fake)
    res = await docker_collector.DockerCollector().collect("utils", None)  # type: ignore[arg-type]
    assert res.status == "failed"
    assert "use for sudo" in res.errors[0]


def test_proxmox_http_hints() -> None:
    assert "token was refused" in http_hint(401)
    assert "PVEAuditor" in http_hint(403)
    assert http_hint(418) == "HTTP 418 from the Proxmox API"
