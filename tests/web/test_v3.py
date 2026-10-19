"""v3: per-target scan status, Proxmox facet priority, Services table + CSV, quick find, docs,
and the Proxmox flow topology (ADR-031/032)."""

import csv
import io
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from homelab_atlas.engine.apps import app_for_unit
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import CollectorRun, Facet, Scan
from homelab_atlas.web import auth, queries, views
from homelab_atlas.web.app import WebConfig, _ago, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit, scanned_lab

PASSWORD = "v3-pages-ATLASFAKE-pw"  # test value for the app under test
LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("v3"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


def _client(rt: Runtime, tmp_path: Path) -> TestClient:
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
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def web(rt: Runtime, tmp_path: Path) -> Iterator[TestClient]:
    with _client(rt, tmp_path) as c:
        token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
        assert token is not None
        r = c.post(
            "/login",
            data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
            follow_redirects=False,
        )
        assert r.status_code == 303
        yield c


# ------------------------------------------------------------------ small pieces


def test_facet_views_pick_the_strongest_proxmox_source() -> None:
    def f(key: str, collector: str, **data: Any) -> Facet:
        return Facet(entity_key=key, collector=collector, target="t", scan_id=1, data=data)

    rows = [
        f("pve:vm:c/1", "pve-ssh-peer", status="unknown"),
        f("pve:vm:c/1", "pve-ssh", status="running"),
        f("pve:vm:c/2", "pve-ssh-peer", status="unknown"),
        f("pve:vm:c/3", "proxmox", status="stopped"),
        f("pve:vm:c/3", "pve-ssh", status="running"),
        f("host:x", "linux-ssh", os={}),
    ]
    got = {(v.entity_key, v.collector): (v.source, v.data.get("status"))
           for v in facet_views(rows)}  # fmt: skip
    assert got == {
        ("pve:vm:c/1", "proxmox"): ("pve-ssh", "running"),
        ("pve:vm:c/2", "proxmox"): ("pve-ssh-peer", "unknown"),
        ("pve:vm:c/3", "proxmox"): ("proxmox", "stopped"),  # the API wins
        ("host:x", "linux-ssh"): ("linux-ssh", None),
    }


def test_app_for_unit() -> None:
    pihole = app_for_unit("pihole-FTL.service")
    assert pihole is not None
    assert pihole.name == "Pi-hole"
    wg = app_for_unit("wg-quick@wg0.service")
    assert wg is not None
    assert wg.name == "WireGuard"
    assert app_for_unit("systemd-journald.service") is None


def test_ago() -> None:
    now = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)
    assert _ago(None, now) == "never"
    assert _ago(now - timedelta(seconds=20), now) == "just now"
    assert _ago(now - timedelta(minutes=5), now) == "5 min ago"
    assert _ago((now - timedelta(hours=3)).replace(tzinfo=None), now) == "3 h ago"
    assert _ago(now - timedelta(days=2), now) == "2 d ago"


# ------------------------------------------------------------------ scan status per target


def test_latest_runs_survive_a_later_scheduled_scan(rt: Runtime) -> None:
    with rt.sessions() as s:
        before = queries.latest_runs(s)
        failed = {t for t, rs in before.items() if queries.target_health(rs) == "failed"}
        assert failed  # the demo lab has unreachable hosts
        # A scheduled UniFi-only scan finishes last: failures elsewhere must still show.
        scan = Scan(mode="demo", label="sched:unifi", status="done",
                    finished_at=datetime.now(UTC))  # fmt: skip
        s.add(scan)
        s.flush()
        unifi_target = next(t for t, rs in before.items() if rs[0]["collector"] == "unifi")
        s.add(CollectorRun(scan_id=scan.id, target=unifi_target, collector="unifi", status="ok"))
        s.flush()
        d = queries.dashboard(s, {*before, "brand-new-vm"})
        assert {p.target for p in d["problems"]} >= failed
        assert d["never_scanned"] == ["brand-new-vm"]
        after = queries.latest_runs(s)
        assert after[unifi_target][0]["status"] == "ok"
        for t in failed:
            assert any(r["last_ok"] is None or r["status"] != "ok" for r in after[t])
        s.rollback()


def test_target_health() -> None:
    assert queries.target_health(None) == "never"
    assert queries.target_health([{"status": "ok"}, {"status": "partial"}]) == "partial"
    assert queries.target_health([{"status": "ok"}, {"status": "refused"}]) == "failed"
    assert queries.target_health([{"status": "ok"}]) == "ok"


def test_targets_page_shows_last_scan(web: TestClient) -> None:
    body = web.get("/targets").text
    assert "<th>Last scan</th>" in body
    assert 'class="pill ok">ok</span>' in body
    assert "run-err" in body  # a failed target explains itself
    assert 'id="t-web01"' in body


def test_dashboard_lists_failed_targets_with_reason(web: TestClient) -> None:
    body = web.get("/").text
    assert "Needs attention" in body
    assert "/targets#t-" in body
    assert "Every collector answered on the last scan" not in body


# ------------------------------------------------------------------ services table + CSV


def test_service_table_filters(rt: Runtime) -> None:
    with rt.sessions() as s:
        running = views.service_table(s)
        everything = views.service_table(s, state="all")
        failed = views.service_table(s, state="failed")
        ctrs = views.service_table(s, state="all", kind="container")
        one = views.service_table(s, state="all", machine="docker01")
        q = views.service_table(s, state="all", q="postgres")
    assert everything["total"] == len(everything["rows"])
    assert len(running["rows"]) == running["counts"]["running"]
    assert sum(running["counts"].values()) == everything["total"]
    assert all(r["state"] == "failed" for r in failed["rows"])
    assert failed["rows"]
    assert ctrs["rows"]
    assert all(r["type"] == "container" for r in ctrs["rows"])
    assert {r["machine"] for r in one["rows"]} == {"docker01"}
    assert any(r["type"] == "container" for r in one["rows"])
    assert q["rows"]
    assert all("postgres" in str(r).lower() for r in q["rows"])
    ssh = next(r for r in everything["rows"] if r["name"] == "ssh")
    assert ssh["app"] == "OpenSSH"
    assert ssh["kind"] in views.KIND_LABELS.values()
    assert set(views.SERVICE_COLUMNS) <= set(ssh)


def test_services_page_and_htmx_partial(web: TestClient) -> None:
    page = web.get("/services?state=all")
    assert page.status_code == 200
    assert "Export CSV" in page.text
    assert 'href="/services.csv?state=all"' in page.text
    part = web.get("/services?state=failed&kind=systemd", headers={"HX-Request": "true"})
    assert "<html" not in part.text
    assert "of" in part.text
    # Unknown values fall back to the defaults instead of erroring.
    assert web.get("/services?state=bogus&kind=bogus").status_code == 200
    assert web.get("/services?q=" + "x" * 65).status_code == 422


def test_services_csv(web: TestClient, rt: Runtime) -> None:
    # A unit description that a spreadsheet would execute must come out neutralised.
    with rt.sessions() as s:
        f = next(
            f for f in s.scalars(select(Facet).where(Facet.collector == "linux-ssh"))
            if f.data.get("services")
        )  # fmt: skip
        original = f.data
        data = dict(original)
        data["services"] = [*original["services"], {"unit": "evil.service", "active": "active",
                            "description": "=HYPERLINK(\"http://x\")"}]  # fmt: skip
        f.data = data
        s.commit()
    try:
        r = web.get("/services.csv?state=all")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/csv")
        assert r.headers["content-disposition"].startswith('attachment; filename="atlas-services-')
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert list(rows[0]) == list(views.SERVICE_COLUMNS)
        evil = next(x for x in rows if x["name"] == "evil")
        assert evil["description"].startswith("'=")
        only = list(csv.DictReader(io.StringIO(web.get("/services.csv?state=failed").text)))
        assert only
        assert {x["state"] for x in only} == {"failed"}
    finally:
        with rt.sessions() as s:
            fresh = s.get(Facet, (f.entity_key, f.collector))
            assert fresh is not None
            fresh.data = original
            s.commit()


def test_services_need_login(rt: Runtime, tmp_path: Path) -> None:
    with _client(rt, tmp_path) as c:
        assert c.get("/services.csv", follow_redirects=False).status_code in (303, 401)
        assert c.get("/api/palette").status_code == 401


# ------------------------------------------------------------------ quick find, docs, favicon


def test_palette(web: TestClient) -> None:
    items = web.get("/api/palette").json()["items"]
    labels = {i["label"] for i in items}
    assert {"Dashboard", "Services", "Documentation", "docker01"} <= labels
    assert all(i["href"].startswith("/") for i in items)  # never off-site
    machine = next(i for i in items if i["label"] == "docker01")
    assert machine["href"] == "/entity?key=pve%3Avm%3Ahomelab%2F101"


def test_docs_nav_and_favicon(web: TestClient) -> None:
    docs = web.get("/docs").text
    for anchor in ("start", "targets", "proxmox", "unifi", "update", "trouble", "security"):
        assert f'id="{anchor}"' in docs
    assert "PVEAuditor" in docs
    assert 'href="/static/favicon.svg"' in docs
    assert 'class="dropdown"' in docs
    assert 'href="/services"' in docs
    icon = web.get("/static/favicon.svg")
    assert icon.status_code == 200
    assert icon.text.lstrip().startswith("<svg")


# ------------------------------------------------------------------ topology: Proxmox flow


def test_proxmox_flow_topology(web: TestClient) -> None:
    els = web.get("/api/topology?view=logical").json()["elements"]
    nodes = {e["data"]["id"]: e["data"] for e in els if "target" not in e["data"]}
    edges = [e["data"] for e in els if "target" in e["data"]]
    # Cytoscape reads any element with "source" as an edge: node data must never carry one.
    assert all("source" not in d for d in nodes.values())
    assert all("source" in d for d in edges)
    boxes = [d for d in nodes.values() if d["kind"] == "pve-node"]
    assert len(boxes) == 2
    for box in boxes:
        kids = [d for d in nodes.values() if d.get("parent") == box["id"]]
        kinds = {d["kind"] for d in kids}
        assert {"pve-hub", "bridge"} <= kinds
        assert "guests" in box["label"]
        bridges = {d["id"] for d in kids if d["kind"] == "bridge"}
        for g in (d for d in kids if d["kind"] in ("pve-vm", "pve-lxc")):
            feeds = [e["source"] for e in edges if e["target"] == g["id"]]
            assert feeds, g["id"]
            # A guest hangs off a bridge of its own node, or off its node's hub.
            assert all(src in bridges or src == f"hub:{box['id']}" for src in feeds), g["id"]
    vm = nodes["pve:vm:homelab/101"]
    assert vm["bridge"] == "vmbr0"
    assert vm["nics"]
    assert vm["pve_from"] in ("proxmox", "pve-ssh")


def test_topology_page_summary(web: TestClient) -> None:
    body = web.get("/topology").text
    assert 'class="kpis"' in body
    assert "VMs &amp; LXCs" in body
    assert 'id="topo-stopped"' in body
    assert web.get("/topology?view=physical").text.count('class="kpis"') == 0


def test_proxmox_summary_numbers(rt: Runtime) -> None:
    with rt.sessions() as s:
        cards = views.machines(s)
    p = views.proxmox_summary(cards)
    assert p["nodes"] == 2
    assert p["vms"] + p["lxcs"] == p["guests"]
    assert p["running"] + p["stopped"] + p["unknown"] == p["guests"]
    assert p["clusters"] == ["homelab"]
    assert p["vcpu"] > 0


def test_static_urls_are_cache_busted(web: TestClient) -> None:
    body = web.get("/topology").text
    v = re.search(r'/static/app\.js\?v=([0-9a-f]{10})"', body)
    assert v is not None
    assert f"/static/app.css?v={v.group(1)}" in body
    assert f"/static/topology.js?v={v.group(1)}" in body
    assert web.get(f"/static/app.js?v={v.group(1)}").status_code == 200
