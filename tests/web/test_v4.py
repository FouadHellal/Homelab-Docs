"""v4: change filters + CSV, exports and diagnostics from the UI, unrecognised ports and owner
app rules, Targets bulk scan, machine summary, public docs, clean value rendering (ADR-034/035)."""

import csv
import io
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from homelab_atlas.engine import apps
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.scheduler import Scheduler
from homelab_atlas.web import auth, queries, views
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit, scanned_lab

PASSWORD = "v4-pages-ATLASFAKE-pw"  # test value for the app under test
LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
KEY = b"k" * 32


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("v4"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


class Recorder(Scheduler):
    def __init__(self) -> None:
        super().__init__(lambda: None, intervals={})  # type: ignore[arg-type,return-value]
        self.calls: list[list[str] | None] = []

    def trigger(self, hosts: list[str] | None = None) -> str:
        self.calls.append(hosts)
        return "queued"


def _app(rt: Runtime, tmp_path: Path, *, sched: Scheduler | None = None) -> TestClient:
    inv, _ = load_lab("B", LAB)
    svc = TargetsService(config_dir=tmp_path / "cfg", data_dir=tmp_path / "data", vault=None,
                         audit=MemoryAudit(), readonly_inventory=inv)  # fmt: skip
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path / "ann",
            allowed_hosts=["testserver"],
            lab=True,
            targets=svc,
            scheduler=sched,
            data_dir=tmp_path / "data",
            export_key=KEY,
        )
    )
    return TestClient(app, base_url="https://testserver")


def _login(c: TestClient) -> str:
    token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
    assert token is not None
    r = c.post("/login", data={"username": "admin", "password": PASSWORD,
                               "csrf_token": token.group(1)}, follow_redirects=False)  # fmt: skip
    assert r.status_code == 303
    m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/").text)
    assert m is not None
    return m.group(1)


@pytest.fixture
def web(rt: Runtime, tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    with _app(rt, tmp_path) as c:
        yield c, _login(c)
    apps.configure_custom(None)


# ------------------------------------------------------------------ rendering, docs, summary


def test_no_python_literals_on_pages(web: tuple[TestClient, str]) -> None:
    c, _ = web
    for path in ("/entity?key=pve:vm:homelab/101", "/entity?key=pve:lxc:homelab/201", "/"):
        body = c.get(path).text
        assert ">None<" not in body, path
        assert ">True<" not in body, path
        assert ">False<" not in body, path
    vm = c.get("/entity?key=pve:vm:homelab/101").text
    assert "<dt>on boot</dt><dd>yes</dd>" in vm


def test_docs_are_public(rt: Runtime, tmp_path: Path) -> None:
    with _app(rt, tmp_path) as c:
        r = c.get("/docs", follow_redirects=False)
        assert r.status_code == 200
        assert "PVEAuditor" in r.text
        assert "Log out" not in r.text  # no user menu without a session
        assert c.get("/", follow_redirects=False).status_code == 303  # the rest stays private


def test_machine_summary_and_actions(rt: Runtime, tmp_path: Path) -> None:
    with _app(rt, tmp_path, sched=Recorder()) as c:
        _login(c)
        body = c.get("/entity?key=pve:vm:homelab/101").text
    assert 'class="facts card"' in body
    assert 'href="/topology?focus=pve%3Avm%3Ahomelab/101"' in body
    assert 'data-copy="ssh 10.0.20.11"' in body
    assert 'action="/targets/scan"' in body
    assert "Open Immich" in body


def test_dashboard_nas_card_is_not_waiting(web: tuple[TestClient, str]) -> None:
    c, _ = web
    body = c.get("/").text
    card = body[body.index(">unas<") :][:600]
    assert "waiting for its first scan" not in card


# ------------------------------------------------------------------ changes


def test_related_keys_include_twin_and_containers(rt: Runtime) -> None:
    with rt.sessions() as s:
        keys = queries.related_keys(s, "pve:vm:homelab/101")
    assert "pve:vm:homelab/101" in keys
    assert any(k.startswith("host:") for k in keys)  # the Linux host inside
    assert any(k.startswith("ctr:") for k in keys)  # its containers


def test_changes_filters_summary_and_csv(web: tuple[TestClient, str], rt: Runtime) -> None:
    c, _ = web
    with rt.sessions() as s:
        keys = queries.related_keys(s, "pve:vm:homelab/101")
        mine = queries.changes(s, keys=keys, limit=500)
        everything = queries.changes(s, limit=500)
        summary = queries.changes_summary(s, None, keys)
        recent = queries.changes(s, since="24h", limit=500)
    assert mine
    assert len(mine) < len(everything)
    assert all(r["event"].entity_key in keys for r in mine)
    assert summary["total"] == len(mine)
    assert len(recent) == len(everything)  # the lab was scanned just now
    page = c.get("/changes?machine=pve:vm:homelab/101&since=7d")
    assert page.status_code == 200
    assert "Export CSV" in page.text
    assert "machine=pve%3Avm%3Ahomelab%2F101" in page.text
    part = c.get("/changes?since=30d", headers={"HX-Request": "true"})
    assert "<html" not in part.text
    r = c.get("/changes.csv?machine=pve:vm:homelab/101")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert list(rows[0]) == ["time", "severity", "type", "entity", "summary", "path", "scan"]
    assert len(rows) == len(mine)


# ------------------------------------------------------------------ targets


def test_targets_tally_and_bulk_scan(rt: Runtime, tmp_path: Path) -> None:
    sched = Recorder()
    with _app(rt, tmp_path, sched=sched) as c:
        csrf = _login(c)
        body = c.get("/targets").text
        assert 'class="card tally"' in body
        assert "Scan failed &amp; new" in body
        r = c.post("/targets/scan-many", data={"csrf_token": csrf, "which": "failed"},
                   follow_redirects=False)  # fmt: skip
        assert r.status_code == 303
        with rt.sessions() as s:
            latest = queries.latest_runs(s)
        failing = sorted(t for t in sched.calls[-1] or [])
        assert failing
        assert all(queries.target_health(latest.get(t)) in ("failed", "never") for t in failing)
        assert "web01" not in failing
        c.post("/targets/scan-many", data={"csrf_token": csrf, "which": "all"})
        assert "web01" in (sched.calls[-1] or [])
        assert c.post("/targets/scan-many", data={"which": "all"}).status_code == 403


# ------------------------------------------------------------------ exports, diagnostics


@pytest.mark.parametrize(
    ("fmt", "mime"),
    [("md", "text/markdown"), ("json", "application/json"), ("csv", "application/zip"),
     ("mermaid", "text/plain")],
)  # fmt: skip
def test_exports(web: tuple[TestClient, str], fmt: str, mime: str) -> None:
    c, _ = web
    r = c.get(f"/export/{fmt}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith(mime)
    assert r.headers["content-disposition"].startswith('attachment; filename="atlas-')
    if fmt == "csv":
        names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
        assert "hosts.csv" in names
    if fmt == "md":
        assert "docker01" in r.text


def test_sanitized_export_hides_names_and_ips(web: tuple[TestClient, str]) -> None:
    c, _ = web
    plain = c.get("/export/json").text
    shared = c.get("/export/json?sanitize=true").text
    assert "10.0.20.11" in plain
    assert "10.0.20.11" not in shared
    assert '"docker01"' not in shared
    assert "ATLASFAKE" not in plain  # fake secrets were redacted at scan time


def test_export_refusals(web: tuple[TestClient, str], rt: Runtime, tmp_path: Path) -> None:
    c, _ = web
    assert c.get("/export/exe").status_code == 404
    assert c.get("/exports").status_code == 200
    with _app(rt, tmp_path / "x") as anon:
        assert anon.get("/export/json", follow_redirects=False).status_code in (303, 401)


def test_diagnostics(web: tuple[TestClient, str]) -> None:
    c, _ = web
    page = c.get("/diagnostics").text
    assert "Versions" in page
    assert "ghost01" in page  # a failing target, with its reason
    r = c.get("/diagnostics/report")
    assert r.status_code == 200
    assert r.headers["content-disposition"].startswith('attachment; filename="atlas-diagnostics-')
    assert "## Targets" in r.text
    assert "ghost01: failed" in r.text
    assert "## Audit log" in r.text
    assert "ATLASFAKE" not in r.text


# ------------------------------------------------------------------ unrecognised ports, owner rules


def test_unrecognised_ports_found_and_grouped(rt: Runtime) -> None:
    apps.configure_custom(None)
    with rt.sessions() as s:
        groups = views.unrecognised_ports(s)
    by_value = {g["value"]: g for g in groups}
    label = by_value["labelmaker"]
    assert label["kind"] == "proc"
    assert label["ports"] == [8077]
    assert [n for n, _ in label["machines"]] == ["backup01"]
    py = by_value["5000"]
    assert py["kind"] == "port"  # python3 is generic: named by port, on that machine only
    assert [n for n, _ in py["machines"]] == ["pi-garage"]
    # Well-known ones are not listed.
    assert not any(p in (22, 53, 443, 5432, 8006) for g in groups for p in g["ports"])


def test_name_a_port_then_forget_it(web: tuple[TestClient, str], rt: Runtime) -> None:
    c, csrf = web
    form = {"csrf_token": csrf, "name": "Label Maker", "category": "dev", "kind": "proc",
            "value": "labelmaker", "ports": "8077", "machines": "backup01"}  # fmt: skip
    r = c.post("/apps/name", data=form, follow_redirects=False)
    assert r.status_code == 303
    assert "saved" in r.headers["location"]
    rules = apps.load_rules()
    assert [x.name for x in rules] == ["Label Maker"]
    with rt.sessions() as s:
        card = next(m for m in views.machines(s) if m["short"] == "backup01")
        assert "Label Maker" in {a["name"] for a in card["apps"]}
        assert "labelmaker" not in {g["value"] for g in views.unrecognised_ports(s)}
    # A generic process: the port is the evidence, on that machine only.
    port_form = {**form, "name": "Garage API", "kind": "port", "value": "5000", "ports": "5000",
                 "machines": "pi-garage", "category": "custom"}  # fmt: skip
    c.post("/apps/name", data=port_form)
    with rt.sessions() as s:
        cards = {m["short"]: m for m in views.machines(s)}
    assert "Garage API" in {a["name"] for a in cards["pi-garage"]["apps"]}
    assert "Garage API" not in {a["name"] for a in cards["backup01"]["apps"]}
    assert "Label Maker" in c.get("/running").text
    c.post("/apps/forget", data={"csrf_token": csrf, "name": "Label Maker"})
    c.post("/apps/forget", data={"csrf_token": csrf, "name": "Garage API"})
    assert apps.load_rules() == []


@pytest.mark.parametrize(
    "bad",
    [{"category": "nope"}, {"value": "x; rm -rf /"}, {"name": ""}, {"ports": "70000"},
     {"name": "<script>"}],
)  # fmt: skip
def test_bad_rules_are_refused(web: tuple[TestClient, str], bad: dict[str, Any]) -> None:
    c, csrf = web
    form = {"csrf_token": csrf, "name": "X", "category": "dev", "kind": "proc",
            "value": "labelmaker", "ports": "8077", "machines": "backup01", **bad}  # fmt: skip
    r = c.post("/apps/name", data=form, follow_redirects=False)
    assert r.status_code in (303, 422)
    assert apps.load_rules() == []
    assert c.post("/apps/name", data={**form, "csrf_token": "x"}).status_code == 403


def test_rule_file_is_strict_and_survives_garbage(tmp_path: Path) -> None:
    f = tmp_path / "custom-apps.yaml"
    f.write_text(
        "apps:\n  - name: Good\n    procs: [goodd]\n  - name: Bad\n    evil: 1\n  - 42\n",
        encoding="utf-8",
    )
    apps.configure_custom(f)
    try:
        assert [r.name for r in apps.load_rules()] == ["Good"]
        found = apps.detect(processes=[{"comm": "goodd"}])
        assert [a["name"] for a in found] == ["Good"]
        assert found[0]["category_label"] == "Your apps"
        f.write_text("::: not yaml", encoding="utf-8")
        assert apps.custom_apps() == ()  # unreadable: ignored, built-ins still work
        assert apps.detect(services=[{"unit": "ssh.service", "active": "active"}])
    finally:
        apps.configure_custom(None)


def test_host_limited_strong_port_rule() -> None:
    rule = apps.CustomRule(name="Garage API", ports=[5000], strong_ports=True, hosts=["pi-garage"])
    app = rule.as_app()
    assert app.custom
    assert app.hosts == ("pi-garage",)
    assert rule.model_dump()["hosts"] == ["pi-garage"]
