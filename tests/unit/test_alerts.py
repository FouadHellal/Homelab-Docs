"""ADR-047: alert rules — built-in and own, thresholds, machine filters, ticket/message switches."""

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from homelab_atlas.engine import alerts, incidents
from homelab_atlas.engine import taskora as tk
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.vault import Vault
from homelab_atlas.store.facets import FacetView
from homelab_atlas.store.tables import Incident, TaskoraLink
from homelab_atlas.web import auth
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit, scanned_lab
from tests.web.test_v8 import PASSWORD, _login

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
NOW = datetime.now(UTC)


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("alerts"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


def found(rt: Runtime, rules: list[alerts.Rule]) -> dict[str, alerts.Condition]:
    inv, _ = load_lab("B", LAB)
    with rt.sessions() as s:
        return {c.key: c for c in alerts.conditions(s, inv, {}, NOW, rules)}


def test_builtin_rules_keep_the_historical_incident_keys(rt: Runtime) -> None:
    keys = set(found(rt, alerts.builtin_rules()))
    assert {
        "media.storage:media",
        "host.unreachable:ghost01",
        "nas.pool:unas:1",
        "container.down:docker02/uptime-kuma",
        "guest.stopped:pve:vm:homelab/105",
    } <= keys
    # Types that are off by default stay quiet until the owner enables them.
    assert not [k for k in keys if k.startswith(("network.unknown:", "container.latest:"))]


def test_own_rule_with_threshold_filter_and_severity(rt: Runtime) -> None:
    mine = alerts.Rule(id="disk-docker", name="Docker disks", type="disk.full", severity="warning",
                       params={"pct": 10}, match="docker0*")  # fmt: skip
    got = found(rt, [mine])
    assert got and all(k.startswith("disk-docker:docker0") for k in got)
    assert {c.severity for c in got.values()} == {"warning"} and {c.kind for c in got.values()} == {
        "disk.full"
    }
    other = alerts.Rule(
        id="disk-but", name="x", type="disk.full", params={"pct": 10}, exclude="docker0*"
    )
    assert not [k for k in found(rt, [other]) if ":docker0" in k]
    off = alerts.Rule(id="disk-off", name="x", type="disk.full", params={"pct": 1}, enabled=False)
    assert found(rt, [off]) == {}


def test_enabling_off_by_default_types(rt: Runtime) -> None:
    rules = [
        alerts.Rule(id="unknown", name="u", type="network.unknown"),
        alerts.Rule(id="unknown-iot", name="u", type="network.unknown", params={"vlans": ["30"]}),
        alerts.Rule(id="latest", name="l", type="container.latest"),
        alerts.Rule(id="priv", name="p", type="container.privileged"),
    ]
    got = found(rt, rules)
    assert any(k.startswith("unknown:") for k in got)
    assert (
        0
        < sum(k.startswith("unknown-iot:") for k in got)
        < sum(k.startswith("unknown:") for k in got)
    )
    assert any(k.startswith("priv:") for k in got)  # the demo lab mounts the Docker socket


def _scope(views: list[FacetView]) -> alerts.Scope:
    sc = alerts.Scope(cast(Any, None), cast(Any, None), {}, NOW)
    sc._views, sc._runs = views, {}
    return sc


def test_security_and_network_detectors() -> None:
    users = [
        {"name": "root", "uid": 0},
        {"name": "toor", "uid": 0, "shell": "/bin/sh", "home": "/"},
    ]
    sockets = [
        {"proto": "tcp", "address": "0.0.0.0", "port": 22},
        {"proto": "tcp", "address": "::", "port": 6379},
        {"proto": "tcp", "address": "127.0.0.1", "port": 5432},
    ]
    services = [
        {"unit": "nginx.service", "active": "failed"},
        {"unit": "fwupd-refresh.service", "active": "failed"},
    ]
    data = {"users": users, "sockets": sockets, "services": services}
    lx = FacetView("host:a", "linux-ssh", "web01", 1, data, "linux-ssh")
    dev = {"mac": "aa:bb:cc:00:00:09", "name": "ap-garden", "state": "OFFLINE", "model": "U6-Mesh"}
    uni = FacetView("unifi:dev:x", "unifi", "ucg", 1, dev, "unifi")
    sc = _scope([lx, uni])
    root = alerts.BY_TYPE["security.root"].detect(sc, {})
    assert [f.title for f in root] == ["web01: account toor has uid 0 (root)"]
    ports = alerts.BY_TYPE["security.port"].detect(sc, {"allowed": ["22"]})
    assert [f.subject for f in ports] == ["web01:tcp/6379"]  # localhost-only 5432 is fine
    svc = alerts.BY_TYPE["service.failed"].detect(sc, {"ignore": ["fwupd-*"]})
    assert [f.subject for f in svc] == ["web01:nginx.service"]
    off = alerts.BY_TYPE["unifi.offline"].detect(sc, {})
    assert off[0].title == "UniFi ap-garden is offline"


def test_rules_roundtrip_store_only_changes(tmp_path: Path) -> None:
    path = tmp_path / "alerts.yaml"
    rules = alerts.load_rules(path)
    assert {r.id for r in rules} == {t.id for t in alerts.TYPES}
    disk = next(r for r in rules if r.id == "disk.full")
    rules = [
        r.model_copy(update={"params": {"pct": 80}}) if r.id == "disk.full" else r for r in rules
    ]
    rules.append(alerts.Rule(id="pve-ports", name="PVE ports", type="security.port", match="PVE*"))
    alerts.save_rules(path, rules)
    raw = yaml.safe_load(path.read_text("utf-8"))["rules"]
    assert (
        raw
        == [
            {"id": "disk.full", "params": {"pct": 80}},
            {**dict(raw[1]), "id": "pve-ports"},
        ]
        and raw[1]["type"] == "security.port"
        and len(raw) == 2
    )
    again = {r.id: r for r in alerts.load_rules(path)}
    assert again["disk.full"].clean_params()["pct"] == 80 and again["disk.full"].builtin
    assert again["pve-ports"].match == "PVE*" and not again["pve-ports"].builtin
    assert disk.clean_params() == {"pct": 90, "warning_pct": 95}
    path.write_text(
        "rules:\n  - {id: bad id, type: disk.full}\n  - {id: x1, type: nope}\n  - junk\n", "utf-8"
    )
    assert {r.id for r in alerts.load_rules(path)} == {t.id for t in alerts.TYPES}
    clamped = alerts.Rule(
        id="c1", name="c", type="disk.full", params={"pct": 5000, "warning_pct": -3}
    )
    assert clamped.clean_params() == {"pct": 100, "warning_pct": 1}
    with pytest.raises(ValueError):
        alerts.Rule(id="c2", name="c", type="disk.full", params={"pct": "x"})  # type: ignore[dict-item]


def test_ticket_and_message_switches(rt: Runtime, tmp_path: Path) -> None:
    path = tmp_path / "alerts.yaml"
    rules = [r.model_copy(update={"ticket": False, "notify": False}) if r.id == "nas.pool" else r
             for r in alerts.load_rules(path)]  # fmt: skip
    alerts.save_rules(path, rules)
    alerts.configure(path)
    try:
        inv, _ = load_lab("B", LAB)
        later = NOW + timedelta(minutes=10)
        with rt.sessions() as s:
            incidents.evaluate(s, inv, {}, NOW)
            s.commit()
            due = {i.key for i, _ in incidents.due_notifications(s, later)}
            assert "nas.pool:unas:1" not in due and "media.storage:media" in due
            settings = tk.TaskoraSettings(url="https://taskora.example.test", incidents=True)
            s.query(TaskoraLink).delete()
            tk.stage(s, inv, settings, now=later)
            s.commit()
            linked = {
                s.get_one(Incident, lk.incident_id).key for lk in s.scalars(select(TaskoraLink))
            }
            assert "nas.pool:unas:1" not in linked and "media.storage:media" in linked
            s.query(TaskoraLink).delete()
            s.commit()
    finally:
        alerts.configure(None)


def test_alerts_page_preview_add_edit_delete(rt: Runtime, tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.json", b"k" * 32)
    inv, _ = load_lab("B", LAB)
    svc = TargetsService(config_dir=tmp_path / "cfg", data_dir=tmp_path, vault=vault,
                         audit=MemoryAudit(), readonly_inventory=None)  # fmt: skip
    svc.inventory = lambda: (inv, set())  # type: ignore[method-assign]
    cfg = WebConfig(sessions=rt.sessions, annotations_dir=tmp_path, allowed_hosts=["testserver"],
                    targets=svc, data_dir=tmp_path)  # fmt: skip
    app = create_app(cfg)
    try:
        with TestClient(app, base_url="https://testserver") as c:
            h = {"X-CSRF-Token": _login(c)}
            page = c.get("/alerts").text
            assert "Alert rules" in page and "Media storage missing" in page and "now" in page
            assert "Jellyfin runs, but its media storage is not mounted" in page  # live preview
            r = c.post("/alerts/save", headers=h, follow_redirects=False, data={
                "type": "disk.full", "name": "Disks on docker hosts", "severity": "warning",
                "param_pct": "10", "param_warning_pct": "99", "match": "docker0*",
                "enabled": "1", "ticket": "1"})  # fmt: skip
            assert r.status_code == 303 and "Saved" in r.headers["location"]
            stored = yaml.safe_load((tmp_path / "alerts.yaml").read_text("utf-8"))["rules"]
            mine = next(x for x in stored if x["id"] == "disks-on-docker-hosts")
            assert mine["params"] == {"pct": 10, "warning_pct": 99} and mine["notify"] is False
            assert "docker0*" in c.get("/alerts").text
            bad = c.post("/alerts/save", headers=h, follow_redirects=False,
                         data={"type": "disk.full", "param_pct": "ten"})  # fmt: skip
            assert "a+number" in bad.headers["location"]
            # Edit a built-in, then reset it.
            edit = {
                "id": "host.unreachable",
                "severity": "notice",
                "param_failures": "4",
                "enabled": "1",
            }
            c.post("/alerts/save", headers=h, data=edit)
            assert any(
                x["id"] == "host.unreachable"
                for x in yaml.safe_load((tmp_path / "alerts.yaml").read_text("utf-8"))["rules"]
            )
            c.post("/alerts/host.unreachable/delete", headers=h)
            c.post("/alerts/disks-on-docker-hosts/delete", headers=h)
            assert yaml.safe_load((tmp_path / "alerts.yaml").read_text("utf-8"))["rules"] == []
            assert (
                c.post(
                    "/alerts/save", data={"type": "disk.full"}, follow_redirects=False
                ).status_code
                == 403
            )
    finally:
        alerts.configure(None)
