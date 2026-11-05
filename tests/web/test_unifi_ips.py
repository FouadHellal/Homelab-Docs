"""ADR-046: IP addresses from UniFi, with what the UniFi UI shows per client."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from homelab_atlas.collectors.unifi.parse import classic_details
from homelab_atlas.runtime import Runtime
from homelab_atlas.web import auth, views
from homelab_atlas.web.app import WebConfig, create_app
from tests.helpers import scanned_lab
from tests.web.test_v8 import PASSWORD, _login


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("uips"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


def test_classic_details_are_typed_and_never_keep_notes() -> None:
    body = {
        "data": [
            {"mac": "AA:BB:CC:00:00:01", "is_wired": False, "hostname": "esp", "oui": "Espressif",
             "essid": "iot", "signal": -55, "channel": 6, "radio": "ng", "satisfaction": 97,
             "uptime": 3600, "first_seen": 1735689600, "last_seen": 1793750000, "tx_bytes": 10,
             "note": "door code ATLASFAKE", "name": "x"},
            {"mac": "aa:bb:cc:00:00:02", "is_wired": True, "signal": -40, "essid": "ignored",
             "vlan": 9999, "satisfaction": 500, "use_fixedip": True, "fixed_ip": "10.0.0.9",
             "first_seen": "yesterday", "tx_bytes": True},
            {"mac": "not-a-mac"}, "junk",
        ]
    }  # fmt: skip
    d = classic_details(body)
    assert set(d) == {"aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"}
    w = d["aa:bb:cc:00:00:01"]
    assert (w["ssid"], w["signal_dbm"], w["radio"], w["vendor"]) == ("iot", -55, "ng", "Espressif")
    assert w["first_seen"].startswith("2025-01-01") and w["uptime_s"] == 3600
    wired = d["aa:bb:cc:00:00:02"]
    assert "ssid" not in wired and "signal_dbm" not in wired  # wireless-only fields on a cable
    assert "vlan" not in wired and "satisfaction" not in wired and "tx_bytes" not in wired
    assert wired["fixed_ip"] == "10.0.0.9" and "first_seen" not in wired
    assert "ATLASFAKE" not in json.dumps(d)


def test_unifi_table_has_clients_and_devices(rt: Runtime) -> None:
    with rt.sessions() as s:
        t = views.unifi_ip_table(s)
    assert t["have_unifi"] and t["total"] > 10
    devices = [r for r in t["rows"] if r["kind"] == "device"]
    assert {d["name"] for d in devices} >= {"ucg-ultra", "sw-core"}
    wifi = next(r for r in t["rows"] if r["kind"] == "client" and r["type"] == "wireless")
    assert wifi["vendor"] == "Espressif Inc." and "homelab-iot" in wifi["connection"]
    assert "dBm" in wifi["connection"] and "ch 6 (2.4 GHz)" in wifi["connection"]
    wired = next(r for r in t["rows"] if r["name"] == "docker01")
    assert wired["machine"] and "port" in wired["connection"] and "1000 Mbps" in wired["connection"]
    assert wired["fixed_ip"] and wired["rx"] is not None
    with rt.sessions() as s:
        assert [r["name"] for r in views.unifi_ip_table(s, "espressif")["rows"]]


def test_ips_page_defaults_to_unifi_and_keeps_the_old_view(rt: Runtime, tmp_path: Path) -> None:
    app = create_app(
        WebConfig(sessions=rt.sessions, annotations_dir=tmp_path, allowed_hosts=["testserver"])
    )
    with TestClient(app, base_url="https://testserver") as c:
        _login(c)
        page = c.get("/ips").text
        assert "From UniFi" in page and 'class="data ip-unifi"' in page and "Espressif" in page
        assert "ATLASFAKE" not in page
        assert 'class="data ip-groups"' in c.get("/ips?source=seen").text
        rows = c.get("/ips?q=docker01", headers={"HX-Request": "true"}).text
        assert "docker01" in rows and "<table" not in rows


def test_network_board_puts_clients_on_ports_and_aps(rt: Runtime, tmp_path: Path) -> None:
    with rt.sessions() as s:
        net = views.network_board(s)
    by_name = {d["name"]: d for d in net["devices"]}
    assert net["devices"][0]["role"] == "gateway"
    assert "sw-core" in by_name["ucg-ultra"]["downlinks"]
    rack = by_name["sw-rack"]
    port1 = next(p for p in rack["ports"] if p["idx"] == 1)
    assert [r["name"] for r in port1["clients"]] == ["docker01"]
    assert any(d["wireless"] for d in net["devices"] if d["role"] == "ap")
    app = create_app(
        WebConfig(sessions=rt.sessions, annotations_dir=tmp_path, allowed_hosts=["testserver"])
    )
    with TestClient(app, base_url="https://testserver") as c:
        _login(c)
        html = c.get("/topology?view=net").text
        assert 'class="nb-ports"' in html and "sw-rack" in html and "cytoscape" not in html
