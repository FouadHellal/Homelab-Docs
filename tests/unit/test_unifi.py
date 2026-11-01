import json
from pathlib import Path
from typing import Any

import pytest

from homelab_atlas.collectors.base import CollectContext
from homelab_atlas.collectors.unifi import endpoints as ep
from homelab_atlas.collectors.unifi import parse
from homelab_atlas.collectors.unifi.collector import UnifiCollector, _Run
from homelab_atlas.collectors.unifi.events import unifi_events
from homelab_atlas.engine.diff import Change
from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.models.unifi import UnifiDeviceFacts, UnifiSiteFacts
from homelab_atlas.runtime import replay_http
from homelab_atlas.security.allowlist import DENIED_SEGMENTS
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, replay_transport
from homelab_atlas.security.ssh import SshRunner
from tests.helpers import MemoryAudit

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"
BASE = "https://ucg.lab.example/proxy/network/integration"


def test_allowlist_is_get_only_and_skips_secret_endpoints() -> None:
    for e in ep.COLLECT:
        assert e.method == "GET"
        assert not set(e.path_template.lower().split("/")) & DENIED_SEGMENTS
    paths = {e.path_template for e in ep.COLLECT}
    assert not any("vouchers" in p or "statistics" in p for p in paths)
    assert "/v1/sites/{site_id}/wifi/broadcasts/{wifi_id}" not in paths  # details hold the PSK


def test_ssid_never_reads_passphrase() -> None:
    s = parse.ssid(
        {
            "id": "x",
            "name": "home",
            "enabled": True,
            "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "psk-ATLASFAKE"},
        }
    )
    assert s is not None
    assert s.security == "WPA2_PERSONAL"
    assert "ATLASFAKE" not in s.model_dump_json()


def test_version_tuple() -> None:
    assert parse.version_tuple("10.6.106") == (10, 6, 106)
    assert parse.version_tuple("9.2.87") < ep.MIN_VERSION
    assert parse.version_tuple(None) == ()


async def test_pagination_follows_total_count() -> None:
    site = "8f2c1d9e-0000-4000-8000-a71a5000000a"
    items = [
        {
            "id": f"00000000-0000-4000-8000-{i:012d}",
            "macAddress": f"aa:00:00:00:{i // 256:02x}:{i % 256:02x}",
        }
        for i in range(250)
    ]
    path = f"/proxy/network/integration/v1/sites/{site}/devices"

    def page(off: int, chunk: list[Any]) -> tuple[int, bytes]:
        body = {"offset": off, "limit": 200, "count": len(chunk), "totalCount": 250, "data": chunk}
        return 200, json.dumps(body).encode()

    rec = {
        f"{path}?offset=0&limit=200": page(0, items[:200]),
        f"{path}?offset=200&limit=200": page(200, items[200:]),
    }
    client = ReadOnlyHttpClient(
        target="ucg",
        base_url=BASE,
        endpoints=ep.COLLECT,
        audit=MemoryAudit(),
        tls=None,
        transport=replay_transport(rec),
    )
    async with client:
        got = await _Run(client, None, "ucg").pages(ep.DEVICES, {"site_id": site})  # type: ignore[arg-type]
    assert len(got) == 250


async def collect(state: str = "A", mutate: Any = None) -> Any:
    inv, ssh = load_lab(state, LAB)
    recs = load_api_recordings(state, LAB)
    if mutate:
        mutate(recs["ucg"])
    audit = MemoryAudit()
    ctx = CollectContext(
        inventory=inv, ssh=SshRunner(transport=ssh, audit=audit), http=replay_http(recs)(audit)
    )
    return await UnifiCollector().collect("ucg", ctx), audit


async def test_lab_collection_topology_and_secrets() -> None:
    result, audit = await collect()
    assert result.status == "ok"
    site = next(f.model for f in result.facets if isinstance(f.model, UnifiSiteFacts))
    assert {n.name: n.vlan_id for n in site.networks} == {
        "Default": 1,
        "Management": 10,
        "Servers": 20,
        "IoT": 30,
    }
    assert {n.name: n.subnet for n in site.networks}["IoT"] == "10.0.30.0/24"
    assert "ATLASFAKE" not in site.model_dump_json()
    devices = {f.model.name: f for f in result.facets if isinstance(f.model, UnifiDeviceFacts)}
    assert devices["ap-garden"].parent_key == f"unifi:dev:{devices['ap-living'].model.mac}"
    assert devices["ucg-ultra"].parent_key.startswith("unifi:site:")
    assert len(devices["sw-core"].model.ports) == 26
    pi = next(c for c in site.clients if c.name == "pi-garage")
    assert pi.uplink_mac == devices["ap-garden"].model.mac
    assert all(e.op.startswith("GET ") for e in audit.events)


async def test_old_network_version_is_flagged() -> None:
    def old(r: dict[str, Any]) -> None:
        r["/proxy/network/integration/v1/info"] = (200, b'{"applicationVersion": "9.2.87"}')

    result, _ = await collect(mutate=old)
    assert result.status == "partial"
    assert any("needs >= 9.3" in e for e in result.errors)


async def test_devices_list_failure_is_fatal() -> None:
    def drop(r: dict[str, Any]) -> None:
        for k in [k for k in r if "/devices?" in k]:
            r[k] = (500, b"{}")

    result, _ = await collect(mutate=drop)
    assert result.status == "failed"
    assert result.facets == []


@pytest.mark.parametrize(
    ("change", "expected", "severity"),
    [
        (Change(("state",), "changed", "ONLINE", "OFFLINE"), "device.offline", "warning"),
        (Change(("state",), "changed", "OFFLINE", "ONLINE"), "device.online", "info"),
        (Change(("firmware",), "changed", "8.0.19", "8.0.26"), "fw.upgraded", "notice"),
        (Change(("uplink_mac",), "changed", "a", "b"), "topology.uplink_changed", "notice"),
        (
            Change(("ssids", "guest"), "added", None, {"name": "guest", "security": "OPEN"}),
            "wifi.ssid_added",
            "warning",
        ),
        (
            Change(("ssids", "home", "security"), "changed", "WPA3_PERSONAL", "OPEN"),
            "wifi.security_changed",
            "warning",
        ),
        (
            Change(("policies", "p", "enabled"), "changed", True, False),
            "firewall.policy_disabled",
            "warning",
        ),
        (
            Change(("networks", "Lab"), "added", None, {"name": "Lab", "vlan_id": 40}),
            "vlan.added",
            "notice",
        ),
        (Change(("app_version",), "changed", "10.5", "10.6"), "unifi.upgraded", "notice"),
    ],
)
def test_event_rules(change: Change, expected: str, severity: str) -> None:
    (event,) = unifi_events("k", "x", [change])
    assert (event.type, event.severity) == (expected, severity)


def test_classic_ports_keep_only_wired_clients_with_a_sane_port() -> None:
    body = {
        "meta": {"rc": "ok"},
        "data": [
            {"mac": "AA:BB:CC:00:00:01", "is_wired": True, "sw_port": 5},
            {"mac": "aa:bb:cc:00:00:02", "is_wired": False, "sw_port": 7},  # wireless
            {"mac": "aa:bb:cc:00:00:03", "is_wired": True, "sw_port": True},  # bool, not a port
            {"mac": "aa:bb:cc:00:00:04", "is_wired": True, "sw_port": 0},
            {"mac": "aa:bb:cc:00:00:05", "is_wired": True, "sw_port": "3"},
            {"mac": "not-a-mac", "is_wired": True, "sw_port": 2},
            "junk",
        ],
    }
    assert parse.classic_ports(body) == {"aa:bb:cc:00:00:01": 5}
    assert parse.classic_ports({"data": "x"}) == {}
    assert parse.classic_ports(["x"]) == {}


def test_classic_url_is_the_sibling_of_the_integration_base() -> None:
    assert ep.classic_url(BASE + "/") == "https://ucg.lab.example/proxy/network/api"
    assert ep.classic_url("https://ucg.lab.example/custom") is None
    for e in ep.CLASSIC:
        assert e.method == "GET"
        assert not set(e.path_template.lower().split("/")) & DENIED_SEGMENTS


async def test_lab_wired_clients_carry_their_switch_port() -> None:
    result, audit = await collect()
    site = next(f.model for f in result.facets if isinstance(f.model, UnifiSiteFacts))
    assert site.switch_ports == "classic"
    by_name = {c.name: c for c in site.clients}
    assert by_name["docker01"].uplink_port == 1
    assert by_name["pi-garage"].uplink_port is None  # wireless
    assert any(e.op == "GET /s/{site_name}/stat/sta" for e in audit.events)


async def test_refused_classic_api_degrades_without_failing_the_run() -> None:
    def refuse(r: dict[str, Any]) -> None:
        r["/proxy/network/api/s/default/stat/sta"] = (401, b"{}")

    result, _ = await collect(mutate=refuse)
    assert result.status == "ok"
    site = next(f.model for f in result.facets if isinstance(f.model, UnifiSiteFacts))
    assert site.switch_ports == "unavailable"
    assert all(c.uplink_port is None for c in site.clients)


@pytest.mark.parametrize("site_name", ["../integration", "default/../../x", "a b", "", "x" * 65])
async def test_classic_site_name_is_validated_before_any_request(site_name: str) -> None:
    audit = MemoryAudit()
    client = ReadOnlyHttpClient(
        target="ucg",
        base_url="https://ucg.lab.example/proxy/network/api",
        endpoints=ep.CLASSIC,
        audit=audit,
        tls=None,
        transport=replay_transport({}),
    )
    async with client:
        with pytest.raises(SecurityRefusal):
            await client.get(ep.CLASSIC_STA, {"site_name": site_name})
    assert audit.outcomes == ["refused"]
