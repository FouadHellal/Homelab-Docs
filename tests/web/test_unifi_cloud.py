"""UniFi with a unifi.ui.com (Site Manager) key: console discovery, connector path, pinning."""

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from homelab_atlas.collectors.unifi.sitemanager import consoles
from homelab_atlas.inventory.hosts import TlsSettings, UnifiSource
from homelab_atlas.inventory.managed import ManagedInventory
from homelab_atlas.runtime import Runtime, live_inputs, live_secrets
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, TlsPolicy, replay_transport
from homelab_atlas.web import auth
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit

PASSWORD = "test-only-ATLASFAKE-pw"
KEY = "cloud-key-ATLASFAKE-0001"
CID = "70A7419783ED0000000006797F060000000006C719490000000062ABD4EA:1261206302"
HOSTS = {
    "data": [
        {
            "id": CID,
            "type": "ucore",
            "ipAddress": "203.0.113.7",
            "reportedState": {"name": "UCG-Home"},
            "userData": {"controllers": ["network", "protect"]},
        },
        {"id": "AA:1", "type": "protect-only", "userData": {"controllers": ["protect"]}},
    ],
    "nextToken": None,
}
INFO = {"applicationVersion": "10.6.106"}


def _transport(first_base_ok: bool) -> Any:
    table = {"/v1/hosts?pageSize=100": (200, json.dumps(HOSTS).encode())}
    ok = (200, json.dumps(INFO).encode())
    if first_base_ok:
        table[f"/v1/connector/consoles/{CID}/network/integration/v1/info"] = ok
    else:
        table[f"/v1/connector/consoles/{CID}/proxy/network/integration/v1/info"] = ok
    return replay_transport(table)


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    cfg_dir, data = tmp_path / "config", tmp_path / "data"
    cfg_dir.mkdir()
    monkeypatch.setenv("ATLAS_CONFIG_DIR", str(cfg_dir))
    monkeypatch.chdir(tmp_path)
    rt = Runtime.open(data, mode="live")
    with rt.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    vault = live_secrets(data).vault
    assert vault is not None
    return {"rt": rt, "data": data, "cfg": cfg_dir, "vault": vault}


def _client(
    env: dict[str, Any], tmp_path: Path, first_base_ok: bool
) -> Iterator[tuple[TestClient, str, MemoryAudit]]:
    audit = MemoryAudit()
    svc = TargetsService(
        config_dir=env["cfg"],
        data_dir=env["data"],
        vault=env["vault"],
        audit=audit,
        transport=_transport(first_base_ok),
    )
    app = create_app(
        WebConfig(
            sessions=env["rt"].sessions,
            annotations_dir=tmp_path / "a",
            allowed_hosts=["testserver"],
            targets=svc,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
        assert tok is not None
        c.post(
            "/login", data={"username": "admin", "password": PASSWORD, "csrf_token": tok.group(1)}
        )
        m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/").text)
        assert m is not None
        yield c, m.group(1), audit


@pytest.mark.parametrize("first_base_ok", [True, False])
def test_cloud_key_end_to_end(env: dict[str, Any], tmp_path: Path, first_base_ok: bool) -> None:
    for c, csrf, audit in _client(env, tmp_path, first_base_ok):
        found = c.post(
            "/targets/unifi/consoles", data={"csrf_token": csrf, "credential": KEY, "name": "ucg"}
        )
        assert "UCG-Home" in found.text
        assert "protect-only" not in found.text  # consoles without the Network app are hidden
        assert KEY not in found.text
        r = c.post(
            "/targets/source",
            data={
                "csrf_token": csrf,
                "kind": "unifi",
                "name": "ucg",
                "connection": "cloud",
                "console_id": CID,
                "credential": KEY,
            },
            follow_redirects=False,
        )
        assert r.status_code == 303, r.text
        src = ManagedInventory(env["data"]).load().sources.unifi[0]
        expected = "network/integration" if first_base_ok else "proxy/network/integration"
        assert src.url == f"https://api.ui.com/v1/connector/consoles/{CID}/{expected}"
        assert (src.connection, src.console_id, src.tls.public_pki) == ("cloud", CID, True)
        assert env["vault"].resolve("ui-unifi-ucg").get_secret_value() == KEY
        assert KEY not in (env["data"] / "inventory.yaml").read_text(encoding="utf-8")
        assert "cloud (api.ui.com)" in c.get("/targets").text
        ops = [e.op for e in audit.events]
        assert "GET /v1/hosts" in ops
        assert "GET /v1/info" in ops
        # A live scan builds a public-PKI client for api.ui.com, paced for the 100/min limit.
        inputs = live_inputs(env["data"])
        from homelab_atlas.collectors.unifi import endpoints as ep  # noqa: PLC0415
        from homelab_atlas.collectors.unifi.collector import UnifiCollector  # noqa: PLC0415

        client = inputs.http(MemoryAudit())(
            UnifiCollector.source(inputs.inventory, "ucg"), ep.COLLECT
        )
        assert isinstance(client, ReadOnlyHttpClient)
        assert client._limits.min_interval_s > 0


def test_cloud_needs_a_console(env: dict[str, Any], tmp_path: Path) -> None:
    for c, csrf, _ in _client(env, tmp_path, True):
        r = c.post(
            "/targets/source",
            data={
                "csrf_token": csrf,
                "kind": "unifi",
                "name": "ucg",
                "connection": "cloud",
                "credential": KEY,
            },
        )
        assert r.status_code == 422
        assert "pick a console" in r.text or "Find my consoles" in r.text


def test_public_pki_is_only_for_api_ui_com() -> None:
    with pytest.raises(SecurityRefusal, match="public PKI not allowed"):
        ReadOnlyHttpClient(
            target="x",
            base_url="https://evil.example/v1",
            endpoints=set(),
            audit=MemoryAudit(),
            tls=TlsPolicy(ca_file=None, public_pki=True),
        )
    with pytest.raises(SecurityRefusal, match="host names"):
        TlsPolicy(ca_file=None, public_pki=True, check_hostname=False)
    with pytest.raises(ValidationError):
        TlsSettings(public_pki=True, sha256_pin="0" * 64)


def test_source_model_rules() -> None:
    url = f"https://api.ui.com/v1/connector/consoles/{CID}/network/integration"
    ok = UnifiSource(
        name="u",
        url=url,
        credential="k",
        connection="cloud",
        console_id=CID,
        tls=TlsSettings(public_pki=True),
    )
    assert ok.connection == "cloud"
    with pytest.raises(ValidationError, match="only with connection: cloud"):
        UnifiSource(name="u", url=url, credential="k")
    with pytest.raises(ValidationError, match="public_pki"):
        UnifiSource(name="u", url=url, credential="k", connection="cloud", console_id=CID)
    with pytest.raises(ValidationError):
        UnifiSource(
            name="u",
            url=url,
            credential="k",
            connection="cloud",
            console_id="bad id",
            tls=TlsSettings(public_pki=True),
        )


def test_consoles_parser_is_defensive() -> None:
    assert consoles(None) == []
    assert consoles({"data": [1, {"id": 5}, {"id": "a:1"}]}) == [
        {"id": "a:1", "name": "a:1", "type": "", "ip": ""}
    ]
