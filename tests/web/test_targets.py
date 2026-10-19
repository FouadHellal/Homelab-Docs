"""Targets page (ADR-025): add VMs / Proxmox / UniFi from the UI, credentials write-only."""

import datetime as dt
import hashlib
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from homelab_atlas.inventory.managed import ManagedInventory
from homelab_atlas.runtime import Runtime, live_inputs
from homelab_atlas.security.vault import Vault
from homelab_atlas.web import auth
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit

PASSWORD = "test-only-ATLASFAKE-pw"
SSH_PW = "ssh-pw-ATLASFAKE-42"
# Format-valid but fake (a token must end in a UUID, so it cannot carry the ATLASFAKE marker).
PVE_TOKEN = "atlas@pve!collector=00000000-0000-0000-0000-000000000000"  # gitleaks:allow
HOST_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINSPPo/6UpynC2GHYZnzTV1aA1E45HQbtUQ+UJYhIR7/"


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    cfg_dir, data = tmp_path / "config", tmp_path / "data"
    cfg_dir.mkdir()
    monkeypatch.setenv("ATLAS_CONFIG_DIR", str(cfg_dir))
    monkeypatch.chdir(tmp_path)  # relative ./secrets dir is empty here
    rt = Runtime.open(data, mode="live")
    with rt.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    audit = MemoryAudit()
    vault = Vault(data / "vault.json", b"v" * 32)
    svc = TargetsService(config_dir=cfg_dir, data_dir=data, vault=vault, audit=audit)
    return {"rt": rt, "svc": svc, "vault": vault, "audit": audit, "cfg": cfg_dir, "data": data}


def _login(c: TestClient) -> str:
    token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
    assert token is not None
    r = c.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert r.status_code == 303
    m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/").text)
    assert m is not None
    return m.group(1)


@pytest.fixture
def client(env: dict[str, Any], tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    app = create_app(
        WebConfig(
            sessions=env["rt"].sessions,
            annotations_dir=tmp_path / "ann",
            allowed_hosts=["testserver"],
            targets=env["svc"],
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        yield c, _login(c)


def _host(csrf: str, **kw: Any) -> dict[str, Any]:
    data = {
        "csrf_token": csrf,
        "name": "docker01",
        "address": "192.168.1.20",
        "type": "linux",
        "collectors": ["linux-ssh", "docker"],
        "ssh_user": "admin",
        "ssh_port": "22",
        "auth": "password",
        "password": SSH_PW,
        "sudo": "1",
        "host_key": HOST_KEY,
        "host_key_confirmed": "1",
    }
    data.update(kw)
    return data


def test_targets_page_needs_login(env: dict[str, Any], tmp_path: Path) -> None:
    app = create_app(
        WebConfig(
            sessions=env["rt"].sessions,
            annotations_dir=tmp_path / "a",
            allowed_hosts=["testserver"],
            targets=env["svc"],
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        assert c.get("/targets", follow_redirects=False).status_code == 303
        assert c.post("/targets/host", data=_host("x")).status_code == 401


def test_add_vm_with_password_end_to_end(
    client: tuple[TestClient, str], env: dict[str, Any]
) -> None:
    c, csrf = client
    r = c.post("/targets/host", data=_host(csrf), follow_redirects=False)
    assert r.status_code == 303, r.text
    # Stored: inventory references a vault NAME; the vault holds ciphertext only.
    inv_text = (env["data"] / "inventory.yaml").read_text(encoding="utf-8")
    assert "ui-ssh-docker01" in inv_text
    assert SSH_PW not in inv_text
    assert SSH_PW not in (env["data"] / "vault.json").read_text(encoding="utf-8")
    assert env["vault"].resolve("ui-ssh-docker01").get_secret_value() == SSH_PW
    # Never rendered back.
    for path in ("/targets", "/targets/host?name=docker01"):
        page = c.get(path).text
        assert SSH_PW not in page
    assert "stored" in c.get("/targets/host?name=docker01").text
    # The audit log has names only.
    ops = [e.op for e in env["audit"].events]
    assert "ui.secret.set" in ops
    assert "ui.host.save" in ops
    assert all(e.transport == "ui" for e in env["audit"].events)
    assert SSH_PW not in str([e.model_dump() for e in env["audit"].events])
    # Scans see it: password mode, pinned key, sudo on.
    inputs = live_inputs(env["data"])
    host = inputs.inventory.host("docker01")
    from homelab_atlas.security.allowlist import ProbeSection  # noqa: PLC0415

    target = inputs.inventory.ssh_target(host, frozenset({ProbeSection.OS}))
    assert (target.auth, target.password_secret, target.sudo, target.username) == (
        "password",
        "ui-ssh-docker01",
        True,
        "admin",
    )
    assert target.host_keys == (HOST_KEY,)


def test_edit_keeps_password_when_left_empty(
    client: tuple[TestClient, str], env: dict[str, Any]
) -> None:
    c, csrf = client
    assert c.post("/targets/host", data=_host(csrf), follow_redirects=False).status_code == 303
    r = c.post(
        "/targets/host",
        data=_host(csrf, password="", host_key="", original="docker01", address="192.168.1.21"),
        follow_redirects=False,
    )
    assert r.status_code == 303, r.text
    assert env["vault"].resolve("ui-ssh-docker01").get_secret_value() == SSH_PW
    assert ManagedInventory(env["data"]).load().host("docker01").address == "192.168.1.21"


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"host_key_confirmed": ""}, "I checked this fingerprint"),
        ({"host_key": ""}, "fetch and confirm the SSH host key"),
        ({"password": ""}, "enter the SSH password"),
        ({"ssh_user": "root"}, "root"),
        ({"name": "../evil"}, "name"),
        ({"host_key": "ssh-rsa AAAAB3"}, "host_keys"),
    ],
)
def test_host_validation(client: tuple[TestClient, str], env: dict[str, Any],
                         kw: dict[str, str], message: str) -> None:  # fmt: skip
    c, csrf = client
    r = c.post("/targets/host", data=_host(csrf, **kw))
    assert r.status_code == 422
    assert message in r.text
    assert not (env["data"] / "inventory.yaml").exists()
    assert SSH_PW not in r.text


def test_csrf_required(client: tuple[TestClient, str]) -> None:
    c, _ = client
    data = _host("wrong")
    assert c.post("/targets/host", data=data, headers={"X-CSRF-Token": "nope"}).status_code == 403
    assert (
        c.post("/targets/host/delete", data={"name": "x", "csrf_token": "nope"}).status_code == 403
    )


def test_delete_removes_secret(client: tuple[TestClient, str], env: dict[str, Any]) -> None:
    c, csrf = client
    c.post("/targets/host", data=_host(csrf), follow_redirects=False)
    r = c.post(
        "/targets/host/delete",
        data={"csrf_token": csrf, "name": "docker01"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert not env["vault"].has("ui-ssh-docker01")
    assert ManagedInventory(env["data"]).load().hosts == ()


def test_hosts_yaml_entries_are_read_only(
    client: tuple[TestClient, str], env: dict[str, Any]
) -> None:
    (env["cfg"] / "hosts.yaml").write_text(
        "version: 1\nhosts:\n  - name: docker01\n    address: 10.0.0.9\n    type: linux\n",
        encoding="utf-8",
    )
    c, csrf = client
    r = c.post("/targets/host", data=_host(csrf))
    assert r.status_code == 422
    assert "hosts.yaml" in r.text
    assert "hosts.yaml" in c.get("/targets").text


def _cert() -> tuple[str, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pve1")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(7)
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=9))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),
    )


def test_add_proxmox_with_token_and_pinned_cert(
    client: tuple[TestClient, str], env: dict[str, Any]
) -> None:
    c, csrf = client
    pem, sha = _cert()
    base = {
        "csrf_token": csrf,
        "kind": "proxmox",
        "name": "homelab",
        "url": "192.168.1.10",
        "cert_pem": pem,
        "cert_sha256": sha,
        "cert_confirmed": "1",
    }
    bad = c.post("/targets/source", data={**base, "credential": "not-a-token-ATLASFAKE"})
    assert bad.status_code == 422
    assert "user@realm" in bad.text
    assert "not-a-token" not in bad.text
    ok = c.post("/targets/source", data={**base, "credential": PVE_TOKEN}, follow_redirects=False)
    assert ok.status_code == 303, ok.text
    src = ManagedInventory(env["data"]).load().sources.proxmox[0]
    assert src.url == "https://192.168.1.10:8006/api2/json"
    assert (src.credential, src.tls.sha256_pin, src.tls.check_hostname) == (
        "ui-proxmox-homelab",
        sha,
        False,
    )
    assert (env["data"] / "ca" / str(src.tls.ca_file)).read_text(encoding="utf-8") == pem
    assert PVE_TOKEN not in c.get("/targets").text
    assert PVE_TOKEN not in (env["data"] / "inventory.yaml").read_text(encoding="utf-8")
    # A live scan would find the pinned CA in <data>/ca.
    assert live_inputs(env["data"]).inventory.sources.proxmox[0].name == "homelab"


def test_unifi_needs_confirmed_cert(client: tuple[TestClient, str]) -> None:
    c, csrf = client
    pem, sha = _cert()
    r = c.post(
        "/targets/source",
        data={
            "csrf_token": csrf,
            "kind": "unifi",
            "name": "ucg",
            "url": "192.168.1.1",
            "credential": "k-ATLASFAKE",
            "cert_pem": pem,
            "cert_sha256": sha,
        },
    )
    assert r.status_code == 422
    assert "fingerprint" in r.text


def test_identity_fetch_refuses_bad_input(client: tuple[TestClient, str]) -> None:
    c, csrf = client
    r = c.post("/targets/hostkey", data={"csrf_token": csrf, "address": "evil; rm -rf /"})
    assert r.status_code == 200
    assert "Could not fetch" in r.text
    r = c.post("/targets/cert", data={"csrf_token": csrf, "kind": "unifi", "url": "http://x"})
    assert "Could not fetch" in r.text


def test_demo_lab_targets_are_read_only(env: dict[str, Any], tmp_path: Path) -> None:
    from homelab_atlas.lab import load_lab  # noqa: PLC0415

    inv, _ = load_lab("B", Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab")
    svc = TargetsService(
        config_dir=env["cfg"],
        data_dir=env["data"],
        vault=None,
        audit=MemoryAudit(),
        readonly_inventory=inv,
    )
    app = create_app(
        WebConfig(
            sessions=env["rt"].sessions,
            annotations_dir=tmp_path / "a",
            allowed_hosts=["testserver"],
            targets=svc,
            lab=True,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        csrf = _login(c)
        page = c.get("/targets").text
        assert "docker01" in page
        assert "Read-only" in page
        r = c.post("/targets/host", data=_host(csrf, name="new01"))
        assert r.status_code == 422
        assert "read-only" in r.text


def test_targets_hidden_when_disabled(env: dict[str, Any], tmp_path: Path) -> None:
    app = create_app(
        WebConfig(
            sessions=env["rt"].sessions,
            annotations_dir=tmp_path / "a",
            allowed_hosts=["testserver"],
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        _login(c)
        assert c.get("/targets").status_code == 404


def test_plain_form_post_passes_origin_check(client: tuple[TestClient, str]) -> None:
    """Browsers send Origin: null on form POSTs under no-referrer; we use same-origin."""
    c, csrf = client
    assert c.get("/targets").headers["Referrer-Policy"] == "same-origin"
    ok = c.post(
        "/targets/host/delete",
        data={"csrf_token": csrf, "name": "none"},
        headers={"Origin": "https://testserver"},
        follow_redirects=False,
    )
    assert ok.status_code == 303
    bad = c.post(
        "/targets/host/delete",
        data={"csrf_token": csrf, "name": "none"},
        headers={"Origin": "null"},
        follow_redirects=False,
    )
    assert bad.status_code == 403


@pytest.mark.parametrize(("mode", "probe"), [("key", "streamed"), ("key-installed", "installed")])
def test_add_vm_with_atlas_ssh_key(client: tuple[TestClient, str], env: dict[str, Any],
                                   mode: str, probe: str) -> None:  # fmt: skip
    c, csrf = client
    form_page = c.get("/targets/host").text
    m = re.search(r"(ssh-ed25519 [A-Za-z0-9+/=]+ atlas-collector)", form_page)
    assert m is not None
    assert "PRIVATE KEY" not in form_page
    r = c.post("/targets/host", data=_host(csrf, auth=mode, password=""), follow_redirects=False)
    assert r.status_code == 303, r.text
    inputs = live_inputs(env["data"])
    from homelab_atlas.security.allowlist import ProbeSection  # noqa: PLC0415

    target = inputs.inventory.ssh_target(
        inputs.inventory.host("docker01"), frozenset({ProbeSection.OS})
    )
    assert (target.auth, target.key_secret, target.probe) == ("key", "ui-atlas-ssh-key", probe)
    # The vault holds a real ed25519 key whose public half is what the page showed.
    from homelab_atlas.security.ssh_keys import public_line  # noqa: PLC0415

    assert public_line(env["vault"].resolve_bytes("ui-atlas-ssh-key")) == m.group(1)
    assert not env["vault"].has("ui-ssh-docker01")  # no password stored in key mode


def test_unknown_page_hides_personal_devices_and_prefills_targets(
    client: tuple[TestClient, str], env: dict[str, Any]
) -> None:
    from homelab_atlas.store.tables import Entity, Facet, Scan  # noqa: PLC0415

    c, _ = client
    with env["rt"].sessions() as s:
        scan = Scan(mode="live")
        s.add(scan)
        s.flush()
        for key, name, cat in [
            ("net:mac:aa", "Fouads-iPhone", "personal"),
            ("net:mac:bb", "rpi-dns", "pi"),
        ]:
            s.add(Entity(key=key, kind="unknown-device", display_name=name, status="unknown"))
            s.add(
                Facet(
                    entity_key=key,
                    collector="reconcile",
                    target="network",
                    scan_id=scan.id,
                    data={
                        "mac": key[-2:],
                        "ip": "192.168.1.9",
                        "name": name,
                        "category": cat,
                        "infrastructure": cat == "pi",
                        "reasons": ["x"],
                        "seen_via": "unifi@ucg",
                    },
                )
            )
        s.commit()
    page = c.get("/unknown").text
    assert "rpi-dns" in page
    assert "Fouads-iPhone" not in page
    assert "show everything" in page
    assert "Fouads-iPhone" in c.get("/unknown?everything=true").text
    m = re.search(r'href="(/targets/host\?prefill[^"]+)"', page)
    assert m is not None
    form = c.get(m.group(1).replace("&amp;", "&")).text
    assert 'value="rpi-dns"' in form
    assert 'value="192.168.1.9"' in form
    assert 'value="pi" selected' in form
