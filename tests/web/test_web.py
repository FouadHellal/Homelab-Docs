"""Web UI: auth, sessions, CSRF, headers/CSP, XSS, open redirects, pages, annotations."""

import asyncio
import hashlib
import re
import shutil
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import select

from homelab_atlas.lab import load_api_recordings, load_lab
from homelab_atlas.runtime import Inputs, Runtime, replay_http
from homelab_atlas.store.tables import Entity, User, WebSession
from homelab_atlas.web import auth
from homelab_atlas.web.app import LOGIN_COOKIE, SESSION_COOKIE, WebConfig, create_app, safe_next

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"
PKG = REPO / "src" / "homelab_atlas" / "web"
PASSWORD = "test-only-ATLASFAKE-pw"  # test value for the app under test, never a real secret


@pytest.fixture(scope="module")
def lab_runtime(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    rt = Runtime.open(tmp_path_factory.mktemp("data"), mode="demo")
    for state in ("A", "B"):
        inv, ssh = load_lab(state, LAB)
        asyncio.run(
            rt.scan_engine(
                Inputs(inv, ssh, replay_http(load_api_recordings(state, LAB)), LAB)
            ).run()
        )
    with rt.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return rt


@pytest.fixture
def ann_dir(tmp_path: Path) -> Path:
    d = tmp_path / "annotations"
    shutil.copytree(LAB / "annotations", d)
    return d


@pytest.fixture
def client(lab_runtime: Runtime, ann_dir: Path) -> Iterator[TestClient]:
    app = create_app(
        WebConfig(
            sessions=lab_runtime.sessions,
            annotations_dir=ann_dir,
            allowed_hosts=["testserver"],
            lab=True,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def login(
    c: TestClient, username: str = "admin", password: str = PASSWORD, next_: str = "/"
) -> Any:
    page = c.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert token is not None
    return c.post(
        "/login",
        data={
            "username": username,
            "password": password,
            "csrf_token": token.group(1),
            "next": next_,
        },
        follow_redirects=False,
    )


def csrf_of(c: TestClient) -> str:
    m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/").text)
    assert m is not None
    return m.group(1)


# ------------------------------------------------------------------ auth


@pytest.mark.parametrize(
    "path", ["/", "/entities", "/ips", "/vlans", "/ports", "/changes", "/unknown", "/topology"]
)
def test_pages_require_login(client: TestClient, path: str) -> None:
    r = client.get(path, follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=")


def test_login_redirect_keeps_the_query(client: TestClient) -> None:
    r = client.get("/entity?key=pve:vm:homelab/101&x=1", follow_redirects=False)
    assert r.status_code == 303
    nxt = parse_qs(urlsplit(r.headers["location"]).query)["next"]
    assert nxt == ["/entity?key=pve:vm:homelab/101&x=1"]


def test_api_and_htmx_get_401(client: TestClient) -> None:
    assert client.get("/api/topology").status_code == 401
    assert client.get("/ips", headers={"HX-Request": "true"}).status_code == 401


def test_login_cookie_flags_and_session(client: TestClient) -> None:
    r = login(client)
    assert r.status_code == 303
    cookie = next(
        v for k, v in r.headers.multi_items() if k == "set-cookie" and v.startswith(SESSION_COOKIE)
    )
    for flag in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
        assert flag.lower() in cookie.lower()
    assert "domain" not in cookie.lower()
    assert client.get("/").status_code == 200


def test_login_requires_login_csrf(client: TestClient) -> None:
    client.get("/login")
    r = client.post(
        "/login", data={"username": "admin", "password": PASSWORD, "csrf_token": "forged"}
    )
    assert r.status_code == 403
    client.cookies.delete(LOGIN_COOKIE)
    r = client.post("/login", data={"username": "admin", "password": PASSWORD, "csrf_token": "x"})
    assert r.status_code == 403


def test_bad_password_generic_message(client: TestClient) -> None:
    r = login(client, password="wrong-password-123")
    assert r.status_code == 401
    assert "invalid credentials" in r.text
    r = login(client, username="nobody", password="wrong-password-123")
    assert "invalid credentials" in r.text


def test_lockout(lab_runtime: Runtime, ann_dir: Path) -> None:
    with lab_runtime.sessions() as s:
        auth.create_user(s, "victim", PASSWORD)
        s.commit()
    app = create_app(
        WebConfig(
            sessions=lab_runtime.sessions, annotations_dir=ann_dir, allowed_hosts=["testserver"]
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        for _ in range(auth.MAX_FAILURES):
            login(c, "victim", "wrong-password-123")
        r = login(c, "victim", PASSWORD)
        assert r.status_code == 401
        assert "locked" in r.text


@pytest.mark.parametrize(
    "target",
    [
        "//evil.example/x",
        "https://evil.example",
        "/\\evil.example",
        "javascript:alert(1)",
        "",
        "evil",
    ],
)
def test_open_redirect_blocked(target: str) -> None:
    assert safe_next(target) == "/"


def test_next_is_honoured_when_local(client: TestClient) -> None:
    r = login(client, next_="/changes?severity=warning")
    assert r.headers["location"] == "/changes?severity=warning"


def test_logout_invalidates_session(client: TestClient) -> None:
    login(client)
    token = csrf_of(client)
    r = client.post("/logout", headers={"X-CSRF-Token": token}, follow_redirects=False)
    assert r.status_code == 303
    assert client.get("/", follow_redirects=False).status_code == 303


def test_session_idle_and_absolute_expiry(lab_runtime: Runtime) -> None:
    with lab_runtime.sessions() as s:
        res = auth.login(s, "admin", PASSWORD)
        s.commit()
        assert res.token is not None
        sess = s.get(WebSession, auth.token_id(res.token))
        assert sess is not None
        assert (
            auth.resolve(s, res.token, sess.last_seen + auth.IDLE - timedelta(seconds=1))
            is not None
        )
        assert auth.resolve(s, res.token, sess.last_seen + auth.IDLE + timedelta(seconds=1)) is None
    with lab_runtime.sessions() as s:
        res = auth.login(s, "admin", PASSWORD)
        assert res.token is not None
        sess = s.get(WebSession, auth.token_id(res.token))
        assert sess is not None
        assert auth.resolve(s, res.token, sess.expires_at) is None


def test_password_rules(lab_runtime: Runtime) -> None:
    with lab_runtime.sessions() as s:
        for name, pw in (
            ("ab", "long-enough-password"),
            ("Admin2", "long-enough-password"),
            ("short", "x" * 11),
        ):
            with pytest.raises(auth.AuthError):
                auth.create_user(s, name, pw)
        user = s.scalar(select(User).where(User.username == "admin"))
        assert user is not None
        assert user.password_hash.startswith("$argon2id$")
        assert PASSWORD not in user.password_hash


# ------------------------------------------------------------------ headers / CSP / XSS


def test_security_headers_and_nonce(client: TestClient) -> None:
    login(client)
    r = client.get("/")
    csp = r.headers["content-security-policy"]
    nonce = re.search(r"'nonce-([^']+)'", csp)
    assert nonce is not None
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'none'" in csp
    assert all(f'nonce="{nonce.group(1)}"' in tag for tag in re.findall(r"<script[^>]*>", r.text))
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    assert "<script>" not in r.text  # no inline scripts at all
    assert (
        client.get("/login").headers["content-security-policy"] != csp
    )  # fresh nonce per response


def test_untrusted_host_rejected(client: TestClient) -> None:
    assert client.get("/login", headers={"Host": "evil.example"}).status_code == 400


def test_target_data_is_escaped(lab_runtime: Runtime, client: TestClient) -> None:
    evil = '<script>alert("pwn")</script><img src=x onerror=alert(1)>'
    with lab_runtime.sessions() as s:
        s.add(Entity(key="host:evil", kind="linux-host", display_name=evil))
        s.commit()
    login(client)
    for path in ("/entities?q=evil", "/entity?key=host:evil"):
        body = client.get(path).text
        assert "<script>alert" not in body
        assert "<img src=x" not in body
        assert "&lt;script&gt;" in body


def test_templates_never_mark_safe() -> None:
    for t in (PKG / "templates").glob("*.html"):
        text = t.read_text(encoding="utf-8")
        assert not re.search(r"\|\s*safe\b|autoescape\s+false|Markup\(", text), t.name


def test_vendored_js_pinned() -> None:
    pins = {
        "htmx.min.js": "d6fdc75f204e6bdefa99b69bf1e6d4ac69b8a364f77929f45c13476b4000f717",
        "cytoscape.min.js": "081591ab735b2b6a3b31a3c60f8f3a3e2fee8c92939e0c7820ad1208571b6cd8",
    }
    for name, digest in pins.items():
        assert hashlib.sha256((PKG / "static" / "vendor" / name).read_bytes()).hexdigest() == digest


# ------------------------------------------------------------------ pages


def test_pages_render(client: TestClient) -> None:
    login(client)
    dash = client.get("/")
    assert dash.status_code == 200
    assert "unknown devices" in dash.text
    for path, expect in [
        ("/entities", "web01"),
        ("/ips", "10.0.20.21"),
        ("/vlans", "IoT"),
        ("/ports", "8443"),
        ("/changes", "guest.migrated"),
        ("/unknown?everything=true", "esp32-c3-5f2a"),  # IoT is hidden by default (ADR-027)
        ("/topology?view=physical", 'data-view="physical"'),
        ("/entity?key=pve:vm:homelab/103", "Public reverse proxy"),
    ]:
        r = client.get(path)
        assert r.status_code == 200, path
        assert expect in r.text, path
    assert client.get("/entity?key=nope").status_code == 404


def test_vm_page_merges_inner_host(client: TestClient) -> None:
    login(client)
    body = client.get("/entity?key=pve:vm:homelab/103").text
    assert "Listening ports" in body  # linux-ssh facet of the same machine
    assert "nginx" in body


@pytest.mark.parametrize("view", ["physical", "logical", "vlan"])
def test_topology_api(client: TestClient, view: str) -> None:
    login(client)
    data = client.get(f"/api/topology?view={view}").json()
    nodes = [e for e in data["elements"] if "source" not in e["data"]]
    edges = [e for e in data["elements"] if "source" in e["data"]]
    ids = {n["data"]["id"] for n in nodes}
    assert len(nodes) > 10
    assert all(e["data"]["source"] in ids and e["data"]["target"] in ids for e in edges)
    assert client.get("/api/topology?view=bogus").status_code == 400


def test_htmx_partials(client: TestClient) -> None:
    login(client)
    r = client.get("/ips?q=10.0.30", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text
    assert "10.0.30.41" in r.text


# ------------------------------------------------------------------ CSRF / annotations / ack


def test_state_changes_need_csrf(client: TestClient) -> None:
    login(client)
    key = "net:mac:84:f7:03:5f:2a:01"
    assert client.post("/unknown/ack", data={"key": key}).status_code == 403
    assert client.post("/unknown/ack", data={"key": key, "csrf_token": "forged"}).status_code == 403
    assert client.post("/unknown/ack", data={"key": key}, headers={"X-CSRF-Token": csrf_of(client),
                       "Origin": "https://evil.example"}).status_code == 403  # fmt: skip
    assert client.post("/entity/annotation", data={"key": "pve:vm:homelab/103"}).status_code == 403


def test_acknowledge_unknown(client: TestClient, ann_dir: Path, lab_runtime: Runtime) -> None:
    login(client)
    key = "net:mac:a2:11:22:33:44:55"
    r = client.post(
        "/unknown/ack", data={"key": key, "csrf_token": csrf_of(client)}, follow_redirects=False
    )
    assert r.status_code == 303
    files = [yaml.safe_load(p.read_text("utf-8")) for p in ann_dir.glob("*.yaml")]
    assert {"entity": key, "acknowledged": True} in files
    assert "android-7f3a" not in client.get("/unknown?everything=true").text
    assert "android-7f3a" in client.get("/unknown?all=true&everything=true").text
    with lab_runtime.sessions() as s:
        entity = s.get(Entity, key)
        assert entity is not None
        assert entity.status == "acknowledged"
    assert (
        client.post(
            "/unknown/ack", data={"key": "pve:vm:homelab/103", "csrf_token": csrf_of(client)}
        ).status_code
        == 404
    )


def test_annotation_edit_roundtrip(client: TestClient, ann_dir: Path) -> None:
    login(client)
    token = csrf_of(client)
    key = "pve:vm:homelab/102"
    form = {
        "key": key,
        "csrf_token": token,
        "owner": "alex",
        "purpose": "apps host",
        "criticality": "medium",
        "tags": "docker, apps",
        "links": "Grafana | https://grafana.lab.example/d/x",
        "notes": "<b>hi</b>",
    }
    r = client.post("/entity/annotation", data=form, headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "&lt;b&gt;hi&lt;/b&gt;" in r.text
    saved = [yaml.safe_load(p.read_text("utf-8")) for p in ann_dir.glob("*.yaml")]
    doc = next(d for d in saved if d["entity"] == key)
    assert doc["tags"] == ["apps", "docker"]
    assert list(doc) == ["entity", "owner", "purpose", "criticality", "tags", "links", "notes"]
    assert "alex" in client.get(f"/entity?key={key}").text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("links", "Evil | javascript:alert(1)"),
        ("links", "no separator"),
        ("tags", "bad tag!"),
        ("criticality", "extreme"),
    ],
)
def test_annotation_validation(client: TestClient, ann_dir: Path, field: str, value: str) -> None:
    login(client)
    before = sorted(p.name for p in ann_dir.glob("*.yaml"))
    r = client.post(
        "/entity/annotation",
        data={"key": "pve:vm:homelab/102", "csrf_token": csrf_of(client), field: value},
    )
    assert r.status_code == 422
    assert sorted(p.name for p in ann_dir.glob("*.yaml")) == before


def test_annotation_unknown_entity_and_traversal(client: TestClient, ann_dir: Path) -> None:
    login(client)
    token = csrf_of(client)
    r = client.post(
        "/entity/annotation", data={"key": "../../etc/passwd", "csrf_token": token, "owner": "x"}
    )
    assert r.status_code == 404
    assert not list(ann_dir.parent.glob("passwd*"))


def test_healthz_is_public_and_empty(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.text == "ok"
    assert "set-cookie" not in r.headers
    assert r.headers["Cache-Control"] == "no-store"
