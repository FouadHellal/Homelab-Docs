"""Portal (ADR-049): seed-once, visibility before login, editing, validation, escaping;
trusted HTTPS for password managers (ADR-050); the login form contract browsers rely on."""

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import PortalCategory, PortalLink, PortalSetting
from homelab_atlas.web import auth, portal
from homelab_atlas.web.app import SESSION_COOKIE, WebConfig, create_app
from homelab_atlas.web.tls import CA_FILE, ensure_self_signed, issue_trusted

PASSWORD = "portal-test-ATLASFAKE-pw"  # test value for the app under test, never a real secret
SEED = """
public: true
categories:
  - name: Home Lab
    links:
      - {name: "Proxmox VE · pve", url: "https://192.0.2.100:8006/#v1",
         icon: "brand:proxmox", favorite: true}
      - {name: Zabbix, url: "http://192.0.2.221/zabbix.php?a=1", icon: "brand:zabbix"}
      - {name: Pi-hole, url: "http://192.0.2.125/admin/login", description: DNS filtering}
      - {name: Jellyfin, url: "http://192.0.2.175:8096/web/"}
      - {name: Nokia, url: "http://192.0.2.254/", icon: "glyph:router"}
  - name: IT Services
    links:
      - {name: Omada Cloud, url: "https://omada.tplinkcloud.com/"}
      - {name: Microsoft Azure, url: "https://portal.azure.com/#home"}
  - name: PhD
    links:
      - {name: Drive, url: "https://drive.google.com/", icon: "brand:googledrive"}
      - {name: Moodle, url: "https://moodle.example.edu/calendar/view.php?view=upcoming"}
      - {name: Webmail, url: "https://mail.example.edu/mail/"}
"""
SEEDED_LINKS = 10


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    rt = Runtime.open(tmp_path / "data", mode="demo")
    with rt.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return rt


@pytest.fixture
def seed(tmp_path: Path) -> Path:
    p = tmp_path / "portal-seed.yaml"
    p.write_text(SEED, encoding="utf-8")
    return p


def _app(rt: Runtime, tmp_path: Path, seed: Path | None) -> TestClient:
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path / "ann",
            allowed_hosts=["testserver"],
            data_dir=rt.data_dir,
            portal_seed=seed,
        )
    )
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def client(rt: Runtime, tmp_path: Path, seed: Path) -> Iterator[TestClient]:
    with _app(rt, tmp_path, seed) as c:
        yield c


def _login(c: TestClient) -> None:
    page = c.get("/login").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert token is not None
    r = c.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": token[1], "next": "/"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert SESSION_COOKIE in c.cookies


def _csrf(c: TestClient) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/portal/edit").text)
    assert m is not None
    return m[1]


def _links(rt: Runtime) -> list[PortalLink]:
    with rt.sessions() as s:
        return list(s.scalars(select(PortalLink).order_by(PortalLink.position)))


def _cat_id(rt: Runtime, name: str) -> int:
    with rt.sessions() as s:
        cid = s.scalar(select(PortalCategory.id).where(PortalCategory.name == name))
    assert cid is not None
    return cid


def _form(c: TestClient, rt: Runtime, **kw: Any) -> dict[str, Any]:
    return {
        "csrf_token": _csrf(c),
        "category_id": str(_cat_id(rt, "Home Lab")),
        "name": "Grafana",
        "url": "http://10.0.0.30:3000/",
        **kw,
    }


# ---------------------------------------------------------------- seed


def test_migration_starts_private_and_empty(rt: Runtime, tmp_path: Path) -> None:
    with rt.sessions() as s:
        assert portal.categories(s) == []
        assert not portal.is_public(s)
    with _app(rt, tmp_path, None) as c:  # no seed file: atlas behaves as before
        r = c.get("/", follow_redirects=False)
        assert r.headers["location"] == "/login?next=/"
        assert "Log in to Atlas" in c.get("/portal").text


def test_seed_is_imported_once_and_never_overwrites_edits(
    client: TestClient, rt: Runtime, tmp_path: Path, seed: Path
) -> None:
    with rt.sessions() as s:
        assert [c.name for c in portal.categories(s)] == ["Home Lab", "IT Services", "PhD"]
        assert s.scalar(select(func.count()).select_from(PortalLink)) == SEEDED_LINKS
        assert portal.is_public(s)
        jelly = s.scalar(select(PortalLink).where(PortalLink.name == "Jellyfin"))
        assert jelly is not None
        jelly.name = "Movies"
        s.delete(s.scalar(select(PortalLink).where(PortalLink.name == "Nokia")))
        portal.set_public(s, False)
        s.commit()
    again = Runtime.open(rt.data_dir, mode="demo")  # an update: migrations and startup again
    with _app(again, tmp_path, seed) as c:
        c.get("/healthz")
    with again.sessions() as s:
        names = set(s.scalars(select(PortalLink.name)))
        assert s.scalar(select(func.count()).select_from(PortalLink)) == SEEDED_LINKS - 1
        assert not portal.is_public(s)
    assert "Movies" in names
    assert "Jellyfin" not in names
    assert "Nokia" not in names


def test_a_broken_seed_file_does_not_stop_atlas(rt: Runtime, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("categories:\n  - name: X\n    links:\n      - {name: a, url: 'javascript:x'}\n")
    with _app(rt, tmp_path, bad) as c:
        assert c.get("/portal").status_code == 200
    with rt.sessions() as s:
        assert portal.categories(s) == []
        assert s.get(PortalSetting, "seeded") is None  # retried after it is fixed


@pytest.mark.parametrize(
    ("text", "why"),
    [
        ("categories: [", "not valid YAML"),
        ("- a", "Start with 'categories:'"),
        ("public: yes please\ncategories: []", "true or false"),
        ("categories:\n  - name: A\n    links: [{name: x, url: 'ftp://h/'}]", "A > x: Only http"),
        (
            "categories:\n  - name: A\n    links: [{name: x, url: 'http://h/', icon: 'brand:x'}]",
            "unknown icon",
        ),
    ],
)
def test_seed_validation(text: str, why: str) -> None:
    with pytest.raises(portal.PortalError, match=re.escape(why)):
        portal.parse_seed(text)


def test_import_in_the_editor_skips_duplicates(client: TestClient, rt: Runtime) -> None:
    _login(client)
    r = client.post("/portal/import", data={"seed": SEED, "csrf_token": _csrf(client)})
    assert "Imported 0 shortcuts; 10 were already there." in r.text
    extra = "categories:\n  - name: Network\n    links: [{name: Router, url: 'http://192.0.2.1/'}]"
    r = client.post("/portal/import", data={"seed": extra, "csrf_token": _csrf(client)})
    assert "Imported 1 shortcut." in r.text
    router = next(x for x in _links(rt) if x.name == "Router")
    assert not router.public  # the pasted document did not say public: true
    r = client.post("/portal/import", data={"seed": "categories: [", "csrf_token": _csrf(client)})
    assert r.status_code == 422
    assert "Import: That is not valid YAML" in r.text


# ---------------------------------------------------------------- visibility


def test_unauthenticated_root_opens_the_portal_with_a_login_button(client: TestClient) -> None:
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/portal"
    page = client.get("/portal")
    assert page.status_code == 200
    assert 'href="/login"' in page.text
    assert "Log in to Atlas" in page.text
    assert "Proxmox VE · pve" in page.text
    assert "/portal/edit" not in page.text  # no editor for anonymous visitors
    assert 'rel="noopener noreferrer"' in page.text
    assert "Found in your inventory" not in page.text


def test_private_links_and_disabled_portal_stay_hidden(client: TestClient, rt: Runtime) -> None:
    with rt.sessions() as s:
        hidden = s.scalar(select(PortalLink).where(PortalLink.name == "Zabbix"))
        assert hidden is not None
        hidden.public = False
        s.commit()
    page = client.get("/portal").text
    assert "zabbix.php" not in page
    assert "1 more shortcut after you" in page
    with rt.sessions() as s:
        portal.set_public(s, False)
        s.commit()
    page = client.get("/portal").text
    assert "192.0.2." not in page
    assert "Log in to Atlas" in page
    r = client.get("/", follow_redirects=False)
    assert r.headers["location"] == "/login?next=/"
    _login(client)
    signed_in = client.get("/portal").text
    assert "zabbix.php" in signed_in  # signed in: everything
    assert 'href="/portal/edit"' in signed_in


def test_editor_requires_login_and_csrf(client: TestClient, rt: Runtime) -> None:
    r = client.get("/portal/edit", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"].startswith("/login?next=/portal/edit")
    assert client.post("/portal/settings", data={"public": "0"}).status_code == 401
    _login(client)
    r = client.post("/portal/settings", data={"public": "0", "csrf_token": "wrong"})
    assert r.status_code == 403
    r = client.post(
        "/portal/settings",
        data={"csrf_token": _csrf(client)},
        headers={"origin": "https://evil.example"},
    )
    assert r.status_code == 403
    with rt.sessions() as s:
        assert portal.is_public(s)


# ---------------------------------------------------------------- editing


def test_add_edit_reorder_toggle_delete(client: TestClient, rt: Runtime) -> None:
    _login(client)
    r = client.post(
        "/portal/links",
        data=_form(client, rt, icon="", description="Dashboards", favorite="1"),
        follow_redirects=False,
    )
    assert r.status_code == 303
    new = next(x for x in _links(rt) if x.name == "Grafana")
    assert new.favorite
    assert not new.public  # new shortcuts are private until the owner says otherwise
    assert portal.resolve_icon(new.icon, new.name, new.url).css == "b-grafana"
    home = _cat_id(rt, "Home Lab")
    order = [x.id for x in _links(rt) if x.category_id == home]
    assert order[-1] == new.id

    client.post(
        f"/portal/links/{new.id}/move", data={"direction": "up", "csrf_token": _csrf(client)}
    )
    order = [x.id for x in _links(rt) if x.category_id == home]
    assert order[-2] == new.id

    client.post(
        f"/portal/links/{new.id}/toggle", data={"field": "public", "csrf_token": _csrf(client)}
    )
    assert next(x for x in _links(rt) if x.id == new.id).public

    phd = _cat_id(rt, "PhD")
    form = _form(client, rt, id=str(new.id), name="Grafana · lab", category_id=str(phd))
    form.update(icon="glyph:chart", url="https://grafana.lab/")
    assert client.post("/portal/links", data=form, follow_redirects=False).status_code == 303
    moved = next(x for x in _links(rt) if x.id == new.id)
    assert (moved.name, moved.category_id, moved.icon, moved.url) == (
        "Grafana · lab",
        phd,
        "glyph:chart",
        "https://grafana.lab/",
    )
    assert not moved.favorite  # an unticked box means off

    client.post(f"/portal/links/{new.id}/delete", data={"csrf_token": _csrf(client)})
    assert all(x.id != new.id for x in _links(rt))
    assert len(_links(rt)) == SEEDED_LINKS


def test_categories_add_rename_move_delete(client: TestClient, rt: Runtime) -> None:
    _login(client)
    client.post("/portal/categories", data={"name": "Network", "csrf_token": _csrf(client)})
    net = _cat_id(rt, "Network")
    client.post(
        f"/portal/categories/{net}/move", data={"direction": "up", "csrf_token": _csrf(client)}
    )
    with rt.sessions() as s:
        assert [c.name for c in portal.categories(s)] == [
            "Home Lab",
            "IT Services",
            "Network",
            "PhD",
        ]
    client.post(
        "/portal/categories", data={"id": str(net), "name": "LAN", "csrf_token": _csrf(client)}
    )
    assert _cat_id(rt, "LAN") == net
    phd = _cat_id(rt, "PhD")
    r = client.post(f"/portal/categories/{phd}/delete", data={"csrf_token": _csrf(client)})
    assert "Deleted PhD and its 3 shortcuts." in r.text
    assert len(_links(rt)) == SEEDED_LINKS - 3


@pytest.mark.parametrize(
    ("url", "why"),
    [
        ("javascript:alert(1)", "http://"),
        ("data:text/html,<b>x</b>", "http://"),
        ("ftp://nas.lan/", "Only http"),
        ("https://admin:hunter2@10.0.0.1/", "never store credentials"),
        ("https://exa mple.com/", "spaces"),
        ("http://:8080/", "host"),
        ("http://10.0.0.1:99999/", "could not be read"),
    ],
)
def test_unsafe_urls_are_refused_and_the_form_is_kept(
    client: TestClient, rt: Runtime, url: str, why: str
) -> None:
    _login(client)
    r = client.post("/portal/links", data=_form(client, rt, name="Typed name", url=url))
    assert r.status_code == 422
    assert why in r.text
    assert 'value="Typed name"' in r.text  # nothing the user typed is lost
    assert len(_links(rt)) == SEEDED_LINKS


def test_user_text_is_escaped_everywhere(client: TestClient, rt: Runtime) -> None:
    _login(client)
    evil = "<img src=x onerror=alert(1)>\"'"
    form = _form(client, rt, name=evil, description=evil, icon="", public="1")
    assert client.post("/portal/links", data=form, follow_redirects=False).status_code == 303
    client.post("/portal/categories", data={"name": evil, "csrf_token": _csrf(client)})
    for page in (client.get("/portal").text, client.get("/portal/edit").text):
        assert "<img src=x" not in page
        assert "&lt;img src=x onerror=alert(1)&gt;" in page
    client.cookies.clear()
    assert "<img src=x" not in client.get("/portal").text


def test_bad_icon_and_lengths_are_refused(client: TestClient, rt: Runtime) -> None:
    _login(client)
    r = client.post("/portal/links", data=_form(client, rt, icon="brand:../../etc/passwd"))
    assert r.status_code == 422
    r = client.post("/portal/links", data=_form(client, rt, name="x" * 81))
    assert r.status_code == 422
    r = client.post("/portal/links", data=_form(client, rt, category_id="999"))
    assert r.status_code == 422
    r = client.post("/portal/links/999/toggle", data={"field": "url", "csrf_token": _csrf(client)})
    assert r.status_code == 400


def test_prefill_from_inventory_suggestion(client: TestClient) -> None:
    _login(client)
    page = client.get("/portal/edit?add_name=Uptime+Kuma&add_url=http://10.0.0.9:3001").text
    assert 'value="Uptime Kuma"' in page
    assert 'value="http://10.0.0.9:3001"' in page


def test_suggestions_skip_known_hosts() -> None:
    class _S:
        def scalars(self, _q: Any) -> list[str]:
            return ["https://10.0.0.100:8006/#v1"]

    quick = [
        {"name": "Proxmox VE", "where": "pve", "url": "https://10.0.0.100:8006"},
        {"name": "Grafana", "where": "mon01", "url": "http://10.0.0.30:3000"},
        {"name": "Bad", "where": "x", "url": "javascript:alert(1)"},
    ]
    out = portal.suggestions(_S(), quick)  # type: ignore[arg-type]
    assert [x["name"] for x in out] == ["Grafana · mon01"]


def test_auto_icons() -> None:
    assert portal.auto_icon("Pi-hole", "http://10.0.0.125/") == "brand:pihole"
    assert portal.auto_icon("UniFi Site Manager", "https://unifi.ui.com/") == "brand:ubiquiti"
    assert portal.auto_icon("Omada Cloud", "https://omada.tplinkcloud.com/") == "brand:tplink"
    assert portal.auto_icon("Uni Webmail", "https://mail.example.edu/mail/") == "glyph:mail"
    assert portal.auto_icon("Complex thing", "http://10.0.0.1/") == "letters"  # no "plex" match
    assert portal.resolve_icon("letters", "What-If", "").text == "WI"
    assert portal.resolve_icon("", "Sirius", "").text == "Si"


# ---------------------------------------------------------------- login form contract


def test_login_form_is_what_password_managers_expect(client: TestClient) -> None:
    page = client.get("/login").text
    form = re.search(r"<form[^>]*>", page)
    assert form is not None
    assert 'method="post"' in form[0]
    assert 'action="/login"' in form[0]
    assert re.search(r'<label for="username">', page)
    assert re.search(r'<label for="password">', page)
    user = re.search(r'<input id="username"[^>]*>', page)
    pw = re.search(r'<input id="password"[^>]*>', page)
    assert user is not None and pw is not None
    assert 'name="username"' in user[0] and 'autocomplete="username"' in user[0]
    assert 'type="text"' in user[0]
    assert 'name="password"' in pw[0] and 'type="password"' in pw[0]
    assert 'autocomplete="current-password"' in pw[0]
    assert '<button type="submit"' in page
    assert 'href="/portal"' in page  # back to the shortcuts
    assert 'href="/docs#https"' in page


def test_failed_login_keeps_the_form_and_succeeds_after(client: TestClient) -> None:
    page = client.get("/login").text
    token = re.search(r'name="csrf_token" value="([^"]+)"', page)
    assert token is not None
    r = client.post(
        "/login",
        data={"username": "admin", "password": "wrong-password!", "csrf_token": token[1]},
    )
    assert r.status_code == 401
    assert 'role="alert"' in r.text
    assert 'autocomplete="current-password"' in r.text
    _login(client)
    assert client.get("/").status_code == 200


# ---------------------------------------------------------------- trusted HTTPS (ADR-050)


def test_trusted_certificate_chain(tmp_path: Path) -> None:
    ensure_self_signed(tmp_path, ["10.0.0.50"])
    cert_path, key_path, ca_path = issue_trusted(tmp_path, ["10.0.0.50", "atlas.lan"])
    tls = tmp_path / "tls"
    assert sorted(p.name for p in tls.iterdir() if p.is_file()) == [
        "atlas-ca.crt",
        "atlas.crt",
        "atlas.key",
    ]
    assert len(list(tls.glob("previous-*/atlas.crt"))) == 1  # the old certificate is kept
    # The CA's private key is never written: the only key on disk is the server's own
    # (plus the previous server key, kept for rollback).
    keys = [p for p in tls.rglob("*") if p.is_file() and b"PRIVATE KEY" in p.read_bytes()]
    assert sorted(p.relative_to(tls).parts[-1] for p in keys) == ["atlas.key", "atlas.key"]
    assert key_path in keys
    leaf, ca_in_chain = x509.load_pem_x509_certificates(cert_path.read_bytes())
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    assert ca_in_chain == ca
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    nc = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical
    assert x509.DNSName("atlas.lan") in (nc.value.permitted_subtrees or [])
    ca_pub = ca.public_key()
    assert isinstance(ca_pub, ec.EllipticCurvePublicKey)
    leaf.verify_directly_issued_by(ca)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "atlas.lan" in san.get_values_for_type(x509.DNSName)
    assert (leaf.not_valid_after_utc - leaf.not_valid_before_utc).days <= 826
    # Serving keeps the issued files (ensure_self_signed never replaces existing ones).
    assert ensure_self_signed(tmp_path, ["10.0.0.50"]) == (cert_path, key_path)


def test_trusted_certificate_needs_a_real_name(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="name or IP"):
        issue_trusted(tmp_path, ["*", "localhost"])


def test_ca_download(client: TestClient, rt: Runtime) -> None:
    assert client.get("/atlas-ca.crt").status_code == 404
    issue_trusted(rt.data_dir, ["10.0.0.50"])
    r = client.get("/atlas-ca.crt")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/x-x509-ca-cert"
    assert r.text.startswith("-----BEGIN CERTIFICATE-----")
    assert "PRIVATE" not in r.text
    assert (rt.data_dir / "tls" / CA_FILE).read_text() == r.text
