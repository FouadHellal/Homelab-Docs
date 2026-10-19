"""First-run account setup, built-in self-signed HTTPS, `atlas user add --password-stdin`."""

import re
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from typer.testing import CliRunner

from homelab_atlas.cli import app as cli_app
from homelab_atlas.cli_web import first_run_setup
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import User
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.tls import ensure_self_signed, fingerprint

PW = "first-run-ATLASFAKE-pw"


@pytest.fixture
def rt(tmp_path: Path) -> Runtime:
    return Runtime.open(tmp_path / "data", mode="live")


@pytest.fixture
def client(rt: Runtime, tmp_path: Path) -> Iterator[tuple[TestClient, Path]]:
    token_file = first_run_setup(rt)
    assert token_file is not None
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path / "ann",
            allowed_hosts=["testserver"],
            setup_token_file=token_file,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        yield c, token_file


def _csrf(c: TestClient, path: str = "/setup") -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', c.get(path).text)
    assert m is not None
    return m.group(1)


def _form(c: TestClient, token: str, **kw: str) -> dict[str, Any]:
    return {
        "csrf_token": _csrf(c),
        "setup_token": token,
        "username": "admin",
        "password": PW,
        "password2": PW,
        **kw,
    }


def test_token_file_is_private_and_stable(rt: Runtime) -> None:
    f = first_run_setup(rt)
    assert f is not None
    first = f.read_text(encoding="utf-8")
    assert len(first.strip()) >= 20
    assert first_run_setup(rt) == f
    assert f.read_text(encoding="utf-8") == first
    if hasattr(stat, "S_IRWXG"):
        import os  # noqa: PLC0415

        if os.name == "posix":
            assert not f.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO)


def test_login_redirects_to_setup_until_an_account_exists(client: tuple[TestClient, Path]) -> None:
    c, _ = client
    r = c.get("/login", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/setup"
    assert "setup token" in c.get("/setup").text.lower()


def test_setup_requires_the_token(client: tuple[TestClient, Path], rt: Runtime) -> None:
    c, _ = client
    r = c.post("/setup", data=_form(c, "wrong-token"))
    assert r.status_code == 401
    with rt.sessions() as s:
        assert s.scalar(select(func.count()).select_from(User)) == 0


def test_setup_creates_account_logs_in_and_closes(
    client: tuple[TestClient, Path], rt: Runtime
) -> None:
    c, token_file = client
    token = token_file.read_text(encoding="utf-8").strip()
    r = c.post("/setup", data=_form(c, token), follow_redirects=False)
    assert r.status_code == 303
    assert "__Host-atlas=" in r.headers["set-cookie"]
    assert not token_file.exists()  # one use only
    assert c.get("/", follow_redirects=False).status_code == 200  # logged in
    # Setup is closed for good, even with the old token.
    c.cookies.clear()
    assert c.get("/setup", follow_redirects=False).headers["location"] == "/login"
    again = c.post(
        "/setup", data={**_form(c, token), "csrf_token": _csrf(c, "/login")}, follow_redirects=False
    )
    assert again.status_code == 303
    with rt.sessions() as s:
        assert s.scalar(select(func.count()).select_from(User)) == 1


@pytest.mark.parametrize(
    ("kw", "msg"),
    [
        ({"password2": "different-ATLASFAKE-pw"}, "differ"),
        ({"password": "short", "password2": "short"}, "password"),
    ],
)
def test_setup_validates_passwords(
    client: tuple[TestClient, Path], kw: dict[str, str], msg: str
) -> None:
    c, token_file = client
    r = c.post("/setup", data=_form(c, token_file.read_text(encoding="utf-8").strip(), **kw))
    assert r.status_code == 422
    assert msg in r.text
    assert token_file.exists()


def test_setup_needs_login_csrf(client: tuple[TestClient, Path]) -> None:
    c, token_file = client
    data = _form(c, token_file.read_text(encoding="utf-8").strip())
    data["csrf_token"] = "forged"
    assert c.post("/setup", data=data).status_code == 403


def test_no_setup_page_without_token_file(rt: Runtime, tmp_path: Path) -> None:
    app = create_app(
        WebConfig(
            sessions=rt.sessions, annotations_dir=tmp_path / "a", allowed_hosts=["testserver"]
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        assert c.get("/setup", follow_redirects=False).headers["location"] == "/login"
        assert c.get("/login").status_code == 200


def test_self_signed_certificate(tmp_path: Path) -> None:
    cert, key = ensure_self_signed(tmp_path, ["atlas.home.arpa", "192.168.1.50", "*"])
    parsed = x509.load_pem_x509_certificate(cert.read_bytes())
    san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "atlas.home.arpa" in san.get_values_for_type(x509.DNSName)
    ips = {str(i) for i in san.get_values_for_type(x509.IPAddress)}
    assert {"192.168.1.50", "127.0.0.1"} <= ips
    fp = fingerprint(cert)
    assert ensure_self_signed(tmp_path, ["other"]) == (cert, key)  # kept, not regenerated
    assert fingerprint(cert) == fp
    assert b"PRIVATE KEY" in key.read_bytes()


def test_user_add_password_stdin(tmp_path: Path) -> None:
    res = CliRunner().invoke(
        cli_app,
        ["user", "add", "ops", "--password-stdin", "--data-dir", str(tmp_path / "d")],
        input=PW + "\n",
    )
    assert res.exit_code == 0, res.output
    assert PW not in res.output
    rt = Runtime.open(tmp_path / "d", mode="live")
    with rt.sessions() as s:
        assert s.scalar(select(User.username)) == "ops"
