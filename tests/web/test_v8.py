"""v8: Command Center, Media operations, Integrations (ADR-039/040). Demo lab + fakes only."""

import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from homelab_atlas.engine.notify import Notification, webhook_settings
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.vault import Vault
from homelab_atlas.web import auth, command, views
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import SourceForm, TargetError, TargetsService
from tests.helpers import MemoryAudit, scanned_lab

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
PASSWORD = "v8-pages-ATLASFAKE-pw"  # test value for the app under test


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("v8"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


class FakeNotifier:
    def __init__(self) -> None:
        self.sent: list[Notification] = []
        self.cfg = type("C", (), {"url": "http://10.0.0.5:5678/webhook/atlas"})()
        self.has_token = True

    async def send(self, note: Notification) -> tuple[bool, str]:
        self.sent.append(note)
        return True, "delivered (HTTP 200)"


def _client(rt: Runtime, tmp_path: Path, **cfg: Any) -> TestClient:
    inv, _ = load_lab("B", LAB)
    svc = TargetsService(
        config_dir=tmp_path / "cfg",
        data_dir=tmp_path / "data",
        vault=None,
        audit=MemoryAudit(),
        readonly_inventory=inv,
    )
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path,
            allowed_hosts=["testserver"],
            lab=True,
            targets=svc,
            data_dir=tmp_path,
            **cfg,
        )
    )
    return TestClient(app, base_url="https://testserver")


def _login(c: TestClient) -> str:
    token = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").text)
    assert token is not None
    r = c.post(
        "/login",
        data={"username": "admin", "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert r.status_code == 303
    m = re.search(r'"X-CSRF-Token": "([^"]+)"', c.get("/overview").text)
    assert m is not None
    return m.group(1)


@pytest.fixture
def web(rt: Runtime, tmp_path: Path) -> Iterator[tuple[TestClient, str]]:
    with _client(rt, tmp_path) as c:
        yield c, _login(c)


# ------------------------------------------------------------------ command center


def test_command_center_is_home_and_built_from_real_data(web: tuple[TestClient, str]) -> None:
    c, _ = web
    html = c.get("/").text
    assert "<h1>Command Center</h1>" in html
    assert re.search(r'class="nav-item" href="/"[^>]*aria-current="page"', html)
    for label in (
        "Proxmox nodes",
        "Virtual machines",
        "LXC containers",
        "Docker containers",
        "Network devices",
        "Apps found",
        "Storage",
        "Unknown devices",
    ):
        assert label in html
    assert 'href="/entities?kind=pve-vm"' in html  # cards drill down
    assert 'id="svc-table"' in html and 'data-state="healthy"' in html
    assert "ghost01: linux-ssh failed" in html  # the demo's dead host needs attention
    assert "media01: mount /mnt/media removed" in html  # recent change in the timeline
    assert "Media storage" not in html or "/media" in html
    assert "Jellyfin" in html


def test_timeline_partial_and_filters(web: tuple[TestClient, str]) -> None:
    c, _ = web
    r = c.get(
        "/",
        params={"hours": 168, "sev": "warning", "q": "mount"},
        headers={"HX-Request": "true", "HX-Target": "timeline"},
    )
    assert r.status_code == 200
    assert r.text.lstrip().startswith('<div id="timeline">')
    assert "<html" not in r.text
    assert c.get("/", params={"hours": 0}).status_code == 422


def test_service_states_need_evidence() -> None:
    fresh = {"state": "fresh"}
    app = {"evidence": ["port 5000"]}
    assert command.app_state(app, [], {}, {})[0] == "unknown"
    assert command.app_state(app, [], {"state": "never"}, {})[0] == "unknown"
    assert (
        command.app_state(app, [{"state": "running", "type": "systemd"}], {"state": "stale"}, {})[0]
        == "stale"
    )
    assert command.app_state(app, [{"state": "failed", "type": "systemd"}], fresh, {})[0] == "down"
    assert (
        command.app_state(
            app,
            [{"state": "running", "type": "container", "sub": "running (unhealthy)"}],
            fresh,
            {},
        )[0]
        == "degraded"
    )
    assert command.app_state({"evidence": ["process x"]}, [], fresh, {})[0] == "healthy"
    assert command.app_state(app, [], fresh, {})[0] == "unknown"  # a port is not "healthy"
    assert (
        command.app_state(app, [{"state": "inactive", "type": "systemd"}], fresh, {})[0] == "down"
    )


def test_unknown_is_not_counted_as_healthy_or_zero(rt: Runtime) -> None:
    with rt.sessions() as s:
        cards = views.machines(s)
        fresh = command.freshness(s, {"linux-ssh": 3600, "docker": 3600, "proxmox": 900})
        by_id = {c["id"]: c for c in command.summary(s, cards, fresh)}
    vms = by_id["pve-vm"]
    parts = {p["label"]: p["n"] for p in vms["parts"]}
    assert vms["total"] == parts["running"] + parts["stopped"] + parts["unknown"]


def test_freshness_marks_old_data_stale(rt: Runtime) -> None:
    with rt.sessions() as s:
        later = datetime.now(UTC) + timedelta(hours=10)
        states = {
            k: v["state"] for k, v in command.freshness(s, {"linux-ssh": 3600}, later).items()
        }
    assert states[("web01", "linux-ssh")] == "stale"
    assert states[("ghost01", "linux-ssh")] in ("failed", "never")


def test_quick_links_only_safe_pins(tmp_path: Path) -> None:
    (tmp_path / "quick-links.yaml").write_text(
        "- {name: Router, url: 'https://192.168.1.1'}\n"
        "- {name: Bad, url: 'javascript:alert(1)'}\n"
        "- {name: Creds, url: 'https://admin:pw@nas.lan'}\n"
        "- just a string\n",
        encoding="utf-8",
    )
    assert command.pinned_links(tmp_path) == [{"name": "Router", "url": "https://192.168.1.1"}]
    assert command.pinned_links(None) == []


# ------------------------------------------------------------------ media


def test_media_page_diagnoses_the_demo(web: tuple[TestClient, str]) -> None:
    c, _ = web
    html = c.get("/media").text
    assert "Jellyfin runs, but its media storage is not mounted" in html
    assert "status-degraded" in html
    assert "not on a network share" in html
    assert "Access to the path" in html  # failed library scan from Jellyfin
    assert "ATLASFAKE" not in html
    assert "MediaBrowser" not in html and "Token=" not in html
    assert 'href="http://10.0.20.55:8096/web/"' in html


def test_media_sessions_fall_back_to_stored_pseudonyms(web: tuple[TestClient, str]) -> None:
    c, _ = web
    html = c.get("/media/sessions", headers={"HX-Request": "true"}).text
    assert "viewer-" in html and "at the last scan" in html
    assert "ATLASFAKE" not in html
    assert "Hardware transcode" in html and "vaapi" in html


def test_media_live_view_is_cached(rt: Runtime, tmp_path: Path) -> None:
    calls: list[str] = []

    async def live(name: str) -> dict[str, Any]:
        calls.append(name)
        return {
            "ok": True,
            "names": {"viewer-1": "Alice"},
            "sessions": [
                {
                    "viewer": "viewer-1",
                    "item": "Film",
                    "play_method": "DirectPlay",
                    "paused": False,
                    "runtime_s": 100,
                    "position_s": 50,
                    "transcode_reasons": [],
                }
            ],
        }

    with _client(rt, tmp_path, media_live=live) as c:
        _login(c)
        first = c.get("/media/sessions").text
        c.get("/media/sessions")
    assert "Alice" in first and "live" in first
    assert calls == ["media"]


def test_media_live_errors_are_shown_not_raised(rt: Runtime, tmp_path: Path) -> None:
    async def live(_name: str) -> dict[str, Any]:
        return {"ok": False, "error": "unreachable: timeout"}

    with _client(rt, tmp_path, media_live=live) as c:
        _login(c)
        html = c.get("/media/sessions").text
    assert "Live view unavailable: unreachable: timeout" in html
    assert "Showing the last scan" in html


def test_media_actions_need_csrf_and_config(web: tuple[TestClient, str]) -> None:
    c, csrf = web
    assert c.post("/media/diagnose", data={"src": "media"}).status_code == 403
    assert (
        c.post("/media/diagnose", data={"src": "media"}, headers={"X-CSRF-Token": csrf}).status_code
        == 404
    )
    assert c.post("/media/refresh", data={"src": "media"}).status_code == 403


def test_diagnostic_request_goes_to_n8n(rt: Runtime, tmp_path: Path) -> None:
    fake = FakeNotifier()
    with _client(rt, tmp_path, notifier=lambda: fake) as c:
        csrf = _login(c)
        r = c.post("/media/diagnose", data={"src": "media"}, headers={"X-CSRF-Token": csrf})
        page = c.get("/integrations").text
        test = c.post("/integrations/n8n/test", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and "delivered" in r.text
    note = fake.sent[0]
    assert note.kind == "diagnostic.requested" and note.severity == "warning"
    assert any("Library folders" in e for e in note.evidence)
    assert "10.0.0.5:5678/webhook/atlas" in page and "never shown" in page
    assert test.status_code == 200 and fake.sent[-1].kind == "test"


def test_integrations_page_without_n8n(web: tuple[TestClient, str]) -> None:
    c, csrf = web
    html = c.get("/integrations").text
    assert "Not configured" in html and "Zabbix" in html and "Jellyfin" in html
    assert c.post("/integrations/n8n/test", headers={"X-CSRF-Token": csrf}).status_code == 404


def test_new_pages_keep_security_headers(web: tuple[TestClient, str]) -> None:
    c, _ = web
    for path in ("/", "/media", "/integrations", "/media/sessions"):
        r = c.get(path)
        assert "script-src 'self' 'nonce-" in r.headers["content-security-policy"], path
        assert "unsafe-inline" not in r.headers["content-security-policy"]


def test_new_pages_need_login(rt: Runtime, tmp_path: Path) -> None:
    with _client(rt, tmp_path) as c:
        for path in ("/", "/media", "/media/sessions", "/integrations"):
            r = c.get(path, follow_redirects=False)
            assert r.status_code in (303, 401), path


# ------------------------------------------------------------------ targets


def test_targets_service_jellyfin(tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.json", b"k" * 32)
    svc = TargetsService(
        config_dir=tmp_path / "cfg", data_dir=tmp_path, vault=vault, audit=MemoryAudit()
    )
    key = SecretStr(bytes(range(16)).hex())
    with pytest.raises(TargetError, match="http://"):
        svc.save_source(SourceForm(kind="jellyfin", name="jf", url="http://10.0.20.55:8096"), key)
    with pytest.raises(TargetError, match="32 hex"):
        svc.save_source(
            SourceForm(kind="jellyfin", name="jf", url="10.0.20.55", allow_http=True),
            SecretStr("not-a-key"),
        )
    with pytest.raises(TargetError):
        svc.save_source(
            SourceForm(kind="jellyfin", name="jf", url="http://8.8.8.8:8096", allow_http=True), key
        )
    src = svc.save_source(
        SourceForm(
            kind="jellyfin", name="jf", url="10.0.20.55", allow_http=True, jf_host="media01"
        ),
        key,
    )
    assert (src.url, src.allow_http, src.host) == ("http://10.0.20.55:8096", True, "media01")
    assert vault.resolve(src.credential).get_secret_value() == key.get_secret_value()
    assert key.get_secret_value() not in (tmp_path / "inventory.yaml").read_text("utf-8")


def test_n8n_settings_saved_from_the_ui(rt: Runtime, tmp_path: Path) -> None:
    vault = Vault(tmp_path / "vault.json", b"k" * 32)
    svc = TargetsService(
        config_dir=tmp_path / "cfg", data_dir=tmp_path, vault=vault, audit=MemoryAudit()
    )
    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path,
            allowed_hosts=["testserver"],
            targets=svc,
            data_dir=tmp_path,
        )
    )
    with TestClient(app, base_url="https://testserver") as c:
        csrf = _login(c)
        h = {"X-CSRF-Token": csrf}
        bad = c.post(
            "/integrations/n8n",
            data={"url": "http://8.8.8.8/webhook/a", "allow_http": "1"},
            headers=h,
            follow_redirects=False,
        )
        assert "private+LAN+IP" in bad.headers["location"]
        ok = c.post(
            "/integrations/n8n",
            headers=h,
            follow_redirects=False,
            data={
                "url": "http://10.0.0.5:5678/webhook/atlas",
                "allow_http": "1",
                "token": "tok-ATLASFAKE",
            },
        )
        assert ok.status_code == 303 and "Saved" in ok.headers["location"]
        assert "tok-ATLASFAKE" not in (tmp_path / "n8n.yaml").read_text("utf-8")
        assert vault.resolve("n8n_webhook_token").get_secret_value() == "tok-ATLASFAKE"
        cfg = webhook_settings(tmp_path)
        assert (
            cfg is not None and cfg.url == "http://10.0.0.5:5678/webhook/atlas" and cfg.allow_http
        )
        assert c.post("/integrations/n8n", data={"url": "x"}).status_code == 403  # CSRF
        c.post("/integrations/n8n/delete", headers=h)
        assert webhook_settings(tmp_path) is None and not vault.has("n8n_webhook_token")
