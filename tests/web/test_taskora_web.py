"""Integrations → Taskora and the Incidents page ticket links (ADR-042). Fakes only."""

import asyncio
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import SecretStr

from homelab_atlas.engine import taskora as tk
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.security.vault import Vault
from homelab_atlas.store.tables import TaskoraLink, TaskoraState
from homelab_atlas.web import auth
from homelab_atlas.web.app import WebConfig, create_app
from homelab_atlas.web.targets import TargetsService
from tests.helpers import MemoryAudit, scanned_lab
from tests.unit.test_taskora import TOKEN, FakeTaskora, later
from tests.web.test_v8 import PASSWORD, _login

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


@pytest.fixture(scope="module")
def rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    runtime = scanned_lab(tmp_path_factory.mktemp("taskora-web"))
    with runtime.sessions() as s:
        auth.create_user(s, "admin", PASSWORD)
        s.commit()
    return runtime


def _app(rt: Runtime, tmp_path: Path, fake: FakeTaskora | None = None) -> TestClient:
    vault = Vault(tmp_path / "vault.json", b"k" * 32)
    svc = TargetsService(
        config_dir=tmp_path / "cfg", data_dir=tmp_path, vault=vault, audit=MemoryAudit()
    )

    def taskora() -> tk.TaskoraClient | None:
        settings = tk.load_settings(tmp_path)
        if settings is None or fake is None:
            return None
        try:
            token = vault.resolve(tk.TOKEN_SECRET)
        except KeyError:
            token = None
        return tk.TaskoraClient(settings, token, MemoryAudit(), transport=httpx.MockTransport(fake))

    app = create_app(
        WebConfig(
            sessions=rt.sessions,
            annotations_dir=tmp_path,
            allowed_hosts=["testserver"],
            targets=svc,
            data_dir=tmp_path,
            taskora=taskora,
        )
    )
    return TestClient(app, base_url="https://testserver")


def test_settings_are_validated_and_the_token_goes_to_the_vault(
    rt: Runtime, tmp_path: Path
) -> None:
    with _app(rt, tmp_path) as c:
        h = {"X-CSRF-Token": _login(c)}
        assert "Taskora service desk" in c.get("/integrations").text
        bad = c.post(
            "/integrations/taskora",
            data={"url": "http://taskora.example.test", "allow_http": "1"},
            headers=h,
            follow_redirects=False,
        )
        assert "private+LAN+IP" in bad.headers["location"]
        wrong = c.post(
            "/integrations/taskora",
            data={"url": "https://taskora.example.test", "token": "not-a-taskora-token"},
            headers=h,
            follow_redirects=False,
        )
        assert "tki_" in wrong.headers["location"]
        ok = c.post(
            "/integrations/taskora",
            data={
                "url": "https://taskora.example.test",
                "instance": "atlas-home",
                "token": f"Bearer {TOKEN}",
                "incidents": "1",
            },
            headers=h,
            follow_redirects=False,
        )
        assert ok.status_code == 303 and "saved" in ok.headers["location"]
        stored = (tmp_path / tk.SETTINGS_FILE).read_text("utf-8")
        assert TOKEN not in stored and yaml.safe_load(stored)["instance"] == "atlas-home"
        vault = Vault(tmp_path / "vault.json", b"k" * 32)
        assert vault.resolve(tk.TOKEN_SECRET).get_secret_value() == TOKEN  # "Bearer " stripped
        assert TOKEN not in c.get("/integrations").text
        # Without the CSRF header nothing changes.
        assert c.post("/integrations/taskora/delete", follow_redirects=False).status_code == 403
        c.post("/integrations/taskora/delete", headers=h, follow_redirects=False)
        assert not (tmp_path / tk.SETTINGS_FILE).exists()


def test_test_buttons_preview_and_ticket_links(rt: Runtime, tmp_path: Path) -> None:
    fake = FakeTaskora()
    tk.save_settings(
        tmp_path,
        tk.TaskoraSettings(
            url="https://taskora.example.test", instance="atlas-home", incidents=True
        ),
    )
    Vault(tmp_path / "vault.json", b"k" * 32).put(tk.TOKEN_SECRET, SecretStr(TOKEN))
    with rt.sessions() as s:
        s.query(TaskoraLink).delete()
        s.query(TaskoraState).delete()
        s.commit()
    with _app(rt, tmp_path, fake) as c:
        h = {"X-CSRF-Token": _login(c)}
        r = c.post("/integrations/taskora/test", data={"what": "health"}, headers=h)
        assert "Connected" in r.text and "pill ok" in r.text
        r = c.post("/integrations/taskora/test", data={"what": "incident"}, headers=h)
        assert "pill ok" in r.text and fake.links["atlas-home:1"]["last"]["test"] is True
        r = c.post(
            "/integrations/taskora/inventory",
            data={"mode": "preview"},
            headers=h,
            follow_redirects=False,
        )
        assert "Preview" in r.headers["location"]
        page = c.get("/integrations").text
        assert "Last CMDB sync" in page and "docker01" in page and "preview" in page

        inv, _ = load_lab("B", LAB)
        settings = tk.load_settings(tmp_path)
        assert settings is not None
        with rt.sessions() as s:
            client = tk.TaskoraClient(
                settings,
                SecretStr(TOKEN),
                MemoryAudit(),
                transport=httpx.MockTransport(fake),
            )
            asyncio.run(tk.tick(s, inv, client, now=later()))
        incidents = c.get("/incidents").text
        assert (
            'href="https://taskora.example.test/tickets/' in incidents and "TKA-0000" in incidents
        )
        assert "delivered" in c.get("/integrations").text

        fake.fail = [503]
        with rt.sessions() as s:
            assert tk.replay_all(s) >= 3
            s.commit()
            asyncio.run(tk.tick(s, inv, client, now=later()))
        page = c.get("/integrations").text
        assert "failing" in page and "503" in page
        r = c.post("/integrations/taskora/retry", headers=h, follow_redirects=False)
        assert "retried" in r.headers["location"]


def test_demo_lab_is_read_only(rt: Runtime, tmp_path: Path) -> None:
    from tests.web.test_v8 import _client  # noqa: PLC0415

    with _client(rt, tmp_path) as c:
        h = {"X-CSRF-Token": _login(c)}
        assert "Read-only here (demo lab)" in c.get("/integrations").text
        r = c.post(
            "/integrations/taskora",
            data={"url": "https://taskora.example.test"},
            headers=h,
            follow_redirects=False,
        )
        assert r.status_code == 403
        assert c.post("/integrations/taskora/test", headers=h).status_code == 404
