"""ADR-039/040 security boundaries: LAN-only plain HTTP, and the one n8n POST."""

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from homelab_atlas.collectors.jellyfin import ENDPOINTS, RECENT, SYSTEM_INFO
from homelab_atlas.engine.notify import (
    Notification,
    WebhookConfig,
    WebhookNotifier,
    webhook_from_env,
)
from homelab_atlas.inventory.hosts import JellyfinSource
from homelab_atlas.redact import Redactor
from homelab_atlas.runtime import auth_header
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, TlsPolicy, lan_ip_literal
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security
KEY = bytes(range(16)).hex()  # a fake 32-hex Jellyfin key (format only), built at runtime


def _client(url: str, *, lan: bool, tls: TlsPolicy | None = None, **kw: Any) -> ReadOnlyHttpClient:
    return ReadOnlyHttpClient(
        target="jf",
        base_url=url,
        endpoints=ENDPOINTS,
        audit=MemoryAudit(),
        tls=tls,
        plain_http_lan=lan,
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={})),
        **kw,
    )


@pytest.mark.parametrize(
    ("host", "ok"),
    [
        ("10.0.20.55", True),
        ("172.16.0.9", True),
        ("172.31.255.1", True),
        ("192.168.1.40", True),
        ("[fd12::1]", True),
        ("172.32.0.1", False),
        ("8.8.8.8", False),
        ("127.0.0.1", False),
        ("169.254.1.1", False),
        ("jellyfin.lan", False),
        ("[2001:db8::1]", False),
    ],
)
def test_lan_ip_literal(host: str, ok: bool) -> None:
    assert lan_ip_literal(host) is ok


def test_plain_http_needs_the_opt_in() -> None:
    with pytest.raises(SecurityRefusal) as exc:
        _client("http://10.0.20.55:8096", lan=False)
    assert exc.value.reason is RefusalReason.CONFIG


@pytest.mark.parametrize(
    "url", ["http://8.8.8.8:8096", "http://jellyfin.lan:8096", "http://127.0.0.1"]
)
def test_plain_http_only_to_private_ip_literals(url: str) -> None:
    with pytest.raises(SecurityRefusal):
        _client(url, lan=True)


def test_plain_http_refuses_tls_settings(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    with pytest.raises(SecurityRefusal) as exc:
        _client("http://10.0.20.55:8096", lan=True, tls=TlsPolicy(ca_file=ca))
    assert exc.value.reason is RefusalReason.TLS_POLICY


async def test_plain_http_lan_still_enforces_the_allowlist() -> None:
    c = _client("http://10.0.20.55:8096", lan=True)
    async with c:
        assert (await c.get(SYSTEM_INFO)).status == 200
        with pytest.raises(SecurityRefusal):  # only the declared fixed query values
            await c.get(RECENT, None, {"sortBy": "Random", "sortOrder": "Descending"})
        with pytest.raises(SecurityRefusal):  # POST through a GET endpoint
            await c.post(SYSTEM_INFO, Notification(kind="test", title="x"))


def test_https_without_tls_policy_still_refused() -> None:
    with pytest.raises(SecurityRefusal):
        ReadOnlyHttpClient(
            target="x",
            base_url="https://10.0.20.55:8920",
            endpoints=ENDPOINTS,
            audit=MemoryAudit(),
            tls=None,
            plain_http_lan=True,
        )


def test_jellyfin_endpoints_are_get_only() -> None:
    assert {e.method for e in ENDPOINTS} == {"GET"}
    assert all(e.body_model is None for e in ENDPOINTS)


@pytest.mark.parametrize(
    ("url", "allow", "msg"),
    [
        ("http://10.0.20.55:8096", False, "allow_http"),
        ("http://jellyfin.lan:8096", True, "IP address"),
        ("http://8.8.8.8:8096", True, "private LAN IP"),
        ("https://10.0.20.55:8920", True, "only for http://"),
    ],
)
def test_jellyfin_source_validation(url: str, allow: bool, msg: str) -> None:
    with pytest.raises(ValueError, match=msg):
        JellyfinSource(name="jf", url=url, credential="jf_key", allow_http=allow)


def test_jellyfin_auth_header_and_bad_keys() -> None:
    h = auth_header("jellyfin-token", SecretStr(KEY))
    assert h.name == "Authorization"
    assert h.value.get_secret_value() == f'MediaBrowser Token="{KEY}"'
    for bad in ("short", KEY + "0", 'x"; evil', KEY[:-1] + "g"):
        with pytest.raises(SecurityRefusal):
            auth_header("jellyfin-token", SecretStr(bad))


# ------------------------------------------------------------------ n8n webhook


class Hook:
    def __init__(self, status: int = 200) -> None:
        self.requests: list[httpx.Request] = []
        self.status = status

    def __call__(self, r: httpx.Request) -> httpx.Response:
        self.requests.append(r)
        return httpx.Response(self.status, json={"ok": True})


def _notifier(
    hook: Hook, url: str = "http://10.0.0.5:5678/webhook/atlas", **kw: Any
) -> WebhookNotifier:
    cfg = WebhookConfig(url, allow_http=True)
    return WebhookNotifier(
        cfg, SecretStr("tok-ATLASFAKE"), MemoryAudit(), transport=httpx.MockTransport(hook), **kw
    )


async def test_notifier_posts_one_typed_payload_to_the_exact_path() -> None:
    hook = Hook()
    ok, msg = await _notifier(hook).send(Notification(kind="test", title="hello"))
    assert ok, msg
    (r,) = hook.requests
    assert r.method == "POST"
    assert r.url.path == "/webhook/atlas"
    assert r.headers["authorization"] == "Bearer tok-ATLASFAKE"
    body = json.loads(r.content)
    assert body["source"] == "atlas" and body["kind"] == "test" and body["title"] == "hello"


async def test_notifier_redacts_secrets_in_text() -> None:
    hook = Hook()
    red = Redactor(b"k" * 32)
    note = Notification(kind="test", title="x", evidence=["DB_PASSWORD=pw-ATLASFAKE-123 in env"])
    ok, _ = await _notifier(hook, redactor=red).send(note)
    assert ok
    assert "pw-ATLASFAKE-123" not in hook.requests[0].content.decode()


@pytest.mark.parametrize(("status", "hint"), [(401, "token"), (404, "publish"), (500, "HTTP 500")])
async def test_notifier_reports_failures_without_raising(status: int, hint: str) -> None:
    ok, msg = await _notifier(Hook(status)).send(Notification(kind="test", title="x"))
    assert not ok and hint in msg


async def test_notifier_https_public_cert_for_that_host_only() -> None:
    hook = Hook()
    cfg = WebhookConfig("https://n8n.example.net/webhook/atlas")
    n = WebhookNotifier(
        cfg, SecretStr("tok-ATLASFAKE"), MemoryAudit(), transport=httpx.MockTransport(hook)
    )
    client = n._client()
    assert client._tls is not None and client._tls.public_pki  # host names always checked
    ok, msg = await n.send(Notification(kind="test", title="x"))
    assert ok, msg
    assert hook.requests[0].url.host == "n8n.example.net"
    # An https IP literal cannot use public CAs (no host name to check): refused.
    ip = WebhookNotifier(WebhookConfig("https://203.0.113.9/webhook/a"), None, MemoryAudit())
    ok, msg = await ip.send(Notification(kind="test", title="x"))
    assert not ok and "refused" in msg


@pytest.mark.parametrize(
    ("url", "host", "public"),
    [
        ("https://n8n.example.net", "other.example.net", True),  # not the URL's host
        ("https://203.0.113.9", "203.0.113.9", True),  # IP literal
        ("https://n8n.example.net", "n8n.example.net", False),  # no public-PKI policy
        ("https://localhost", "localhost", True),  # not a qualified DNS name
    ],
)
def test_public_pki_host_refusals(url: str, host: str, public: bool, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("x")
    tls = TlsPolicy(ca_file=None, public_pki=True) if public else TlsPolicy(ca_file=ca)
    with pytest.raises(SecurityRefusal):
        ReadOnlyHttpClient(
            target="n8n",
            base_url=url,
            endpoints=ENDPOINTS,
            audit=MemoryAudit(),
            tls=tls,
            public_pki_host=host,
        )


def test_public_pki_still_refused_for_unlisted_hosts() -> None:
    with pytest.raises(SecurityRefusal):
        ReadOnlyHttpClient(
            target="x",
            base_url="https://n8n.example.net",
            endpoints=ENDPOINTS,
            audit=MemoryAudit(),
            tls=TlsPolicy(ca_file=None, public_pki=True),
        )


async def test_notifier_refuses_public_http() -> None:
    public = WebhookNotifier(
        WebhookConfig("http://8.8.8.8/webhook/a", allow_http=True), None, MemoryAudit()
    )
    ok, msg = await public.send(Notification(kind="test", title="x"))
    assert not ok and "refused" in msg


@pytest.mark.parametrize(
    "url",
    [
        "ftp://10.0.0.5/webhook/a",
        "http://10.0.0.5:5678/rest/workflows",
        "http://user:pw@10.0.0.5/webhook/a",
        "http://10.0.0.5/webhook/a?x=1",
        "http://10.0.0.5/webhook/../admin",
    ],
)
def test_webhook_url_validation(url: str) -> None:
    with pytest.raises(ValueError):
        webhook_from_env({"ATLAS_N8N_WEBHOOK_URL": url})


def test_webhook_unset_means_off() -> None:
    assert webhook_from_env({}) is None
    cfg = webhook_from_env(
        {"ATLAS_N8N_WEBHOOK_URL": "http://10.0.0.5:5678/webhook/atlas", "ATLAS_N8N_ALLOW_HTTP": "1"}
    )
    assert cfg is not None and cfg.allow_http and cfg.path == "/webhook/atlas"


def test_notification_shape_is_closed() -> None:
    with pytest.raises(ValueError):
        Notification.model_validate({"kind": "test", "title": "x", "command": "rm -rf /"})
    with pytest.raises(ValueError):
        Notification(kind="restart.vm", title="x")  # type: ignore[arg-type]
