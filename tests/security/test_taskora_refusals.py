"""ADR-042 boundaries: atlas talks to Taskora only through registered, typed endpoints."""

import asyncio
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, SecretStr

from homelab_atlas.engine import taskora as tk
from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, TlsPolicy
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security
TOKEN = SecretStr("tki_ATLASFAKE0000000000000000000000000000000")


def _client(**kw: Any) -> ReadOnlyHttpClient:
    return ReadOnlyHttpClient(
        target="taskora",
        base_url=kw.pop("base_url", "https://taskora.example.test"),
        endpoints=tk.ENDPOINTS,
        audit=MemoryAudit(),
        tls=kw.pop("tls", TlsPolicy(ca_file=None, public_pki=True)),
        public_pki_host=kw.pop("public_pki_host", "taskora.example.test"),
        transport=httpx.MockTransport(kw.pop("handler", lambda _r: httpx.Response(200, json={}))),
        **kw,
    )


def _event(**kw: Any) -> tk.IncidentEvent:
    base: dict[str, Any] = {
        "instance": "atlas",
        "incidentId": 1,
        "revision": 1,
        "fingerprint": "x",
        "kind": "x",
        "title": "t",
        "severity": "warning",
        "state": "open",
        "firstObservedAt": "2026-11-03T00:00:00+00:00",
        "lastObservedAt": "2026-11-03T00:00:00+00:00",
    }
    return tk.IncidentEvent(**(base | kw))


@pytest.mark.parametrize(
    "key",
    ["../health", "atlas:1/../../x", "atlas:-1", "ATLAS:1", "atlas", "atlas:1;x", "a" * 70 + ":1"],
)
def test_incident_key_must_be_instance_colon_number(key: str) -> None:
    async def go() -> None:
        async with _client() as c:
            await c.post(tk.INCIDENT_PUT, _event(), {"key": key})

    with pytest.raises(SecurityRefusal) as exc:
        asyncio.run(go())
    assert exc.value.reason is RefusalReason.PATH_INVALID


def test_only_registered_endpoints_and_typed_bodies() -> None:
    other = Endpoint("taskora.users", "GET", "/api/v1/users")

    async def unregistered() -> None:
        async with _client() as c:
            await c.get(other)

    with pytest.raises(SecurityRefusal) as exc:
        asyncio.run(unregistered())
    assert exc.value.reason is RefusalReason.NOT_ALLOWLISTED

    class Other(BaseModel):
        x: int = 1

    async def wrong_body() -> None:
        async with _client() as c:
            await c.post(tk.INVENTORY, Other())

    with pytest.raises(SecurityRefusal) as exc:
        asyncio.run(wrong_body())
    assert exc.value.reason is RefusalReason.BODY_INVALID


def test_no_put_or_delete_endpoints_can_exist() -> None:
    for method in ("PUT", "DELETE", "PATCH"):
        with pytest.raises(ValueError, match="not allowed"):
            Endpoint("taskora.x", method, "/api/v1/x")  # type: ignore[arg-type]


def test_feed_query_is_numeric_only() -> None:
    async def go(q: dict[str, Any]) -> None:
        async with _client(handler=lambda _r: httpx.Response(200, json={"events": []})) as c:
            await c.get(tk.FEED, None, q)

    for bad in ({"after": "1 OR 1=1"}, {"after": "-1"}, {"cursor": "1"}, {"limit": "1000"}):
        with pytest.raises(SecurityRefusal) as exc:
            asyncio.run(go(bad))
        assert exc.value.reason is RefusalReason.QUERY_INVALID


def test_plain_http_only_to_a_lan_ip_when_allowed() -> None:
    with pytest.raises(SecurityRefusal):
        _client(base_url="http://taskora.example.test", tls=None, public_pki_host=None)
    with pytest.raises(SecurityRefusal):
        _client(base_url="http://8.8.8.8", tls=None, public_pki_host=None, plain_http_lan=True)
    with pytest.raises(SecurityRefusal):
        _client(
            base_url="http://127.0.0.1:3000", tls=None, public_pki_host=None, plain_http_lan=True
        )
    _client(base_url="http://10.0.0.5:8080", tls=None, public_pki_host=None, plain_http_lan=True)


def test_redirects_are_refused_and_reported_as_configuration() -> None:
    def redirect(_r: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://elsewhere.example/steal"})

    c = tk.TaskoraClient(
        tk.TaskoraSettings(url="https://taskora.example.test"),
        TOKEN,
        MemoryAudit(),
        transport=httpx.MockTransport(redirect),
    )
    with pytest.raises(tk.TaskoraError) as exc:
        asyncio.run(c.health())
    assert exc.value.kind == "config" and "redirect" in str(exc.value)


def test_missing_token_never_sends_anything() -> None:
    sent: list[httpx.Request] = []

    def record(r: httpx.Request) -> httpx.Response:
        sent.append(r)
        return httpx.Response(200, json={})

    c = tk.TaskoraClient(
        tk.TaskoraSettings(url="https://taskora.example.test"),
        None,
        MemoryAudit(),
        transport=httpx.MockTransport(record),
    )
    with pytest.raises(tk.TaskoraError) as exc:
        asyncio.run(c.health())
    assert exc.value.kind == "config" and sent == []


def test_a_server_that_is_not_taskora_is_rejected() -> None:
    c = tk.TaskoraClient(
        tk.TaskoraSettings(url="https://taskora.example.test"),
        TOKEN,
        MemoryAudit(),
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"ok": True})),
    )
    with pytest.raises(tk.TaskoraError, match="does not answer like Taskora"):
        asyncio.run(c.health())


def test_oversized_answers_are_refused() -> None:
    big = b"[" + b"0," * (3 * 1024 * 1024) + b"0]"
    c = tk.TaskoraClient(
        tk.TaskoraSettings(url="https://taskora.example.test"),
        TOKEN,
        MemoryAudit(),
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, content=big)),
    )
    with pytest.raises(tk.TaskoraError) as exc:
        asyncio.run(c.feed(0))
    assert exc.value.kind == "config" and "output_too_large" in str(exc.value)


def test_outgoing_text_is_redacted_again() -> None:
    from homelab_atlas.redact import Redactor  # noqa: PLC0415

    seen: list[bytes] = []

    def record(r: httpx.Request) -> httpx.Response:
        seen.append(r.content)
        return httpx.Response(200, json={"applied": True, "ticket": None})

    c = tk.TaskoraClient(
        tk.TaskoraSettings(url="https://taskora.example.test"),
        TOKEN,
        MemoryAudit(),
        redactor=Redactor(bytes(32)),
        transport=httpx.MockTransport(record),
    )
    leaked = "password=ATLASFAKEhunter2hunter2"
    asyncio.run(c.upsert(_event(title=f"db login {leaked}", evidence=[leaked])))
    assert b"ATLASFAKEhunter2" not in seen[0]


def test_payload_limits() -> None:
    with pytest.raises(ValueError):
        _event(evidence=["x"] * 21)
    with pytest.raises(ValueError):
        _event(title="x" * 251)
    with pytest.raises(ValueError):
        tk.InventorySync(instance="atlas", mode="apply", entities=[{}] * 501)
