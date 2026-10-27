"""ReadOnlyHttpClient: refusals, path tricks, redirects, caps, headers, audit."""

import asyncio
import dataclasses
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import BaseModel, SecretStr

from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.errors import (
    HttpStatusError,
    RefusalReason,
    SecurityRefusal,
    TargetTimeout,
)
from homelab_atlas.security.http import AuthHeader, HttpLimits, ReadOnlyHttpClient, TlsPolicy
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security

NODE = r"[a-z0-9-]{1,32}"
TOKEN = "PVEAPIToken=atlas@pve!collector=ATLASFAKE-0000-0000-0000-000000000000"

EP_QEMU = Endpoint(
    id="pve.qemu.list",
    method="GET",
    path_template="/nodes/{node}/qemu",
    path_vars={"node": NODE},
    query={"full": r"0|1"},
)
EP_CONFIG = Endpoint(
    id="pve.qemu.config",
    method="GET",
    path_template="/nodes/{node}/qemu/{vmid}/config",
    path_vars={"node": NODE, "vmid": r"\d{1,9}"},
)


class LoginBody(BaseModel):
    username: str
    password: SecretStr


EP_LOGIN = Endpoint(
    id="unifi.classic.login",
    method="POST",
    path_template="/api/auth/login",
    body_model=LoginBody,
    read_only_justification="session login, no configuration change",
)
EP_UNREGISTERED = Endpoint(id="pve.nodes", method="GET", path_template="/nodes")

Handler = Callable[[httpx.Request], httpx.Response]


class Recorder:
    def __init__(self, handler: Handler | None = None) -> None:
        self.requests: list[httpx.Request] = []
        self._handler = handler or (lambda _r: httpx.Response(200, json={"data": []}))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)


def make_client(
    audit: MemoryAudit,
    recorder: Recorder,
    *,
    endpoints: tuple[Endpoint, ...] = (EP_QEMU, EP_CONFIG, EP_LOGIN),
    limits: HttpLimits | None = None,
) -> ReadOnlyHttpClient:
    return ReadOnlyHttpClient(
        target="pve",
        base_url="https://pve.test:8006/api2/json",
        endpoints=endpoints,
        audit=audit,
        tls=None,
        auth=AuthHeader("Authorization", SecretStr(TOKEN)),
        limits=limits,
        transport=httpx.MockTransport(recorder),
    )


# --------------------------------------------------------------------------- happy path


async def test_get_ok_and_audited(audit: MemoryAudit) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as client:
        result = await client.get(EP_QEMU, {"node": "pve1"}, {"full": 1})
    assert result.json() == {"data": []}
    (req,) = rec.requests
    assert req.method == "GET"
    assert req.url.raw_path == b"/api2/json/nodes/pve1/qemu?full=1"
    assert {k.lower() for k in req.headers} <= {
        "host", "accept", "accept-encoding", "user-agent", "authorization", "connection",
    }  # fmt: skip
    assert req.headers["accept-encoding"] == "identity"
    (event,) = audit.events
    assert (event.outcome, event.op, event.status) == ("ok", "GET /nodes/{node}/qemu", 200)
    dumped = event.model_dump_json()
    assert "pve1" not in dumped
    assert "ATLASFAKE" not in dumped


async def test_post_registered_login(audit: MemoryAudit) -> None:
    rec = Recorder()
    body = LoginBody(username="atlas-ro", password=SecretStr("pw-ATLASFAKE"))
    async with make_client(audit, rec) as client:
        await client.post(EP_LOGIN, body)
    (req,) = rec.requests
    assert req.method == "POST"
    assert json.loads(req.content) == {"username": "atlas-ro", "password": "pw-ATLASFAKE"}
    assert "ATLASFAKE" not in audit.events[0].model_dump_json()


# --------------------------------------------------------------------------- endpoint definition


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "get", "GET "])
def test_endpoint_methods_rejected(method: str) -> None:
    with pytest.raises(ValueError, match="method"):
        Endpoint(id="x", method=method, path_template="/x")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "template",
    [
        "nodes",
        "/nodes/",
        "//nodes",
        "/a//b",
        "/a/../b",
        "/a/./b",
        "/a/%2e%2e/b",
        "/a;b",
        "/a\\b",
        "/a b",
        "/ünï",
        "/a?x=1",
        "/a#f",
        "/nodes/{node}/qemu/{vmid}/status/start",
        "/sites/{site}/devices/{id}/actions",
        "/sites/{site}/devices/{id}/Actions",
        "/nodes/{node}/qemu/{vmid}/agent/exec",
        "/nodes/{node}/qemu/{vmid}/agent/file-write",
        "/nodes/{node}/termproxy",
        "/nodes/{node}/{Node}",
        "/x/{}",
        "/x/{a-b}",
        "/x/{a}{b}",
    ],
)
def test_endpoint_templates_rejected(template: str) -> None:
    with pytest.raises(ValueError):
        Endpoint(id="x", method="GET", path_template=template, path_vars={"node": NODE})


def test_endpoint_var_mismatch_and_post_rules() -> None:
    with pytest.raises(ValueError, match="path_vars"):
        Endpoint(id="x", method="GET", path_template="/n/{node}")
    with pytest.raises(ValueError, match="path_vars"):
        Endpoint(id="x", method="GET", path_template="/n", path_vars={"node": NODE})
    with pytest.raises(ValueError, match="duplicate"):
        Endpoint(id="x", method="GET", path_template="/n/{a}/{a}", path_vars={"a": NODE})
    with pytest.raises(ValueError, match="POST"):
        Endpoint(id="x", method="POST", path_template="/login", body_model=LoginBody)
    with pytest.raises(ValueError, match="POST"):
        Endpoint(id="x", method="POST", path_template="/login", read_only_justification="x")
    with pytest.raises(ValueError, match="body"):
        Endpoint(id="x", method="GET", path_template="/login", body_model=LoginBody)
    with pytest.raises(ValueError, match="query key"):
        Endpoint(id="x", method="GET", path_template="/n", query={"a&b": ".*"})


def test_endpoint_mappings_frozen() -> None:
    src = {"node": NODE}
    ep = Endpoint(id="x", method="GET", path_template="/n/{node}", path_vars=src)
    src["node"] = ".*"
    assert ep.path_vars["node"] == NODE
    with pytest.raises(TypeError):
        ep.path_vars["node"] = ".*"  # type: ignore[index]


# --------------------------------------------------------------------------- allowlist bypasses


async def _expect_refusal(
    audit: MemoryAudit, rec: Recorder, coro: Any, reason: RefusalReason | None = None
) -> SecurityRefusal:
    with pytest.raises(SecurityRefusal) as exc:
        await coro
    assert rec.requests == [], "transport must not be reached"
    assert audit.outcomes[-1] == "refused"
    if reason is not None:
        assert exc.value.reason is reason
    return exc.value


async def test_unregistered_endpoint(audit: MemoryAudit) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(EP_UNREGISTERED), RefusalReason.NOT_ALLOWLISTED)


async def test_lookalike_endpoint_not_registered(audit: MemoryAudit) -> None:
    rec = Recorder()
    twin = dataclasses.replace(EP_QEMU, path_template="/nodes/{node}/lxc")
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(twin, {"node": "pve1"}))


async def test_mutated_endpoint_after_registration(audit: MemoryAudit) -> None:
    rec = Recorder()
    ep = Endpoint(
        id="m", method="GET", path_template="/nodes/{node}/qemu", path_vars={"node": NODE}
    )
    async with make_client(audit, rec, endpoints=(ep,)) as c:
        object.__setattr__(ep, "path_template", "/nodes/{node}/lxc")
        await _expect_refusal(audit, rec, c.get(ep, {"node": "pve1"}))
        object.__setattr__(ep, "path_template", "/nodes/{node}/qemu/start")
        await _expect_refusal(audit, rec, c.get(ep, {"node": "pve1"}))
        object.__setattr__(ep, "path_template", "/nodes/{node}/qemu")
        object.__setattr__(ep, "method", "DELETE")
        await _expect_refusal(audit, rec, c.get(ep, {"node": "pve1"}))


async def test_endpoint_subclass_and_duck_type(audit: MemoryAudit) -> None:
    @dataclasses.dataclass(frozen=True, slots=True)
    class Sub(Endpoint):
        pass

    sub = Sub(id="pve.qemu.list", method="GET", path_template="/nodes/{node}/qemu",
              path_vars={"node": NODE}, query={"full": r"0|1"})  # fmt: skip
    duck = type("Duck", (), {"id": "d", "method": "GET", "path_template": "/nodes", "op": "x"})()
    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(sub, {"node": "pve1"}), RefusalReason.BAD_TYPE)
        await _expect_refusal(audit, rec, c.get(duck), RefusalReason.BAD_TYPE)


async def test_method_mismatch(audit: MemoryAudit) -> None:
    rec = Recorder()
    body = LoginBody(username="u", password=SecretStr("p"))
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(EP_LOGIN), RefusalReason.METHOD_FORBIDDEN)
        await _expect_refusal(
            audit, rec, c.post(EP_QEMU, body, {"node": "pve1"}), RefusalReason.METHOD_FORBIDDEN
        )


async def test_post_wrong_body(audit: MemoryAudit) -> None:
    class Other(BaseModel):
        username: str
        password: SecretStr
        admin: bool = True

    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(
            audit,
            rec,
            c.post(EP_LOGIN, Other(username="u", password=SecretStr("p"))),
            RefusalReason.BODY_INVALID,
        )


PATH_TRICKS = [
    "..", ".", "...", "%2e%2e", "%252e%252e", "%2E%2E", "a/b", "a%2Fb", "a%2fb", "a\\b", "a;b",
    "a;jsessionid=1", "a?x", "a#x", "a&b", "．．", "․․", "pve1\x00", "%00",
    "", " ", "pve1 ", " pve1", "pve1\n", "pve1\r\nX-HTTP-Method-Override: DELETE",
    "../../access/users", "pve1/../..", "pve1/..", "-pve1", "pvе1", "PVE1", "start", "actions",
    "exec", "a" * 33, "pve1%20", "~pve1", "pve1@evil", "pve1:8006",
]  # fmt: skip


@pytest.mark.parametrize("value", PATH_TRICKS)
async def test_path_var_tricks(audit: MemoryAudit, value: str) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as c:
        err = await _expect_refusal(audit, rec, c.get(EP_QEMU, {"node": value}))
    assert err.reason in {RefusalReason.PATH_INVALID, RefusalReason.PATH_DENIED}


async def test_denied_segment_via_value_even_if_regex_allows(audit: MemoryAudit) -> None:
    rec = Recorder()
    loose = Endpoint(id="loose", method="GET", path_template="/n/{x}", path_vars={"x": ".*"})
    async with make_client(audit, rec, endpoints=(loose,)) as c:
        for v in ("start", "Actions", "termproxy"):
            await _expect_refusal(audit, rec, c.get(loose, {"x": v}), RefusalReason.PATH_DENIED)
        await _expect_refusal(audit, rec, c.get(loose, {"x": "a/b"}), RefusalReason.PATH_INVALID)


class EvilStr(str):
    def __eq__(self, other: object) -> bool:
        return True

    __hash__ = str.__hash__


@pytest.mark.parametrize("value", [1, None, b"pve1", ["pve1"], EvilStr("pve1"), 1.5])
async def test_path_var_types(audit: MemoryAudit, value: object) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(EP_QEMU, {"node": value}))  # type: ignore[dict-item]


@pytest.mark.parametrize(
    "path_vars", [{}, {"node": "pve1", "extra": "x"}, {"nodes": "pve1"}, ["node"], "node"]
)
async def test_path_var_set_mismatch(audit: MemoryAudit, path_vars: Any) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(audit, rec, c.get(EP_QEMU, path_vars))


@pytest.mark.parametrize(
    "query",
    [
        {"fulls": 1},
        {"full": 2},
        {"full": "1&delete=1"},
        {"full": "1#"},
        {"full": "1\n"},
        {"full": 1.0},
        {"full": [1]},
        {"full": None},
        {1: 1},
        {"Full": 1},
    ],
)
async def test_query_refusals(audit: MemoryAudit, query: Any) -> None:
    rec = Recorder()
    async with make_client(audit, rec) as c:
        await _expect_refusal(
            audit, rec, c.get(EP_QEMU, {"node": "pve1"}, query), RefusalReason.QUERY_INVALID
        )


async def test_query_bool_and_no_override_headers(audit: MemoryAudit) -> None:
    ep = Endpoint(id="b", method="GET", path_template="/b", query={"full": "true|false"})
    rec = Recorder()
    async with make_client(audit, rec, endpoints=(ep,)) as c:
        await c.get(ep, query={"full": True})
    (req,) = rec.requests
    assert req.url.params["full"] == "true"
    assert not {"x-http-method-override", "x-http-method", "x-method-override"} & {
        k.lower() for k in req.headers
    }


# --------------------------------------------------------------------------- responses


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_redirects_refused(audit: MemoryAudit, status: int) -> None:
    rec = Recorder(lambda _r: httpx.Response(status, headers={"Location": "https://evil.test/x"}))
    async with make_client(audit, rec) as c:
        with pytest.raises(SecurityRefusal) as exc:
            await c.get(EP_QEMU, {"node": "pve1"})
    assert exc.value.reason is RefusalReason.REDIRECT
    assert len(rec.requests) == 1
    assert audit.outcomes == ["refused"]


async def test_oversize_declared(audit: MemoryAudit) -> None:
    rec = Recorder(lambda _r: httpx.Response(200, content=b"x" * 2048))
    async with make_client(audit, rec, limits=HttpLimits(max_bytes=1024)) as c:
        with pytest.raises(SecurityRefusal) as exc:
            await c.get(EP_QEMU, {"node": "pve1"})
    assert exc.value.reason is RefusalReason.OUTPUT_TOO_LARGE


async def test_oversize_streamed_without_length(audit: MemoryAudit) -> None:
    async def chunks() -> Any:
        for _ in range(64):
            yield b"y" * 512

    rec = Recorder(lambda _r: httpx.Response(200, content=chunks()))
    async with make_client(audit, rec, limits=HttpLimits(max_bytes=4096)) as c:
        with pytest.raises(SecurityRefusal) as exc:
            await c.get(EP_QEMU, {"node": "pve1"})
    assert exc.value.reason is RefusalReason.OUTPUT_TOO_LARGE


async def test_http_error_status_has_no_body(audit: MemoryAudit) -> None:
    rec = Recorder(lambda _r: httpx.Response(403, text="secret-body-ATLASFAKE"))
    async with make_client(audit, rec) as c:
        with pytest.raises(HttpStatusError) as exc:
            await c.get(EP_QEMU, {"node": "pve1"})
    assert exc.value.status == 403
    assert "ATLASFAKE" not in str(exc.value)
    assert audit.events[-1].outcome == "error"


async def test_timeout_mapped(audit: MemoryAudit) -> None:
    def boom(_r: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow")

    rec = Recorder(boom)
    async with make_client(audit, rec) as c:
        with pytest.raises(TargetTimeout):
            await c.get(EP_QEMU, {"node": "pve1"})
    assert audit.events[-1].reason == "TargetTimeout"


async def test_total_time_cap_stops_a_slow_drip(audit: MemoryAudit) -> None:
    async def drip() -> Any:
        for _ in range(1000):
            await asyncio.sleep(0.01)  # each read is quick; the whole body is not
            yield b"y"

    rec = Recorder(lambda _r: httpx.Response(200, content=drip()))
    async with make_client(audit, rec, limits=HttpLimits(total_s=0.2)) as c:
        with pytest.raises(TargetTimeout):
            await c.get(EP_QEMU, {"node": "pve1"})
    assert audit.events[-1].outcome == "error"
    assert audit.events[-1].reason == "TargetTimeout"


# --------------------------------------------------------------------------- construction


@pytest.mark.parametrize(
    "url",
    [
        "http://pve.test:8006/api2/json",
        "https://user:pw@pve.test/api2/json",
        "https://pve.test/api2/json?x=1",
        "https://pve.test/api2/json#f",
        "https:///api2/json",
        "https://pve.test/api2/../json",
        "https://pve.test/api 2",
        "ftp://pve.test/",
    ],
)
def test_bad_base_url(audit: MemoryAudit, url: str) -> None:
    with pytest.raises(SecurityRefusal) as exc:
        ReadOnlyHttpClient(
            target="t", base_url=url, endpoints=(), audit=audit, tls=None,
            transport=httpx.MockTransport(Recorder()),
        )  # fmt: skip
    assert exc.value.reason is RefusalReason.CONFIG


def test_tls_policy_required_for_real_transport(audit: MemoryAudit) -> None:
    with pytest.raises(SecurityRefusal) as exc:
        ReadOnlyHttpClient(
            target="t", base_url="https://pve.test", endpoints=(), audit=audit, tls=None
        )
    assert exc.value.reason is RefusalReason.TLS_POLICY


def test_tls_policy_validation(tmp_path: Path) -> None:
    with pytest.raises(SecurityRefusal):
        TlsPolicy(ca_file=tmp_path / "ca.pem", sha256_pin="ABC")
    with pytest.raises(SecurityRefusal):
        TlsPolicy(ca_file=tmp_path / "missing.pem").ssl_context()


@pytest.mark.parametrize("value", ["tok\r\nX-HTTP-Method-Override: DELETE", "tok\n", "a\x00"])
def test_auth_header_injection(value: str) -> None:
    with pytest.raises(SecurityRefusal):
        AuthHeader("X-API-KEY", SecretStr(value))


def test_auth_header_name_allowlist() -> None:
    with pytest.raises(SecurityRefusal):
        AuthHeader("X-HTTP-Method-Override", SecretStr("DELETE"))  # type: ignore[arg-type]


async def test_env_proxies_ignored(audit: MemoryAudit, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://evil.test:3128")
    monkeypatch.setenv("SSL_CERT_FILE", "/nonexistent")
    rec = Recorder()
    async with make_client(audit, rec) as c:
        assert c._client.trust_env is False
        await c.get(EP_QEMU, {"node": "pve1"})
    assert rec.requests[0].url.host == "pve.test"
