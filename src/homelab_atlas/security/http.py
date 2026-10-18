"""Read-only HTTP client: the single choke point for every API call (ADR-008).

Only `Endpoint` objects registered with the client can be requested. GET is the default.
POST exists only for registered, schema-checked, justified endpoints (e.g. a session login).
Callers cannot set headers, methods, URLs or redirects.
"""

import hashlib
import hmac
import json
import re
import ssl
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Final, Literal, Self, cast
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, SecretStr

from homelab_atlas import __version__
from homelab_atlas.security.allowlist import (
    DENIED_SEGMENTS,
    SAFE_QUERY_VALUE_RE,
    SAFE_VALUE_RE,
    Endpoint,
    validate_endpoint,
)
from homelab_atlas.security.audit import AuditEvent, AuditSink, Outcome
from homelab_atlas.security.errors import (
    HttpStatusError,
    RefusalReason,
    SecurityRefusal,
    TargetTimeout,
    TransportError,
)

FINAL_PATH_RE: Final = re.compile(r"(/[A-Za-z0-9._:@-]+)+")
BASE_PATH_RE: Final = re.compile(r"(/[A-Za-z0-9._-]+)*")
AUTH_HEADER_NAMES: Final = frozenset({"X-API-KEY", "Authorization"})
#: Headers that must never appear on a request (method override and friends).
FORBIDDEN_HEADERS: Final = frozenset(
    {"x-http-method-override", "x-http-method", "x-method-override", "x-original-method"}
)
MAX_SEGMENTS: Final = 32


@dataclass(frozen=True, slots=True)
class TlsPolicy:
    """Trust exactly the given anchor(s): a private CA or the device's self-signed leaf.

    System CAs are never loaded. `check_hostname=False` is allowed only because the trust
    store is a pinned anchor, not the public PKI. `sha256_pin` is an optional extra leaf pin.
    """

    ca_file: Path
    check_hostname: bool = True
    sha256_pin: str | None = None

    def __post_init__(self) -> None:
        if self.sha256_pin is not None and not re.fullmatch(r"[0-9a-f]{64}", self.sha256_pin):
            raise SecurityRefusal(RefusalReason.TLS_POLICY, "sha256_pin must be 64 lowercase hex")

    def ssl_context(self) -> ssl.SSLContext:
        if not self.ca_file.is_file():
            raise SecurityRefusal(RefusalReason.TLS_POLICY, "CA/anchor file missing")
        ctx = ssl.create_default_context(cafile=str(self.ca_file))
        ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
        ctx.check_hostname = self.check_hostname
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx


@dataclass(frozen=True, slots=True)
class AuthHeader:
    name: Literal["X-API-KEY", "Authorization"]
    value: SecretStr

    def __post_init__(self) -> None:
        if self.name not in AUTH_HEADER_NAMES:
            raise SecurityRefusal(RefusalReason.CONFIG, "unsupported auth header")
        if any(c in self.value.get_secret_value() for c in "\r\n\x00"):
            raise SecurityRefusal(RefusalReason.CONFIG, "auth header value has control chars")


@dataclass(frozen=True, slots=True)
class HttpLimits:
    connect_s: float = 5.0
    read_s: float = 20.0
    total_s: float = 60.0
    max_bytes: int = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    content_type: str
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


def _dump_body(model: BaseModel) -> dict[str, Any]:
    """Serialize a POST body, unwrapping top-level SecretStr fields at the last moment."""
    out: dict[str, Any] = {}
    for name, value in model:
        if isinstance(value, SecretStr):
            out[name] = value.get_secret_value()
        elif isinstance(value, BaseModel):
            out[name] = value.model_dump(mode="json")
        else:
            out[name] = value
    return out


class ReadOnlyHttpClient:
    def __init__(
        self,
        *,
        target: str,
        base_url: str,
        endpoints: Iterable[Endpoint],
        audit: AuditSink,
        tls: TlsPolicy | None,
        auth: AuthHeader | None = None,
        limits: HttpLimits | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._target = target
        self._audit = audit
        self._limits = limits or HttpLimits()
        self._tls = tls
        self._auth = auth
        self._allowed: frozenset[Endpoint] = frozenset(endpoints)
        for ep in self._allowed:
            validate_endpoint(ep)
        url = httpx.URL(base_url)
        raw_path = urlsplit(base_url).path.rstrip("/")  # before httpx normalises dot-segments
        if (
            not BASE_PATH_RE.fullmatch(raw_path)
            or any(s in {".", ".."} for s in raw_path.split("/"))
            or url.scheme != "https"
            or not url.host
            or url.userinfo
            or url.query
            or url.fragment
            or not BASE_PATH_RE.fullmatch(url.path.rstrip("/"))
        ):
            raise SecurityRefusal(RefusalReason.CONFIG, "base_url must be https://host[:port][/p]")
        self._scheme, self._host, self._port = url.scheme, url.host, url.port
        self._base_path = url.path.rstrip("/")
        if transport is None and tls is None:
            raise SecurityRefusal(RefusalReason.TLS_POLICY, "a TlsPolicy is required")
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "User-Agent": f"homelab-atlas/{__version__}",
        }
        if auth is not None:
            headers[auth.name] = auth.value.get_secret_value()
        self._client = httpx.AsyncClient(
            base_url=f"{url.scheme}://{url.netloc.decode('ascii')}",
            headers=headers,
            verify=tls.ssl_context() if tls is not None else True,
            transport=transport,
            follow_redirects=False,
            trust_env=False,  # ignore HTTP(S)_PROXY, SSL_CERT_FILE, .netrc
            timeout=httpx.Timeout(
                self._limits.read_s, connect=self._limits.connect_s, pool=self._limits.connect_s
            ),
            max_redirects=0,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ public API

    async def get(
        self,
        endpoint: Endpoint,
        path_vars: Mapping[str, str] | None = None,
        query: Mapping[str, str | int | bool] | None = None,
    ) -> HttpResult:
        return await self._call("GET", endpoint, path_vars, query, None)

    async def post(
        self,
        endpoint: Endpoint,
        body: BaseModel,
        path_vars: Mapping[str, str] | None = None,
    ) -> HttpResult:
        return await self._call("POST", endpoint, path_vars, None, body)

    # ------------------------------------------------------------------ internals

    async def _call(
        self,
        method: str,
        endpoint: Endpoint,
        path_vars: Mapping[str, str] | None,
        query: Mapping[str, str | int | bool] | None,
        body: BaseModel | None,
    ) -> HttpResult:
        # Runtime type checks below are deliberate: callers may not respect the hints.
        op = endpoint.op if isinstance(cast(object, endpoint), Endpoint) else "<invalid>"
        start = time.monotonic()
        try:
            request = self._prepare(method, endpoint, path_vars or {}, query or {}, body)
        except SecurityRefusal as exc:
            self._record(op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        try:
            result = await self._send(request, op)
        except SecurityRefusal as exc:
            self._record(op, "refused", start, reason=exc.reason.value, detail=exc.detail)
            raise
        except HttpStatusError as exc:
            self._record(op, "error", start, status=exc.status, reason="http_status")
            raise
        except TransportError as exc:
            self._record(op, "error", start, reason=type(exc).__name__)
            raise
        self._record(op, "ok", start, status=result.status, nbytes=len(result.body))
        return result

    def _prepare(
        self,
        method: str,
        ep: Endpoint,
        path_vars: Mapping[str, str],
        query: Mapping[str, str | int | bool],
        body: BaseModel | None,
    ) -> httpx.Request:
        if type(ep) is not Endpoint:
            raise SecurityRefusal(RefusalReason.BAD_TYPE, "endpoint must be an Endpoint")
        try:
            validate_endpoint(ep)  # catches post-registration mutation
        except ValueError as exc:
            raise SecurityRefusal(RefusalReason.NOT_ALLOWLISTED, str(exc)) from None
        if ep not in self._allowed:
            raise SecurityRefusal(RefusalReason.NOT_ALLOWLISTED, f"{ep.id} not registered")
        if ep.method != method:
            raise SecurityRefusal(RefusalReason.METHOD_FORBIDDEN, f"{ep.id} is {ep.method}")

        path = self._expand_path(ep, path_vars)
        params = self._check_query(ep, query)

        json_body: dict[str, Any] | None = None
        if method == "POST":
            if ep.body_model is None or type(body) is not ep.body_model:
                raise SecurityRefusal(RefusalReason.BODY_INVALID, f"{ep.id}: wrong body type")
            json_body = _dump_body(body)
        elif body is not None:
            raise SecurityRefusal(RefusalReason.BODY_INVALID, "GET with a body")

        request = self._client.build_request(method, path, params=params, json=json_body)
        # Re-parse what httpx will actually send and compare to what we meant to send.
        u = request.url
        if (
            u.scheme != self._scheme
            or u.host != self._host
            or u.port != self._port
            or u.path != path
            or u.raw_path.split(b"?", 1)[0] != path.encode("ascii")
            or u.userinfo
            or u.fragment
        ):
            raise SecurityRefusal(RefusalReason.PATH_INVALID, f"{ep.id}: URL canonicalisation")
        if FORBIDDEN_HEADERS & {k.lower() for k in request.headers}:
            raise SecurityRefusal(RefusalReason.METHOD_FORBIDDEN, "method override header")
        if request.method != ep.method:
            raise SecurityRefusal(RefusalReason.METHOD_FORBIDDEN, "method mismatch")
        return request

    def _expand_path(self, ep: Endpoint, path_vars: Mapping[str, str]) -> str:
        if not isinstance(cast(object, path_vars), Mapping) or set(path_vars) != set(ep.path_vars):
            raise SecurityRefusal(RefusalReason.PATH_INVALID, f"{ep.id}: path vars mismatch")
        segments: list[str] = []
        for template_seg in ep.path_template[1:].split("/"):
            seg = template_seg
            if template_seg.startswith("{"):
                name = template_seg[1:-1]
                value = path_vars[name]
                if (
                    type(value) is not str
                    or not SAFE_VALUE_RE.fullmatch(value)
                    or ".." in value
                    or not re.fullmatch(ep.path_vars[name], value)
                ):
                    raise SecurityRefusal(RefusalReason.PATH_INVALID, f"{ep.id}: bad {name}")
                seg = value
            if seg.lower() in DENIED_SEGMENTS:
                raise SecurityRefusal(RefusalReason.PATH_DENIED, f"{ep.id}: denied segment")
            segments.append(seg)
        path = self._base_path + "/" + "/".join(segments)
        if (
            not FINAL_PATH_RE.fullmatch(path)
            or len(segments) > MAX_SEGMENTS
            or any(s in {".", ".."} for s in path.split("/"))
        ):
            raise SecurityRefusal(RefusalReason.PATH_INVALID, f"{ep.id}: final path invalid")
        return path

    @staticmethod
    def _check_query(ep: Endpoint, query: Mapping[str, str | int | bool]) -> dict[str, str]:
        if not isinstance(query, Mapping):
            raise SecurityRefusal(RefusalReason.QUERY_INVALID, "query must be a mapping")
        out: dict[str, str] = {}
        for key, raw in query.items():
            if type(key) is not str or key not in ep.query:
                raise SecurityRefusal(RefusalReason.QUERY_INVALID, f"{ep.id}: key not allowed")
            if type(raw) is bool:
                value = "true" if raw else "false"
            elif type(raw) is int:
                value = str(raw)
            elif type(raw) is str:
                value = raw
            else:
                raise SecurityRefusal(RefusalReason.QUERY_INVALID, f"{ep.id}: bad value type")
            if not SAFE_QUERY_VALUE_RE.fullmatch(value) or not re.fullmatch(ep.query[key], value):
                raise SecurityRefusal(RefusalReason.QUERY_INVALID, f"{ep.id}: bad value for {key}")
            out[key] = value
        return out

    async def _send(self, request: httpx.Request, op: str) -> HttpResult:
        try:
            response = await self._client.send(request, stream=True, follow_redirects=False)
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"{op}: timeout") from exc
        except httpx.HTTPError as exc:
            if isinstance(exc.__cause__, ssl.SSLError) or "CERTIFICATE" in str(exc).upper():
                raise SecurityRefusal(RefusalReason.TLS_POLICY, "TLS verification failed") from None
            raise TransportError(f"{op}: {type(exc).__name__}") from None
        try:
            self._check_pin(response)
            if 300 <= response.status_code < 400:
                raise SecurityRefusal(RefusalReason.REDIRECT, f"redirect {response.status_code}")
            declared = response.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > self._limits.max_bytes:
                raise SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, "content-length over cap")
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > self._limits.max_bytes:
                    raise SecurityRefusal(RefusalReason.OUTPUT_TOO_LARGE, "body over cap")
                chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise TargetTimeout(f"{op}: read timeout") from exc
        finally:
            await response.aclose()
        if not 200 <= response.status_code < 300:
            raise HttpStatusError(response.status_code, op)
        return HttpResult(
            status=response.status_code,
            content_type=response.headers.get("content-type", ""),
            body=b"".join(chunks),
        )

    def _check_pin(self, response: httpx.Response) -> None:
        if self._tls is None or self._tls.sha256_pin is None:
            return
        stream = response.extensions.get("network_stream")
        ssl_object = stream.get_extra_info("ssl_object") if stream is not None else None
        der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        if not der:
            raise SecurityRefusal(RefusalReason.TLS_PIN_MISMATCH, "peer certificate unavailable")
        actual = hashlib.sha256(der).hexdigest()
        if not hmac.compare_digest(actual, self._tls.sha256_pin):
            raise SecurityRefusal(RefusalReason.TLS_PIN_MISMATCH, "leaf certificate pin mismatch")

    def _record(
        self,
        op: str,
        outcome: Outcome,
        start: float,
        *,
        status: int | None = None,
        nbytes: int = 0,
        reason: str | None = None,
        detail: str | None = None,
    ) -> None:
        self._audit.record(
            AuditEvent(
                target=self._target,
                transport="http",
                op=op,
                outcome=outcome,
                status=status,
                duration_ms=int((time.monotonic() - start) * 1000),
                bytes=nbytes,
                reason=reason,
                detail=detail,
            )
        )
