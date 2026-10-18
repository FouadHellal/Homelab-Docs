"""Real TLS against a local asyncio server: anchor pinning, leaf pins, hostname checks."""

import asyncio
import hashlib
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import trustme

from homelab_atlas.security.allowlist import Endpoint
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient, TlsPolicy
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security

EP = Endpoint(id="v", method="GET", path_template="/version")
BODY = b'{"data":{"version":"9.2"}}'


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        await reader.readuntil(b"\r\n\r\n")
        writer.write(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            + f"Content-Length: {len(BODY)}\r\nConnection: close\r\n\r\n".encode()
            + BODY
        )
        await writer.drain()
    except (ConnectionError, asyncio.IncompleteReadError, ssl.SSLError):
        pass
    finally:
        writer.close()


class TlsServer:
    def __init__(self, cert: trustme.LeafCert, port: int, server: asyncio.Server) -> None:
        self.cert, self.port, self.server = cert, port, server

    @property
    def leaf_sha256(self) -> str:
        der = ssl.PEM_cert_to_DER_cert(self.cert.cert_chain_pems[0].bytes().decode())
        return hashlib.sha256(der).hexdigest()


@pytest.fixture
def ca() -> trustme.CA:
    return trustme.CA()


async def _serve(ca: trustme.CA, *names: str) -> TlsServer:
    cert = ca.issue_cert(*names)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    cert.configure_cert(ctx)
    server = await asyncio.start_server(_handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    return TlsServer(cert, port, server)


@pytest.fixture
async def srv(ca: trustme.CA) -> AsyncIterator[TlsServer]:
    s = await _serve(ca, "127.0.0.1", "localhost")
    yield s
    s.server.close()
    await s.server.wait_closed()


def _client(audit: MemoryAudit, port: int, tls: TlsPolicy) -> ReadOnlyHttpClient:
    return ReadOnlyHttpClient(
        target="pve", base_url=f"https://127.0.0.1:{port}", endpoints=(EP,), audit=audit, tls=tls
    )


def _pem(tmp_path: Path, name: str, data: bytes) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


async def test_trusted_ca_ok(
    srv: TlsServer, ca: trustme.CA, tmp_path: Path, audit: MemoryAudit
) -> None:
    tls = TlsPolicy(ca_file=_pem(tmp_path, "ca.pem", ca.cert_pem.bytes()))
    async with _client(audit, srv.port, tls) as c:
        r = await c.get(EP)
    assert r.json()["data"]["version"] == "9.2"


async def test_system_cas_not_loaded(ca: trustme.CA, tmp_path: Path) -> None:
    ctx = TlsPolicy(ca_file=_pem(tmp_path, "ca.pem", ca.cert_pem.bytes())).ssl_context()
    assert ctx.cert_store_stats()["x509_ca"] == 1
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.minimum_version >= ssl.TLSVersion.TLSv1_2


async def test_untrusted_ca_refused(srv: TlsServer, tmp_path: Path, audit: MemoryAudit) -> None:
    other = trustme.CA()
    tls = TlsPolicy(ca_file=_pem(tmp_path, "other.pem", other.cert_pem.bytes()))
    async with _client(audit, srv.port, tls) as c:
        with pytest.raises(SecurityRefusal) as exc:
            await c.get(EP)
    assert exc.value.reason is RefusalReason.TLS_POLICY
    assert audit.outcomes == ["refused"]


async def test_leaf_as_anchor_partial_chain(
    srv: TlsServer, tmp_path: Path, audit: MemoryAudit
) -> None:
    """A device's own (self-signed style) cert as the only trust anchor."""
    leaf = srv.cert.cert_chain_pems[0].bytes()
    tls = TlsPolicy(ca_file=_pem(tmp_path, "leaf.pem", leaf))
    async with _client(audit, srv.port, tls) as c:
        assert (await c.get(EP)).status == 200


async def test_leaf_pin_match(
    srv: TlsServer, ca: trustme.CA, tmp_path: Path, audit: MemoryAudit
) -> None:
    tls = TlsPolicy(
        ca_file=_pem(tmp_path, "ca.pem", ca.cert_pem.bytes()), sha256_pin=srv.leaf_sha256
    )
    async with _client(audit, srv.port, tls) as c:
        assert (await c.get(EP)).status == 200


async def test_leaf_pin_mismatch(
    srv: TlsServer, ca: trustme.CA, tmp_path: Path, audit: MemoryAudit
) -> None:
    tls = TlsPolicy(ca_file=_pem(tmp_path, "ca.pem", ca.cert_pem.bytes()), sha256_pin="0" * 64)
    async with _client(audit, srv.port, tls) as c:
        with pytest.raises(SecurityRefusal) as exc:
            await c.get(EP)
    assert exc.value.reason is RefusalReason.TLS_PIN_MISMATCH


async def test_hostname_mismatch(ca: trustme.CA, tmp_path: Path, audit: MemoryAudit) -> None:
    s = await _serve(ca, "pve.test")
    try:
        anchor = _pem(tmp_path, "ca.pem", ca.cert_pem.bytes())
        async with _client(audit, s.port, TlsPolicy(ca_file=anchor)) as c:
            with pytest.raises(SecurityRefusal) as exc:
                await c.get(EP)
        assert exc.value.reason is RefusalReason.TLS_POLICY
        # Pinned anchor without hostname check (UniFi self-signed certs with no IP SAN).
        async with _client(audit, s.port, TlsPolicy(ca_file=anchor, check_hostname=False)) as c:
            assert (await c.get(EP)).status == 200
    finally:
        s.server.close()
        await s.server.wait_closed()
