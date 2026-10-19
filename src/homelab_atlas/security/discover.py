"""Identity discovery for onboarding from the UI (ADR-025): fetch, show, let the owner pin.

Both helpers only *read* the identity a server presents during the handshake. Nothing is
authenticated and no command or request is sent. The result is never trusted
automatically: the UI shows the fingerprint and the owner confirms it (ideally against the
target's console) before it is pinned. Every fetch is audited.
"""

import asyncio
import hashlib
import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import asyncssh

from homelab_atlas.security.audit import AuditEvent, AuditSink, Outcome
from homelab_atlas.security.errors import RefusalReason, SecurityRefusal, TransportError
from homelab_atlas.security.ssh import HOST_KEY_ALGS, HOST_RE, TARGET_NAME_RE

TIMEOUT_S = 10.0


@dataclass(frozen=True, slots=True)
class HostKey:
    line: str  # "ssh-ed25519 AAAA..."
    fingerprint: str  # "SHA256:..."


@dataclass(frozen=True, slots=True)
class PeerCertificate:
    pem: str
    sha256: str  # hex of the DER certificate, the form `tls.sha256_pin` takes
    subject: str


def _record(audit: AuditSink, target: str, transport: str, op: str, outcome: Outcome,  # noqa: PLR0917
            start: float, reason: str | None = None) -> None:  # fmt: skip
    audit.record(
        AuditEvent(
            target=target if TARGET_NAME_RE.fullmatch(target) else "<onboarding>",
            transport="ssh" if transport == "ssh" else "http",
            op=op,
            outcome=outcome,
            duration_ms=int((time.monotonic() - start) * 1000),
            reason=reason,
        )
    )


def _check_host(host: str, port: int) -> None:
    if not HOST_RE.fullmatch(host) or not 1 <= port <= 65535:
        raise SecurityRefusal(RefusalReason.CONFIG, "bad host or port")


async def fetch_host_key(name: str, host: str, port: int, audit: AuditSink) -> HostKey:
    """The server's ed25519 (else ECDSA P-256) host key, without authenticating."""
    _check_host(host, port)
    start = time.monotonic()
    for alg in sorted(HOST_KEY_ALGS, key=lambda a: a != "ssh-ed25519"):
        try:
            async with asyncio.timeout(TIMEOUT_S):
                key = await asyncssh.get_server_host_key(
                    host, port, server_host_key_algs=[alg], config=None
                )
        except TimeoutError:
            _record(audit, name, "ssh", "fetch-host-key", "error", start, "timeout")
            raise TransportError(f"{name}: timeout") from None
        except asyncssh.KeyExchangeFailed:
            continue  # server has no key of this type
        except (OSError, asyncssh.Error) as exc:
            _record(audit, name, "ssh", "fetch-host-key", "error", start, type(exc).__name__)
            raise TransportError(f"{name}: {type(exc).__name__}") from None
        if key is not None:
            _record(audit, name, "ssh", "fetch-host-key", "ok", start)
            line = key.export_public_key().decode().split()[:2]
            return HostKey(" ".join(line), key.get_fingerprint("sha256"))
    _record(audit, name, "ssh", "fetch-host-key", "refused", start, "host_key")
    raise SecurityRefusal(RefusalReason.HOST_KEY, f"{name}: no ed25519/ECDSA host key offered")


def _fetch_certificate_blocking(host: str, port: int) -> bytes:
    ctx = ssl.create_default_context()
    # Deliberately unverified: we only read the certificate to show its fingerprint.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ipaddress.ip_address(host.strip("[]"))
        sni = None
    except ValueError:
        sni = host
    with (
        socket.create_connection((host.strip("[]"), port), timeout=TIMEOUT_S) as sock,
        ctx.wrap_socket(sock, server_hostname=sni) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise TransportError("no certificate presented")
    return der


async def fetch_certificate(name: str, url: str, audit: AuditSink) -> PeerCertificate:
    """The leaf certificate an https:// server presents (no request is sent)."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise SecurityRefusal(RefusalReason.CONFIG, "URL must be https://host[:port]/...")
    host, port = parts.hostname, parts.port or 443
    _check_host(host, port)
    start = time.monotonic()
    try:
        der = await asyncio.to_thread(_fetch_certificate_blocking, host, port)
    except (OSError, ssl.SSLError, TransportError) as exc:
        _record(audit, name, "http", "fetch-certificate", "error", start, type(exc).__name__)
        raise TransportError(f"{name}: {type(exc).__name__}") from None
    _record(audit, name, "http", "fetch-certificate", "ok", start)
    pem = ssl.DER_cert_to_PEM_cert(der)
    subject = _subject(pem)
    return PeerCertificate(pem=pem, sha256=hashlib.sha256(der).hexdigest(), subject=subject)


def _subject(pem: str) -> str:
    try:
        from cryptography import x509  # noqa: PLC0415

        cert = x509.load_pem_x509_certificate(pem.encode())
        return cert.subject.rfc4514_string()[:200]
    except ValueError:
        return "?"
