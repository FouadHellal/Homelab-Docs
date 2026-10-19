"""Built-in HTTPS for LAN use without a reverse proxy (ADR-026).

The session cookies are `__Host-`/`Secure`, so browsers only keep them over HTTPS. When atlas
runs on a LAN with no TLS proxy in front, `atlas serve --self-signed-tls` generates a
per-installation ECDSA P-256 certificate once (10 years, SANs: the given names + loopback)
under `<data>/tls/` and serves HTTPS with it. The browser warns once; after that, cookies,
CSRF and HSTS work exactly as behind a proxy.
"""

import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _san(names: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    seen: set[str] = set()
    for raw in [*names, "localhost", "127.0.0.1", "::1"]:
        n = raw.strip().lower()
        if not n or n in seen or n == "*":
            continue
        seen.add(n)
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


def ensure_self_signed(data_dir: Path, names: list[str]) -> tuple[Path, Path]:
    """Return (cert, key) paths, creating them on first use. Existing files are kept."""
    d = data_dir / "tls"
    cert_path, key_path = d / "atlas.crt", d / "atlas.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path
    d.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "atlas (self-signed)")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(_san(names)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    fd = os.open(
        key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def fingerprint(cert_path: Path) -> str:
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex(":").upper()
