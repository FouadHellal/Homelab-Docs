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


CA_FILE = "atlas-ca.crt"
#: Apple platforms refuse TLS certificates valid for more than 825 days, even from a private CA.
TRUSTED_DAYS = 825


def _constraint(name: x509.GeneralName) -> x509.GeneralName:
    if isinstance(name, x509.IPAddress):
        ip = name.value
        return x509.IPAddress(ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}"))
    return name


def issue_trusted(data_dir: Path, names: list[str]) -> tuple[Path, Path, Path]:
    """Replace the server certificate with one a browser can trust (ADR-050).

    Chrome turns its password manager off on pages with a certificate error, so the
    self-signed default means "never offers to save the atlas password". This makes a
    one-time CA that may only vouch for atlas's own names (X.509 name constraints), signs
    the server certificate with it and throws the CA's private key away: once you import
    `atlas-ca.crt` on your PC, atlas is trusted, and nothing on this server can ever mint
    another certificate your PC would accept. The previous certificate is kept alongside.

    Returns (cert, key, ca_cert) paths. Restart atlas to serve the new certificate.
    """
    sans = _san(names)
    if not any(n not in ("localhost", "127.0.0.1", "::1") for n in (str(s.value) for s in sans)):
        raise ValueError("give the name or IP address you open atlas with")
    d = data_dir / "tls"
    d.mkdir(parents=True, exist_ok=True)
    cert_path, key_path, ca_path = d / "atlas.crt", d / "atlas.key", d / CA_FILE
    now = dt.datetime.now(dt.UTC)
    if cert_path.is_file():
        keep = d / f"previous-{now:%Y%m%d-%H%M%S}"
        keep.mkdir()
        for p in (cert_path, key_path, ca_path):
            if p.is_file():
                p.replace(keep / p.name)

    first = next(
        str(s.value) for s in sans if str(s.value) not in ("localhost", "127.0.0.1", "::1")
    )
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "atlas"),
            x509.NameAttribute(NameOID.COMMON_NAME, f"atlas local CA for {first}"[:64]),
        ]
    )
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=TRUSTED_DAYS + 1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.NameConstraints(
                permitted_subtrees=[_constraint(s) for s in sans], excluded_subtrees=None
            ),
            critical=True,
        )
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, first[:64])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=TRUSTED_DAYS))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    del ca_key  # never written anywhere: the CA can sign nothing else, ever
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
    # Leaf + CA, so clients that were given only the CA build the chain from the handshake.
    cert_path.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM)
    )
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path, ca_path


def ca_certificate(data_dir: Path) -> bytes | None:
    """The public CA certificate from `issue_trusted`, if atlas serves one (for /atlas-ca.crt)."""
    p = data_dir / "tls" / CA_FILE
    try:
        data = p.read_bytes() if p.is_file() and p.stat().st_size < 16 * 1024 else None
    except OSError:
        return None
    return data if data and data.startswith(b"-----BEGIN CERTIFICATE-----") else None
