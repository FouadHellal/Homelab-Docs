"""ADR-025 security core: UI vault, password-mode SSH wire format, identity fetch helpers."""

import asyncio
import contextlib
import datetime as dt
import json
import ssl
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

import asyncssh
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from homelab_atlas.probe.render import render_probe
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.discover import fetch_certificate, fetch_host_key
from homelab_atlas.security.errors import (
    RefusalReason,
    SecretError,
    SecurityRefusal,
    TransportError,
)
from homelab_atlas.security.secrets import SecretDir, SecretResolver
from homelab_atlas.security.ssh import (
    INLINE_COMMANDS,
    INLINE_LOADER,
    AsyncSshTransport,
    SshRunner,
    SshTarget,
)
from homelab_atlas.security.vault import ChainedSecrets, Vault, load_master_key
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security
PW = "pw-ATLASFAKE-123"

# ------------------------------------------------------------------ vault


def _vault(tmp_path: Path, key: bytes = b"k" * 32) -> Vault:
    return Vault(tmp_path / "vault.json", key)


def test_vault_roundtrip_and_ciphertext_only_on_disk(tmp_path: Path) -> None:
    v = _vault(tmp_path)
    v.put("ui-ssh-docker01", SecretStr(PW))
    assert v.resolve("ui-ssh-docker01").get_secret_value() == PW
    assert v.has("ui-ssh-docker01")
    assert v.names() == ["ui-ssh-docker01"]
    raw = (tmp_path / "vault.json").read_text(encoding="utf-8")
    assert PW not in raw
    assert "ATLASFAKE" not in raw


def test_vault_wrong_key_and_tamper_fail_closed(tmp_path: Path) -> None:
    _vault(tmp_path).put("a-secret", SecretStr(PW))
    with pytest.raises(SecretError, match="cannot decrypt"):
        _vault(tmp_path, b"x" * 32).resolve("a-secret")
    doc = json.loads((tmp_path / "vault.json").read_text(encoding="utf-8"))
    # Moving a ciphertext under another name must not decrypt (name is associated data).
    doc["secrets"]["b-secret"] = doc["secrets"]["a-secret"]
    (tmp_path / "vault.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(SecretError, match="cannot decrypt"):
        _vault(tmp_path).resolve("b-secret")
    (tmp_path / "vault.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(SecretError, match="corrupt"):
        _vault(tmp_path).resolve("a-secret")


def test_vault_validates_names_and_values(tmp_path: Path) -> None:
    v = _vault(tmp_path)
    for bad in ("../x", "UPPER", "", "a" * 80):
        with pytest.raises(SecurityRefusal):
            v.put(bad, SecretStr(PW))
    with pytest.raises(SecretError, match="empty"):
        v.put("ok-name", SecretStr(""))
    v.put("ok-name", SecretStr(PW))
    v.delete("ok-name")
    assert not v.has("ok-name")
    with pytest.raises(SecretError, match="not found"):
        v.resolve("ok-name")


def test_master_key_prefers_docker_secret(tmp_path: Path) -> None:
    sec = tmp_path / "secrets"
    sec.mkdir()
    generated = load_master_key(tmp_path / "data")
    assert len(generated) == 32
    assert load_master_key(tmp_path / "data") == generated  # stable
    (sec / "atlas_master_key").write_bytes(b"m" * 40)
    from_secret = load_master_key(tmp_path / "data", SecretResolver([SecretDir(sec, False)]))
    assert from_secret != generated
    (sec / "atlas_master_key").write_bytes(b"short")
    with pytest.raises(SecretError, match="32 bytes"):
        load_master_key(tmp_path / "data", SecretResolver([SecretDir(sec, False)]))


def test_chained_secrets_operator_secrets_win(tmp_path: Path) -> None:
    sec = tmp_path / "secrets"
    sec.mkdir()
    (sec / "shared").write_bytes(b"from-docker-ATLASFAKE")
    v = _vault(tmp_path)
    v.put("shared", SecretStr("from-vault-ATLASFAKE"))
    v.put("ui-only", SecretStr("vault-ATLASFAKE"))
    chain = ChainedSecrets(SecretResolver([SecretDir(sec, False)]), v)
    assert chain.resolve("shared").get_secret_value() == "from-docker-ATLASFAKE"
    assert chain.resolve("ui-only").get_secret_value() == "vault-ATLASFAKE"
    with pytest.raises(SecretError):
        ChainedSecrets(SecretResolver([SecretDir(sec, False)]), None).resolve("ui-only")


# ------------------------------------------------------------------ password-mode SSH


@dataclass
class Seen:
    commands: list[str | None] = field(default_factory=list)
    stdin: list[bytes] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)
    pubkey_tries: int = 0


@dataclass
class PwLab:
    port: int
    host_key: asyncssh.SSHKey
    resolver: SecretResolver
    seen: Seen

    def target(self, **kw: object) -> SshTarget:
        args: dict[str, object] = {
            "name": "pwlab",
            "host": "127.0.0.1",
            "port": self.port,
            "host_keys": (self.host_key.export_public_key().decode().strip(),),
            "sections": frozenset(ProbeSection),
            "auth": "password",
            "password_secret": "pw",
            "username": "admin",
        }
        args.update(kw)
        return SshTarget(**args)  # type: ignore[arg-type]


@pytest.fixture
async def pwlab(tmp_path: Path) -> AsyncIterator[PwLab]:
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    (tmp_path / "pw").write_bytes(PW.encode() + b"\n")
    seen = Seen()

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username: str) -> bool:
            return True

        def public_key_auth_supported(self) -> bool:
            return True

        def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
            seen.pubkey_tries += 1
            return False

        def password_auth_supported(self) -> bool:
            return True

        def validate_password(self, username: str, password: str) -> bool:
            seen.passwords.append(password)
            return password == PW

    async def handle(process: asyncssh.SSHServerProcess[bytes]) -> None:
        seen.commands.append(process.command)
        seen.stdin.append(await process.stdin.read())
        process.stdout.write(b"ATLAS-PROBE 1 os x\n")
        process.exit(0)

    server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle,
        encoding=None,
    )  # fmt: skip
    port = server.sockets[0].getsockname()[1]
    yield PwLab(port, host_key, SecretResolver([SecretDir(tmp_path, False)]), seen)
    server.close()
    await server.wait_closed()


def _pw_runner(lab: PwLab, audit: MemoryAudit, probe: bytes | None = b"PROBE") -> SshRunner:
    return SshRunner(transport=AsyncSshTransport(lab.resolver, probe), audit=audit)


async def test_password_mode_sends_constant_loader_and_streams_probe(
    pwlab: PwLab, audit: MemoryAudit
) -> None:
    probe = render_probe()
    out = await _pw_runner(pwlab, audit, probe).run(pwlab.target(), ProbeSection.OS)
    assert out.exit_status == 0
    assert pwlab.seen.commands == [INLINE_COMMANDS[ProbeSection.OS]]
    assert pwlab.seen.stdin == [PW.encode() + b"\n" + probe]
    assert pwlab.seen.passwords == [PW]
    assert pwlab.seen.pubkey_tries == 0
    # The password is never on the command line or in the audit log.
    assert PW not in (pwlab.seen.commands[0] or "")
    assert PW not in json.dumps([e.model_dump(mode="json") for e in audit.events])


async def test_password_mode_without_sudo_sends_empty_password_line(
    pwlab: PwLab, audit: MemoryAudit
) -> None:
    await _pw_runner(pwlab, audit).run(pwlab.target(sudo=False), ProbeSection.VERSION)
    assert pwlab.seen.stdin == [b"\nPROBE"]


def test_inline_commands_are_constant_per_section() -> None:
    assert set(INLINE_COMMANDS) == set(ProbeSection)
    for section, cmd in INLINE_COMMANDS.items():
        assert cmd.startswith("bash -c ")
        assert cmd.endswith(f" atlas {section.value}")
        assert INLINE_LOADER.replace('"', "") in cmd.replace('"', "")
    # The password only travels via stdin: the loader never mentions argv/env for it.
    assert "$p" in INLINE_LOADER
    assert "export" not in INLINE_LOADER


async def test_password_mode_wrong_password(
    pwlab: PwLab, audit: MemoryAudit, tmp_path: Path
) -> None:
    (tmp_path / "pw").write_bytes(b"wrong-ATLASFAKE")
    with pytest.raises(TransportError, match="authentication refused"):
        await _pw_runner(pwlab, audit).run(pwlab.target(), ProbeSection.OS)
    assert pwlab.seen.commands == []


@pytest.mark.parametrize("value", [b"a\nb-ATLASFAKE", b"", b"x\r-ATLASFAKE"])
async def test_password_mode_refuses_unsafe_passwords(
    pwlab: PwLab, audit: MemoryAudit, tmp_path: Path, value: bytes
) -> None:
    (tmp_path / "pw").write_bytes(value)
    with pytest.raises(SecurityRefusal):
        await _pw_runner(pwlab, audit).run(pwlab.target(), ProbeSection.OS)
    assert pwlab.seen.passwords == []


async def test_password_mode_needs_bundled_probe(pwlab: PwLab, audit: MemoryAudit) -> None:
    with pytest.raises(SecurityRefusal, match="bundled probe"):
        await _pw_runner(pwlab, audit, None).run(pwlab.target(), ProbeSection.OS)
    assert pwlab.seen.commands == []


async def test_password_mode_still_pins_host_key(pwlab: PwLab, audit: MemoryAudit) -> None:
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    with pytest.raises(SecurityRefusal) as exc:
        await _pw_runner(pwlab, audit).run(pwlab.target(host_keys=(other,)), ProbeSection.OS)
    assert exc.value.reason is RefusalReason.HOST_KEY
    assert pwlab.seen.passwords == []  # never offered to an unverified server


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"password_secret": None}, "no password secret"),
        ({"auth": "key", "key_secret": None}, "no key secret"),
        ({"auth": "telnet"}, "bad auth mode"),
        ({"password_secret": "../x"}, "secret name"),
    ],
)
def test_target_auth_mode_validation(pwlab: PwLab, kw: dict[str, object], match: str) -> None:
    with pytest.raises(SecurityRefusal, match=match):
        pwlab.target(**kw)


# ------------------------------------------------------------------ identity fetch


async def test_fetch_host_key_matches_server(pwlab: PwLab, audit: MemoryAudit) -> None:
    hk = await fetch_host_key("pwlab", "127.0.0.1", pwlab.port, audit)
    assert hk.line == " ".join(pwlab.host_key.export_public_key().decode().split()[:2])
    assert hk.fingerprint == pwlab.host_key.get_fingerprint("sha256")
    assert pwlab.seen.passwords == []
    assert pwlab.seen.commands == []
    assert audit.events[-1].op == "fetch-host-key"
    assert audit.events[-1].outcome == "ok"


async def test_fetch_host_key_refuses_bad_input(audit: MemoryAudit) -> None:
    with pytest.raises(SecurityRefusal):
        await fetch_host_key("x", "bad host; rm -rf /", 22, audit)
    with pytest.raises(TransportError):
        await fetch_host_key("x", "127.0.0.1", 1, audit)


def _self_signed(tmp_path: Path) -> tuple[Path, Path, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ucg.lab.example")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    cp, kp = tmp_path / "c.pem", tmp_path / "k.pem"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))  # fmt: skip
    return cp, kp, cert.public_bytes(serialization.Encoding.DER)


async def test_fetch_certificate_reads_leaf_without_request(
    tmp_path: Path, audit: MemoryAudit
) -> None:
    cp, kp, der = _self_signed(tmp_path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    got: list[bytes] = []

    async def handle(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        with contextlib.suppress(TimeoutError, ConnectionError, ssl.SSLError):
            got.append(await asyncio.wait_for(r.read(100), 2))
        w.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    port = server.sockets[0].getsockname()[1]
    try:
        cert = await fetch_certificate("ucg", f"https://127.0.0.1:{port}/proxy/network", audit)
    finally:
        server.close()
        await server.wait_closed()
    import hashlib  # noqa: PLC0415

    assert cert.sha256 == hashlib.sha256(der).hexdigest()
    assert "ucg.lab.example" in cert.subject
    assert cert.pem.startswith("-----BEGIN CERTIFICATE-----")
    assert got in ([], [b""])  # no HTTP request was sent
    assert audit.events[-1].op == "fetch-certificate"


async def test_fetch_certificate_refuses_non_https(audit: MemoryAudit) -> None:
    for url in ("http://x/", "file:///etc/passwd", "https:///nohost"):
        with pytest.raises(SecurityRefusal):
            await fetch_certificate("x", url, audit)
