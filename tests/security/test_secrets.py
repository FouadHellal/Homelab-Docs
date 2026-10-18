import os
from pathlib import Path

import pytest

from homelab_atlas.security.errors import RefusalReason, SecretError, SecurityRefusal
from homelab_atlas.security.secrets import SecretDir, SecretResolver

pytestmark = pytest.mark.security

FAKE = "tok-ATLASFAKE-0123456789"


@pytest.fixture
def resolver(tmp_path: Path) -> SecretResolver:
    (tmp_path / "proxmox_auditor").write_text(FAKE + "\n", encoding="utf-8")
    if os.name == "posix":
        (tmp_path / "proxmox_auditor").chmod(0o600)
    return SecretResolver([SecretDir(tmp_path, enforce_private_mode=True)])


def test_resolves_and_strips(resolver: SecretResolver) -> None:
    secret = resolver.resolve("proxmox_auditor")
    assert secret.get_secret_value() == FAKE
    assert FAKE not in repr(secret)
    assert FAKE not in str(secret)


@pytest.mark.parametrize(
    "name",
    [
        "../etc/passwd",
        "..",
        "a/b",
        "a\\b",
        "/abs",
        "C:\\x",
        "",
        "UPPER",
        ".hidden",
        "a..b",
        "a\x00b",
        "x" * 65,
        "naïve",
        "a b",
        "~root",
    ],
)
def test_bad_names_refused(resolver: SecretResolver, name: str) -> None:
    with pytest.raises(SecurityRefusal) as exc:
        resolver.resolve(name)
    assert exc.value.reason is RefusalReason.SECRET_NAME


@pytest.mark.parametrize("name", [None, 1, b"proxmox_auditor", ["proxmox_auditor"]])
def test_non_str_refused(resolver: SecretResolver, name: object) -> None:
    with pytest.raises(SecurityRefusal):
        resolver.resolve(name)  # type: ignore[arg-type]


def test_missing_does_not_leak_dirs(resolver: SecretResolver, tmp_path: Path) -> None:
    with pytest.raises(SecretError) as exc:
        resolver.resolve("nope")
    assert str(tmp_path) not in str(exc.value)


def test_directory_refused(tmp_path: Path) -> None:
    (tmp_path / "adir").mkdir()
    r = SecretResolver([SecretDir(tmp_path, enforce_private_mode=False)])
    with pytest.raises(SecurityRefusal):
        r.resolve("adir")


def test_first_dir_wins(tmp_path: Path) -> None:
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    (a / "k").write_text("from-a", encoding="utf-8")
    (b / "k").write_text("from-b", encoding="utf-8")
    r = SecretResolver([SecretDir(a, False), SecretDir(b, False)])
    assert r.resolve("k").get_secret_value() == "from-a"


def test_oversized_refused(tmp_path: Path) -> None:
    (tmp_path / "big").write_bytes(b"x" * (64 * 1024 + 1))
    r = SecretResolver([SecretDir(tmp_path, False)])
    with pytest.raises(SecretError):
        r.resolve("big")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_world_readable_refused_in_dev_dir(tmp_path: Path) -> None:
    p = tmp_path / "k"
    p.write_text("v", encoding="utf-8")
    p.chmod(0o644)
    with pytest.raises(SecurityRefusal) as exc:
        SecretResolver([SecretDir(tmp_path, True)]).resolve("k")
    assert exc.value.reason is RefusalReason.SECRET_PERMISSIONS
    # Docker-secrets style dir does not enforce
    assert SecretResolver([SecretDir(tmp_path, False)]).resolve("k").get_secret_value() == "v"


@pytest.mark.skipif(os.name != "posix", reason="symlinks need privileges on Windows")
def test_symlink_refused(tmp_path: Path) -> None:
    target = tmp_path / "real"
    target.write_text("v", encoding="utf-8")
    (tmp_path / "link").symlink_to(target)
    with pytest.raises(SecurityRefusal):
        SecretResolver([SecretDir(tmp_path, False)]).resolve("link")
