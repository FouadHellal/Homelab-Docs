from pathlib import Path

import pytest

from homelab_atlas.inventory.hosts import InventoryError, load_inventory
from homelab_atlas.security.allowlist import ProbeSection

REPO = Path(__file__).resolve().parents[2]
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinPinPinPinPinPinPinPinPinPinPinPinPinPinPin x"

BASE = f"""
version: 1
defaults:
  ssh: {{ key: ssh_default }}
hosts:
  - name: web01
    address: "10.0.20.21"
    type: linux
    collectors: [linux-ssh]
    ssh: {{ host_keys: ["{KEY}"], port: 2222 }}
"""


def write(tmp_path: Path, text: str) -> Path:
    p = tmp_path / "hosts.yaml"
    p.write_text(text, encoding="utf-8")
    return p


def test_demo_lab_inventory_loads() -> None:
    inv = load_inventory(REPO / "fixtures" / "demo-lab" / "hosts.yaml")
    assert len(inv.hosts) == 12
    assert inv.host("ipv6only01").address == "2001:db8:20::80"


def test_ssh_target_built_from_defaults(tmp_path: Path) -> None:
    inv = load_inventory(write(tmp_path, BASE))
    t = inv.ssh_target(inv.host("web01"), frozenset({ProbeSection.OS}))
    assert (t.host, t.port, t.username, t.key_secret) == (
        "10.0.20.21",
        2222,
        "atlas-ro",
        "ssh_default",
    )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda s: s.replace("version: 1", "version: 2"), "version"),
        (lambda s: s + "    bogus: 1\n", "bogus"),
        (lambda s: s.replace("type: linux", "type: linux\n    type: pi"), "duplicate key"),
        (lambda s: s + s.split("hosts:\n", 1)[1], "duplicate host names"),
        (
            lambda s: s.replace(
                'ssh: { host_keys: ["' + KEY + '"], port: 2222 }', "ssh: { port: 22 }"
            ),
            "host_keys",
        ),
        (lambda s: s.replace("key: ssh_default", "key: AKIAATLASFAKE0000001"), "secret NAME"),
        (
            lambda s: s.replace("key: ssh_default", "key: '-----BEGIN OPENSSH " + "PRIVATE KEY'"),
            "secret NAME",
        ),
        (lambda s: s.replace("port: 2222", "port: 2222, user: root"), "root"),
        (lambda s: s.replace('"10.0.20.21"', '"10.0.20.21; rm -rf /"'), "address"),
        (lambda s: s.replace("name: web01", "name: ../web01"), "name"),
        (lambda s: s.replace("[linux-ssh]", "[linux-ssh, shell]"), "collectors"),
        (lambda s: s + "!!python/object/apply:os.system ['id']\n", "invalid YAML"),
        (lambda s: "- just\n- a list\n", "mapping"),
    ],
)
def test_rejections(tmp_path: Path, mutation: object, message: str) -> None:
    text = mutation(BASE)  # type: ignore[operator]
    with pytest.raises(InventoryError, match=message):
        load_inventory(write(tmp_path, text))


def test_python_tags_never_constructed(tmp_path: Path) -> None:
    p = write(tmp_path, "version: !!python/object/apply:os.system ['echo pwned']\n")
    with pytest.raises(InventoryError, match="invalid YAML"):
        load_inventory(p)


def test_size_cap(tmp_path: Path) -> None:
    p = write(tmp_path, BASE + "#" * (1024 * 1024))
    with pytest.raises(InventoryError, match="larger"):
        load_inventory(p)
