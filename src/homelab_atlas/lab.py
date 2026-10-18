"""Synthetic demo lab (`--lab demo:A`): recorded probe output replayed through the real stack.

Layout: <lab>/hosts.yaml and <lab>/state-<X>/<host>/<section>.out. A host without a
directory is unreachable in that state.
"""

import os
import re
from pathlib import Path
from typing import Final

from homelab_atlas.inventory.hosts import Inventory, load_inventory
from homelab_atlas.probe.render import probe_sha256
from homelab_atlas.security.allowlist import PROBE_COMMANDS, ProbeSection
from homelab_atlas.security.ssh import ReplayTransport

LAB_SPEC_RE: Final = re.compile(r"demo(?::([A-Z]))?")
SHA_PLACEHOLDER: Final = b"@@PROBE_SHA256@@"


class LabError(ValueError):
    pass


def lab_root() -> Path:
    root = Path(os.environ.get("ATLAS_LAB_DIR", "fixtures/demo-lab"))
    if not (root / "hosts.yaml").is_file():
        raise LabError(f"demo lab not found at {root} (set ATLAS_LAB_DIR)")
    return root


def parse_spec(spec: str) -> str | None:
    """'demo:A' -> 'A'; 'demo' -> None (lab data dir, no state)."""
    m = LAB_SPEC_RE.fullmatch(spec)
    if m is None:
        raise LabError("lab spec must look like demo:A")
    return m.group(1)


def load_lab(state: str, root: Path | None = None) -> tuple[Inventory, ReplayTransport]:
    root = root or lab_root()
    state_dir = root / f"state-{state}"
    if not state_dir.is_dir():
        raise LabError(f"no such lab state: {state}")
    inventory = load_inventory(root / "hosts.yaml")
    sha = probe_sha256().encode()
    recordings: dict[tuple[str, str], bytes] = {}
    for host_dir in sorted(p for p in state_dir.iterdir() if p.is_dir()):
        for rec in sorted(host_dir.glob("*.out")):
            try:
                section = ProbeSection(rec.stem)
            except ValueError:
                raise LabError(f"unknown section recording: {rec.name}") from None
            data = rec.read_bytes().replace(SHA_PLACEHOLDER, sha)
            recordings[(host_dir.name, PROBE_COMMANDS[section])] = data
    return inventory, ReplayTransport(recordings)
