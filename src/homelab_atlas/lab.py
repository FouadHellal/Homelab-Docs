"""Synthetic demo lab (`--lab demo:A`): recorded probe output replayed through the real stack.

Layout: <lab>/hosts.yaml, <lab>/state-<X>/<host>/<section>.out (SSH probe output) and
<lab>/state-<X>/_api/<source>.json (API responses). A host without a directory is
unreachable in that state; an API source without a file answers 404.
"""

import json
import os
import re
from pathlib import Path
from typing import Final

from homelab_atlas.inventory.hosts import Inventory, load_inventory
from homelab_atlas.probe.render import PROBE_VERSION, probe_sha256
from homelab_atlas.security.allowlist import PROBE_COMMANDS, ProbeSection
from homelab_atlas.security.ssh import ReplayTransport

LAB_SPEC_RE: Final = re.compile(r"demo(?::([A-Z]))?")
SHA_PLACEHOLDER: Final = b"@@PROBE_SHA256@@"
VERSION_PLACEHOLDER: Final = b"@@PROBE_VERSION@@"


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


def load_api_recordings(
    state: str, root: Path | None = None
) -> dict[str, dict[str, tuple[int, bytes]]]:
    """state-<X>/_api/<source>.json: {"<raw path>": {"status": 200, "body": {...}}}."""
    root = root or lab_root()
    out: dict[str, dict[str, tuple[int, bytes]]] = {}
    for f in sorted((root / f"state-{state}" / "_api").glob("*.json")):
        raw = json.loads(f.read_text(encoding="utf-8"))
        out[f.stem] = {
            path: (int(r["status"]), json.dumps(r["body"]).encode()) for path, r in raw.items()
        }
    return out


def load_lab(state: str, root: Path | None = None) -> tuple[Inventory, ReplayTransport]:
    root = root or lab_root()
    state_dir = root / f"state-{state}"
    if not state_dir.is_dir():
        raise LabError(f"no such lab state: {state}")
    inventory = load_inventory(root / "hosts.yaml")
    sha = probe_sha256().encode()
    recordings: dict[tuple[str, str], bytes] = {}
    for host_dir in sorted(p for p in state_dir.iterdir() if p.is_dir() and p.name != "_api"):
        for rec in sorted(host_dir.glob("*.out")):
            try:
                section = ProbeSection(rec.stem)
            except ValueError:
                raise LabError(f"unknown section recording: {rec.name}") from None
            data = (
                rec.read_bytes()
                .replace(SHA_PLACEHOLDER, sha)
                .replace(VERSION_PLACEHOLDER, PROBE_VERSION.encode())
            )
            recordings[(host_dir.name, PROBE_COMMANDS[section])] = data
    return inventory, ReplayTransport(recordings)
