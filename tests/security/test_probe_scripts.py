"""Target-side scripts: gate exact-match, probe argument handling, framing, drift check."""

import hashlib
import os
import shutil
import subprocess
from pathlib import Path, PurePosixPath

import pytest

from homelab_atlas.collectors.linux_ssh.frame import FrameError, parse_frame
from homelab_atlas.probe.render import (
    PROBE_PATH,
    PROBE_VERSION,
    probe_sha256,
    render_all,
    render_gate,
    render_probe,
    render_sudoers,
)
from homelab_atlas.security.allowlist import PROBE_COMMANDS, ProbeSection

pytestmark = pytest.mark.security

REPO = Path(__file__).resolve().parents[2]


def _bash() -> str | None:
    for cand in (shutil.which("bash"), r"C:\Program Files\Git\bin\bash.exe"):
        # System32\bash.exe is WSL: different filesystem view, not usable here.
        if cand and Path(cand).exists() and "system32" not in cand.lower():
            return cand
    return None


BASH = _bash()
needs_bash = pytest.mark.skipif(BASH is None, reason="bash not available")


def posix(p: Path) -> str:
    p = p.resolve()
    if os.name == "nt":
        return str(PurePosixPath("/" + p.drive[0].lower(), *p.parts[1:]))
    return p.as_posix()


def run(
    script: Path, *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    assert BASH is not None
    full_env = {**os.environ, **(env or {})}
    full_env.pop("SSH_ORIGINAL_COMMAND", None)
    if env and "SSH_ORIGINAL_COMMAND" in env:
        full_env["SSH_ORIGINAL_COMMAND"] = env["SSH_ORIGINAL_COMMAND"]
    return subprocess.run(  # noqa: S603
        [BASH, posix(script), *args], env=full_env, capture_output=True, timeout=30, check=False
    )


@pytest.fixture
def gate(tmp_path: Path) -> Path:
    stub = tmp_path / "sudo-stub"
    stub.write_bytes(b"#!/bin/bash\nprintf '%s\\n' \"$@\"\n")
    stub.chmod(0o755)
    path = tmp_path / "gate"
    path.write_bytes(render_gate(sudo=posix(stub)))
    return path


@needs_bash
@pytest.mark.parametrize("section", list(ProbeSection))
def test_gate_accepts_exact_commands(gate: Path, section: ProbeSection) -> None:
    res = run(gate, env={"SSH_ORIGINAL_COMMAND": PROBE_COMMANDS[section]})
    assert res.returncode == 0, res.stderr
    assert res.stdout.decode().splitlines() == ["-n", "--", PROBE_PATH, section.value]


GATE_REFUSALS = [
    "", "os", "atlas-probe", "atlas-probe ", "atlas-probe os ", " atlas-probe os",
    "atlas-probe  os", "atlas-probe\tos", "atlas-probe os\n", "atlas-probe os\nid",
    "atlas-probe os;id", "atlas-probe os && id", "atlas-probe os | sh", "atlas-probe $(id)",
    "atlas-probe `id`", "atlas-probe *", "atlas-probe ?s", "atlas-probe [o]s", "atlas-probe o*",
    "ATLAS-PROBE os", "atlas-probe OS", "/usr/local/libexec/atlas-probe os", "sudo atlas-probe os",
    "atlas-probe оs", "atlas-probe os --help", "atlas-probe docker inspect x", "bash -i",
    "scp -t /tmp", "internal-sftp", "rsync --server . /",
]  # fmt: skip


@needs_bash
@pytest.mark.parametrize("request_", GATE_REFUSALS, ids=repr)
def test_gate_refuses(gate: Path, request_: str) -> None:
    res = run(gate, env={"SSH_ORIGINAL_COMMAND": request_})
    assert res.returncode == 64
    assert res.stdout == b"", "sudo must not be reached"
    assert res.stderr.strip() == b"atlas-probe-gate: refused"  # request never echoed


@needs_bash
def test_gate_refuses_when_unset(gate: Path) -> None:
    res = run(gate)
    assert res.returncode == 64
    assert res.stdout == b""


@pytest.fixture
def probe(tmp_path: Path) -> Path:
    path = tmp_path / "atlas-probe"
    path.write_bytes(render_probe())
    return path


@needs_bash
def test_probe_version_frame_and_self_hash(probe: Path) -> None:
    res = run(probe, "version")
    assert res.returncode == 0, res.stderr
    frame = parse_frame(res.stdout, ProbeSection.VERSION)
    assert frame.complete
    assert frame.errors == []
    assert (frame.text("version") or "").strip() == PROBE_VERSION
    sha = frame.text("sha256")
    assert sha is not None
    assert sha.split()[0] == probe_sha256() == hashlib.sha256(probe.read_bytes()).hexdigest()


@needs_bash
@pytest.mark.parametrize(
    "args", [(), ("os", "net"), ("os;id",), ("../x",), ("OS",), ("",), ("--help",)]
)
def test_probe_rejects_arguments(probe: Path, args: tuple[str, ...]) -> None:
    res = run(probe, *args)
    assert res.returncode == 64
    assert b"--" not in res.stdout.split(b"\n", 1)[-1]  # no parts emitted


@needs_bash
@pytest.mark.parametrize("section", ["docker", "pi"])
def test_probe_unimplemented_sections(probe: Path, section: str) -> None:
    assert run(probe, section).returncode == 3


def test_probe_boundaries_are_random() -> None:
    assert "od -An -N12 -tx1 /dev/urandom" in render_probe().decode()


def test_rendered_artifacts_match_committed() -> None:
    """docs/targets/ is what the owner reviews: it must be exactly what we render."""
    target_dir = REPO / "docs" / "targets"
    for name, data in render_all().items():
        committed = (target_dir / name).read_bytes()
        assert committed == data, f"docs/targets/{name} is stale: run `atlas targets render`"


def test_sudoers_has_no_wildcards() -> None:
    text = render_sudoers().decode()
    assert "*" not in text
    assert "ALL=(root) NOPASSWD: ATLAS_PROBE" in text
    for section in ProbeSection:
        assert f"{PROBE_PATH} {section.value}" in text


def test_render_refuses_bad_paths() -> None:
    for bad in ("relative/sudo", "/usr/bin/sudo;id", "/usr/../bin/sudo", "/a b", "C:\\sudo"):
        with pytest.raises(ValueError, match="path"):
            render_gate(sudo=bad)


# ------------------------------------------------------------------ frame parser


def _frame(section: str, body: str, b: str = "0123456789abcdef01234567") -> bytes:
    return f"ATLAS-PROBE 1 {section} {b}\n{body}".encode()


def test_frame_parses_parts_and_rc() -> None:
    b = "0123456789abcdef01234567"
    data = _frame(
        "os", f"--{b} part kernel\n6.8.12\n\n--{b} rc 0\n--{b} part virt\n\n--{b} rc 1\n--{b} end\n"
    )
    f = parse_frame(data, ProbeSection.OS)
    assert f.complete
    assert f.text("kernel") == "6.8.12\n"
    assert f.text("virt") is None
    assert f.parts["virt"].rc == 1


def test_frame_forged_header_inside_content_is_data() -> None:
    b = "0123456789abcdef01234567"
    evil = "--ffffffffffffffffffffffff part machine-id\nforged\n--ffffffffffffffffffffffff rc 0\n"
    data = _frame("cron", f"--{b} part cron:/etc/crontab\n{evil}\n--{b} rc 0\n--{b} end\n")
    f = parse_frame(data, ProbeSection.CRON)
    assert list(f.parts) == ["cron:/etc/crontab"]
    assert "forged" in f.parts["cron:/etc/crontab"].content


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"garbage\n",
        b"ATLAS-PROBE 2 os 0123456789abcdef01234567\n",
        b"ATLAS-PROBE 1 os short\n",
    ],
)
def test_frame_bad_header(data: bytes) -> None:
    with pytest.raises(FrameError):
        parse_frame(data, ProbeSection.OS)


def test_frame_section_mismatch() -> None:
    with pytest.raises(FrameError, match="mismatch"):
        parse_frame(_frame("net", ""), ProbeSection.OS)


def test_frame_truncated_and_duplicates() -> None:
    b = "0123456789abcdef01234567"
    f = parse_frame(
        _frame("os", f"--{b} part a\nx\n--{b} rc 0\n--{b} part a\ny\n--{b} rc 0\n--{b} part b\nz"),
        ProbeSection.OS,
    )
    assert f.parts["a"].content == "x"
    assert not f.complete
    assert any("duplicate" in e for e in f.errors)
    assert any("truncated" in e for e in f.errors)
