"""deploy/atlas.sh against a fake `docker` (records calls; no containers, no network)."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "deploy" / "atlas.sh"
PW = "deploy-ATLASFAKE-pw1"


def _bash() -> str | None:
    if os.name == "nt":
        git_bash = (
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")) / "Git" / "bin" / "bash.exe"
        )
        return str(git_bash) if git_bash.is_file() else None  # never WSL's bash.exe
    return shutil.which("bash")


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash")

FAKE_DOCKER = r"""#!/usr/bin/env bash
# Fake docker: log argv, answer what atlas.sh asks.
printf '%s\n' "$*" >> "$FAKE_LOG"
args="$*"
case "$args" in
  "compose version") exit 0 ;;
  *" pull atlas") exit "${FAKE_PULL_RC:-0}" ;;
  *" atlas user add "*|*" atlas user passwd "*)
      IFS= read -r pw; printf 'stdin-password-length=%s\n' "${#pw}" >> "$FAKE_LOG"; exit 0 ;;
  *" ps -q atlas") echo fakeid; exit 0 ;;
  "inspect -f "*) echo healthy; exit 0 ;;
  *" logs atlas") echo "self-signed HTTPS certificate (SHA-256 AA:BB:CC)"; exit 0 ;;
  "build -t atlas:local "*) exit 0 ;;
  *) exit 0 ;;
esac
"""


def _run(
    tmp_path: Path, *args: str, stdin: str = "", pull_rc: int = 0
) -> tuple[subprocess.CompletedProcess[str], str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_bytes(FAKE_DOCKER.encode())
    fake.chmod(0o755)
    log = tmp_path / "docker.log"
    env = {
        **os.environ,
        "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
        if os.name != "nt"
        else f"{bin_dir.as_posix()}:/usr/bin:/bin:/mingw64/bin",
        "ATLAS_DIR": (tmp_path / "atlas").as_posix(),
        "FAKE_LOG": log.as_posix(),
        "FAKE_PULL_RC": str(pull_rc),
    }
    assert BASH is not None
    res = subprocess.run(  # noqa: S603 - fixed argv, test-only
        [BASH, SCRIPT.as_posix(), *args],
        input=stdin,
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    return res, log.read_text(encoding="utf-8") if log.exists() else ""


def test_script_parses() -> None:
    assert BASH is not None
    subprocess.run([BASH, "-n", SCRIPT.as_posix()], check=True, timeout=30)  # noqa: S603


def test_install_pulls_creates_account_and_starts(tmp_path: Path) -> None:
    res, log = _run(tmp_path, "install", stdin=f"admin\n{PW}\n{PW}\n")
    assert res.returncode == 0, res.stdout + res.stderr
    d = tmp_path / "atlas"
    key = (d / "secrets" / "atlas_master_key").read_text(encoding="utf-8").strip()
    assert len(key) >= 60  # 48 random bytes, base64
    assert (d / "secrets" / "mcp_token").stat().st_size >= 40
    env = (d / ".env").read_text(encoding="utf-8")
    assert "ATLAS_MODE=lan" in env
    assert "ATLAS_PORT=8443" in env
    assert "localhost" in env
    assert (d / "docker-compose.yml").is_file()
    assert f"build: {REPO.as_posix()}" in (d / "docker-compose.yml").read_text(
        encoding="utf-8"
    ) or "build:" in (d / "docker-compose.yml").read_text(encoding="utf-8")
    assert " pull atlas" in log
    assert "build -t atlas:local" not in log
    assert "atlas user add admin --password-stdin" in log
    assert f"stdin-password-length={len(PW)}" in log
    assert PW not in log  # never on a command line
    assert PW not in res.stdout + res.stderr
    assert " up -d" in log
    assert "https://" in res.stdout
    assert "AA:BB:CC" in res.stdout
    # Re-running keeps the existing key and .env.
    res2, _ = _run(tmp_path, "install", "--no-user")
    assert res2.returncode == 0, res2.stderr
    assert (d / "secrets" / "atlas_master_key").read_text(encoding="utf-8").strip() == key


def test_install_builds_when_pull_fails(tmp_path: Path) -> None:
    res, log = _run(tmp_path, "install", "--no-user", pull_rc=1)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "build -t atlas:local" in log
    env = (tmp_path / "atlas" / ".env").read_text(encoding="utf-8")
    assert "ATLAS_IMAGE=atlas" in env
    assert "ATLAS_VERSION=local" in env
    assert "docker login ghcr.io" in res.stderr


def test_user_add_rejects_mismatch_then_accepts(tmp_path: Path) -> None:
    _run(tmp_path, "install", "--no-user")
    res, log = _run(tmp_path, "user", "add", "alice", stdin=f"{PW}\nnope-ATLASFAKE-x\n{PW}\n{PW}\n")
    assert res.returncode == 0, res.stderr
    assert "differ" in res.stderr
    assert "atlas user add alice --password-stdin" in log


def test_bad_user_name_and_unknown_command(tmp_path: Path) -> None:
    res, _ = _run(tmp_path, "user", "add", "Bad Name;rm")
    assert res.returncode != 0
    res, _ = _run(tmp_path, "frobnicate")
    assert res.returncode == 2
    res, _ = _run(tmp_path, "help")
    assert "install" in res.stdout


def test_proxy_mode_adds_override(tmp_path: Path) -> None:
    _run(tmp_path, "install", "--no-user")
    env = tmp_path / "atlas" / ".env"
    env.write_text(
        env.read_text(encoding="utf-8").replace("ATLAS_MODE=lan", "ATLAS_MODE=proxy"),
        encoding="utf-8",
    )
    res, log = _run(tmp_path, "status")
    assert res.returncode == 0, res.stderr
    assert "docker-compose.proxy.yml" in log.splitlines()[-1] or "docker-compose.proxy.yml" in log
