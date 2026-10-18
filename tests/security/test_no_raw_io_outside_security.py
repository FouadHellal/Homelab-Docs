"""Architecture guard: outbound I/O modules may only be imported by homelab_atlas.security.

Backs up the ruff TID251 banned-api rule so the check cannot be silenced by a noqa.
"""

import ast
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "homelab_atlas"
SECURITY = SRC / "security"

BANNED_MODULES = frozenset(
    {
        "httpx",
        "asyncssh",
        "paramiko",
        "requests",
        "urllib.request",
        "http.client",
        "socket",
        "subprocess",
        "pty",
        "ctypes",
    }
)
BANNED_CALLS = frozenset(
    {
        ("os", "system"),
        ("os", "popen"),
        ("os", "execv"),
        ("os", "execvp"),
        ("os", "spawnv"),
        ("os", "posix_spawn"),
    }
)


def _is_banned(module: str) -> bool:
    return any(module == b or module.startswith(f"{b}.") for b in BANNED_MODULES)


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if _is_banned(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.module and _is_banned(node.module):
            found.append(f"from {node.module} import ...")
        elif (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and (node.value.id, node.attr) in BANNED_CALLS
        ):
            found.append(f"{node.value.id}.{node.attr}")
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"__import__", "exec", "eval"}
        ):
            found.append(f"{node.func.id}()")
    return found


def _source_files() -> list[Path]:
    return [p for p in SRC.rglob("*.py") if SECURITY not in p.parents]


@pytest.mark.security
def test_no_raw_io_outside_security() -> None:
    offenders = {str(p.relative_to(SRC)): v for p in _source_files() if (v := _violations(p))}
    assert offenders == {}


@pytest.mark.security
def test_guard_detects_violations(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text(
        "import subprocess\nfrom httpx import Client\nimport os\nos.system('id')\n"
        "__import__('socket')\n",
        encoding="utf-8",
    )
    assert sorted(_violations(bad)) == sorted(
        ["import subprocess", "from httpx import ...", "os.system", "__import__()"]
    )
