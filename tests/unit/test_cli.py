from pathlib import Path

from typer.testing import CliRunner

from homelab_atlas import __version__
from homelab_atlas.cli import app

runner = CliRunner()


def test_version_flag() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"atlas {__version__}"


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_no_args_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "Usage" in result.output


def test_selftest_security_passes() -> None:
    result = runner.invoke(app, ["selftest", "security"])
    assert result.exit_code == 0, result.output
    assert "FAIL" not in result.output


def test_audit_verify_ok_and_broken(tmp_path: Path) -> None:
    from homelab_atlas.security.audit import AuditEvent, AuditLog  # noqa: PLC0415

    log = AuditLog(tmp_path)
    for i in range(2):
        log.record(
            AuditEvent(target="t", transport="http", op="GET /x", outcome="ok", duration_ms=i)
        )
    ok = runner.invoke(app, ["audit", "verify", "--dir", str(tmp_path)])
    assert ok.exit_code == 0
    assert "2 records" in ok.output
    (path,) = tmp_path.glob("audit-*.jsonl")
    path.write_bytes(path.read_bytes().replace(b'"GET /x"', b'"PUT /x"', 1))
    broken = runner.invoke(app, ["audit", "verify", "--dir", str(tmp_path)])
    assert broken.exit_code == 1
    assert "BROKEN" in broken.output
