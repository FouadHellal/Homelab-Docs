import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from homelab_atlas.cli import app

REPO = Path(__file__).resolve().parents[2]
LAB = REPO / "fixtures" / "demo-lab"
runner = CliRunner()


@pytest.fixture(autouse=True)
def lab_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATLAS_LAB_DIR", str(LAB))
    monkeypatch.setenv("COLUMNS", "200")


def test_acceptance_scan_a_b_diff(tmp_path: Path) -> None:
    d = str(tmp_path / "data")
    a = runner.invoke(app, ["scan", "--lab", "demo:A", "--data-dir", d])
    assert a.exit_code == 0, a.output
    assert "29 events" in a.output
    b = runner.invoke(app, ["scan", "--lab", "demo:B", "--data-dir", d])
    assert b.exit_code == 0, b.output
    out = runner.invoke(app, ["diff", "--lab", "demo", "--data-dir", d, "--json"])
    assert out.exit_code == 0, out.output
    got = sorted((e["type"], e["summary"]) for e in json.loads(out.output))
    golden = sorted(
        tuple(x) for x in json.loads((LAB / "expected-diff-A-B.json").read_text("utf-8"))
    )
    assert got == golden
    table = runner.invoke(app, ["diff", "--lab", "demo", "--data-dir", d, "--scan", "1"])
    assert "entity.added" in table.output


def test_mode_is_required() -> None:
    res = runner.invoke(app, ["scan"])
    assert res.exit_code == 2
    assert "exactly one" in res.output
    both = runner.invoke(app, ["scan", "--lab", "demo:A", "--live"])
    assert both.exit_code == 2


def test_bad_lab_spec_and_state(tmp_path: Path) -> None:
    for spec in ("prod:A", "demo:Z", "demo"):
        res = runner.invoke(app, ["scan", "--lab", spec, "--data-dir", str(tmp_path)])
        assert res.exit_code == 2, spec


def test_fresh_refuses_non_lab_dir(tmp_path: Path) -> None:
    keep = tmp_path / "keep.txt"
    keep.write_text("x", encoding="utf-8")
    res = runner.invoke(app, ["scan", "--lab", "demo:A", "--data-dir", str(tmp_path), "--fresh"])
    assert res.exit_code == 2
    assert keep.exists()


def test_doctor_flags_old_probe_and_unreachable(tmp_path: Path) -> None:
    res = runner.invoke(app, ["doctor", "--lab", "demo:A", "--data-dir", str(tmp_path)])
    assert res.exit_code == 1
    assert "db01" in res.output
    assert "0.9.0" in res.output
    assert "ghost01" in res.output
    ok = runner.invoke(
        app, ["doctor", "--lab", "demo:B", "--data-dir", str(tmp_path), "--host", "db01"]
    )
    assert ok.exit_code == 0, ok.output


def test_live_without_config_fails_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ATLAS_CONFIG_DIR", str(tmp_path / "nope"))
    res = runner.invoke(app, ["scan", "--live", "--data-dir", str(tmp_path / "d")])
    assert res.exit_code == 2


def test_targets_render_check_and_write(tmp_path: Path) -> None:
    assert runner.invoke(app, ["targets", "render", "--check"]).exit_code == 0
    stale = runner.invoke(app, ["targets", "render", "--check", "--out", str(tmp_path)])
    assert stale.exit_code == 1
    assert runner.invoke(app, ["targets", "render", "--out", str(tmp_path)]).exit_code == 0
    assert (tmp_path / "atlas-probe").read_bytes() == (
        REPO / "docs/targets/atlas-probe"
    ).read_bytes()


def test_db_upgrade_and_empty_diff(tmp_path: Path) -> None:
    assert runner.invoke(app, ["db", "upgrade", "--data-dir", str(tmp_path)]).exit_code == 0
    res = runner.invoke(app, ["diff", "--data-dir", str(tmp_path)])
    assert res.exit_code == 2
    assert "no scans" in res.output
