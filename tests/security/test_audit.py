"""Hash-chained audit log: append, verify, tamper detection, restart, concurrency."""

import json
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from homelab_atlas.security import audit as audit_mod
from homelab_atlas.security.audit import AuditCorruptError, AuditEvent, AuditLog, verify

pytestmark = pytest.mark.security


def ev(i: int = 0, **kw: Any) -> AuditEvent:
    args: dict[str, Any] = {
        "target": "pve",
        "transport": "http",
        "op": "GET /nodes/{node}/qemu",
        "outcome": "ok",
        "status": 200,
        "duration_ms": i,
        "bytes": 10,
    }
    args.update(kw)
    return AuditEvent.model_validate(args)


def lines(d: Path) -> list[str]:
    return [
        ln
        for p in sorted(d.glob("audit-*.jsonl"))
        for ln in p.read_text(encoding="utf-8").splitlines()
    ]


def test_append_and_verify(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    for i in range(5):
        log.record(ev(i))
    report = verify(tmp_path)
    assert report.ok, report.error
    assert report.records == 5
    assert log.head == (5, report.head)
    first = json.loads(lines(tmp_path)[0])
    assert first["seq"] == 1
    assert first["prev"] == "0" * 64


def test_empty_dir_verifies(tmp_path: Path) -> None:
    assert verify(tmp_path / "none").ok


@pytest.mark.parametrize(
    ("field", "value"),
    [("op", "DELETE /nodes/pve1"), ("outcome", "refused"), ("bytes", 0), ("target", "evil")],
)
def test_field_tamper_detected(tmp_path: Path, field: str, value: object) -> None:
    log = AuditLog(tmp_path)
    for i in range(3):
        log.record(ev(i))
    (path,) = tmp_path.glob("audit-*.jsonl")
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    recs[1][field] = value
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    report = verify(tmp_path)
    assert not report.ok
    assert report.error is not None
    assert ":2:" in report.error


def test_recomputed_hash_still_breaks_chain(tmp_path: Path) -> None:
    """An attacker who rewrites a record and its own hash breaks the next link."""
    log = AuditLog(tmp_path)
    for i in range(3):
        log.record(ev(i))
    (path,) = tmp_path.glob("audit-*.jsonl")
    recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
    body = {k: v for k, v in recs[1].items() if k != "hash"} | {"op": "GET /forged"}
    recs[1] = body | {"hash": audit_mod._chain_hash(recs[1]["prev"], body)}
    path.write_text("".join(json.dumps(r) + "\n" for r in recs))
    report = verify(tmp_path)
    assert not report.ok
    assert report.error is not None
    assert ":3:" in report.error


@pytest.mark.parametrize("mutation", ["delete_middle", "swap", "duplicate", "truncate", "garbage"])
def test_structural_tamper_detected(tmp_path: Path, mutation: str) -> None:
    log = AuditLog(tmp_path)
    for i in range(4):
        log.record(ev(i))
    (path,) = tmp_path.glob("audit-*.jsonl")
    raw = path.read_text(encoding="utf-8").splitlines(keepends=True)
    if mutation == "delete_middle":
        del raw[1]
    elif mutation == "swap":
        raw[1], raw[2] = raw[2], raw[1]
    elif mutation == "duplicate":
        raw.insert(2, raw[1])
    elif mutation == "truncate":
        raw[-1] = raw[-1][:20]
    elif mutation == "garbage":
        raw.insert(1, "not json\n")
    path.write_text("".join(raw))
    assert not verify(tmp_path).ok


def test_restart_continues_chain(tmp_path: Path) -> None:
    a = AuditLog(tmp_path)
    a.record(ev(1))
    a.record(ev(2))
    b = AuditLog(tmp_path)
    assert b.head == a.head
    b.record(ev(3))
    report = verify(tmp_path)
    assert report.ok
    assert report.records == 3


def test_refuses_to_start_on_truncated_tail(tmp_path: Path) -> None:
    AuditLog(tmp_path).record(ev())
    (path,) = tmp_path.glob("audit-*.jsonl")
    path.write_bytes(path.read_bytes()[:-5])
    with pytest.raises(AuditCorruptError):
        AuditLog(tmp_path)


def test_refuses_to_start_on_forged_tail(tmp_path: Path) -> None:
    AuditLog(tmp_path).record(ev())
    (path,) = tmp_path.glob("audit-*.jsonl")
    rec = json.loads(path.read_text(encoding="utf-8"))
    rec["op"] = "GET /forged"
    path.write_text(json.dumps(rec) + "\n")
    with pytest.raises(AuditCorruptError):
        AuditLog(tmp_path)


def test_month_rotation_keeps_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    class Clock(datetime):
        current = datetime(2026, 9, 30, 23, 59, tzinfo=UTC)

        @classmethod
        def now(cls, tz: Any = None) -> "Clock":
            return cls.current  # type: ignore[return-value]

    monkeypatch.setattr(audit_mod, "datetime", Clock)
    log = AuditLog(tmp_path)
    log.record(ev(1, ts=Clock.current))
    Clock.current = Clock.current + timedelta(minutes=2)
    log.record(ev(2, ts=Clock.current))
    names = sorted(p.name for p in tmp_path.glob("audit-*.jsonl"))
    assert names == ["audit-2026-09.jsonl", "audit-2026-10.jsonl"]
    assert verify(tmp_path).ok
    assert AuditLog(tmp_path).head[0] == 2


def test_concurrent_appends(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)

    def worker(n: int) -> None:
        for i in range(50):
            log.record(ev(n * 100 + i))

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    report = verify(tmp_path)
    assert report.ok, report.error
    assert report.records == 400


def test_detail_is_redacted_and_capped(tmp_path: Path) -> None:
    log = AuditLog(tmp_path)
    log.record(ev(outcome="error", detail="failed: --password=pw-ATLASFAKE " + "x" * 500))
    (rec,) = [json.loads(x) for x in lines(tmp_path)]
    assert "ATLASFAKE" not in rec["detail"]
    assert len(rec["detail"]) <= 200


@pytest.mark.parametrize(
    "kw",
    [
        {"target": "pve\nforged"},
        {"op": "GET /x\r\n"},
        {"transport": "smtp"},
        {"outcome": "maybe"},
        {"duration_ms": -1},
        {"ts": datetime(2026, 1, 1)},  # naive
        {"extra": "field"},
    ],
)
def test_event_validation(kw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ev(**kw)


def test_no_mutation_api() -> None:
    public = {n for n in dir(AuditLog) if not n.startswith("_")}
    assert public == {"record", "head"}
