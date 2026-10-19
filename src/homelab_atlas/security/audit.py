"""Append-only, hash-chained audit log of every outbound operation (ADR-010).

One JSON object per line in `audit-YYYY-MM.jsonl`. Each record carries `seq`, `prev`
(the previous record's hash) and `hash` = sha256(prev || canonical(record body)). The chain
continues across monthly files. There is deliberately no update or delete API.
"""

import hashlib
import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from homelab_atlas.redact import redact_text

GENESIS: Final = "0" * 64
FILE_RE: Final = re.compile(r"audit-(\d{4})-(\d{2})\.jsonl")
MAX_DETAIL: Final = 200

Outcome = Literal["ok", "refused", "error"]
Transport = Literal["ssh", "http", "replay", "ui"]  # ui: config changes from the web UI


class AuditEvent(BaseModel):
    """What a transport reports. Contains templates and metadata only, never payloads."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scan_id: str | None = None
    target: str = Field(max_length=128)
    transport: Transport
    op: str = Field(max_length=256)
    outcome: Outcome
    status: int | None = None
    duration_ms: int = Field(ge=0)
    bytes: int = Field(default=0, ge=0)
    reason: str | None = Field(default=None, max_length=64)
    detail: str | None = None

    @field_validator("ts")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("ts must be timezone-aware")
        return v.astimezone(UTC)

    @field_validator("target", "op")
    @classmethod
    def _printable(cls, v: str) -> str:
        if not v.isprintable():
            raise ValueError("control characters not allowed")
        return v


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class AuditCorruptError(Exception):
    pass


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _chain_hash(prev: str, body: dict[str, Any]) -> str:
    return hashlib.sha256(prev.encode("ascii") + b"\n" + _canonical(body)).hexdigest()


def _files(directory: Path) -> list[Path]:
    if not directory.is_dir():
        return []
    return sorted(p for p in directory.iterdir() if FILE_RE.fullmatch(p.name))


@dataclass(frozen=True, slots=True)
class VerifyReport:
    ok: bool
    records: int
    head: str
    error: str | None = None


class AuditLog:
    """Thread-safe appender.

    Startup reads only the last record (cheap) and refuses to start if it is malformed or
    does not hash to itself. Full-chain checking is `verify()` / `atlas audit verify`.
    """

    def __init__(self, directory: Path, *, scrub: Callable[[str], str] = redact_text) -> None:
        self._dir = directory
        self._scrub = scrub
        self._lock = threading.Lock()
        directory.mkdir(parents=True, exist_ok=True)
        self._seq, self._head = _tail(directory)

    @property
    def head(self) -> tuple[int, str]:
        return self._seq, self._head

    def record(self, event: AuditEvent) -> None:
        body = event.model_dump(mode="json")
        if body["detail"] is not None:
            body["detail"] = self._scrub(body["detail"])[:MAX_DETAIL]
        with self._lock:
            body["seq"] = self._seq + 1
            body["prev"] = self._head
            digest = _chain_hash(self._head, body)
            line = _canonical({**body, "hash": digest}) + b"\n"
            # File by write time (not event time) so files stay in chain order.
            path = self._dir / f"audit-{datetime.now(UTC):%Y-%m}.jsonl"
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
            fd = os.open(path, flags, 0o600)
            try:
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._seq += 1
            self._head = digest


def _tail(directory: Path) -> tuple[int, str]:
    files = _files(directory)
    if not files:
        return 0, GENESIS
    data = files[-1].read_bytes()
    if not data:
        raise AuditCorruptError(f"{files[-1].name}: empty file")
    if not data.endswith(b"\n"):
        raise AuditCorruptError(f"{files[-1].name}: truncated last record")
    try:
        rec = json.loads(data.rstrip(b"\n").rsplit(b"\n", 1)[-1])
        digest = rec.pop("hash")
        seq, prev = int(rec["seq"]), str(rec["prev"])
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise AuditCorruptError(f"{files[-1].name}: malformed last record") from exc
    if digest != _chain_hash(prev, rec):
        raise AuditCorruptError(f"{files[-1].name}: last record hash mismatch")
    return seq, str(digest)


def verify(directory: Path) -> VerifyReport:
    """Walk every file in order and recompute the chain."""
    prev, seq = GENESIS, 0
    for path in _files(directory):
        with path.open("rb") as fh:
            for lineno, raw in enumerate(fh, start=1):
                where = f"{path.name}:{lineno}"
                if not raw.endswith(b"\n"):
                    return VerifyReport(False, seq, prev, f"{where}: truncated record")
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    return VerifyReport(False, seq, prev, f"{where}: not JSON")
                if not isinstance(rec, dict):
                    return VerifyReport(False, seq, prev, f"{where}: not an object")
                digest = rec.pop("hash", None)
                if rec.get("seq") != seq + 1:
                    return VerifyReport(False, seq, prev, f"{where}: sequence gap")
                if rec.get("prev") != prev:
                    return VerifyReport(False, seq, prev, f"{where}: broken link")
                if digest != _chain_hash(prev, rec):
                    return VerifyReport(False, seq, prev, f"{where}: hash mismatch")
                prev, seq = digest, seq + 1
    return VerifyReport(True, seq, prev)
