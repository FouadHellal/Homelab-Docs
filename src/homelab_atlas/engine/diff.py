"""Field-level diff over canonical snapshot bodies (ADR-011)."""

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal

ChangeKind = Literal["added", "removed", "changed"]


@dataclass(frozen=True, slots=True)
class Change:
    path: tuple[str, ...]
    kind: ChangeKind
    old: Any = None
    new: Any = None

    @property
    def dotted(self) -> str:
        return ".".join(self.path)


def canonical_json(body: Any) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def body_sha256(body: Any) -> str:
    return hashlib.sha256(canonical_json(body)).hexdigest()


def _is_scalar_list(v: Any) -> bool:
    return isinstance(v, list) and all(not isinstance(i, dict | list) for i in v)


def diff(old: Any, new: Any, path: tuple[str, ...] = ()) -> list[Change]:
    """Deterministic, ordered list of changes from `old` to `new`."""
    if isinstance(old, dict) and isinstance(new, dict):
        changes: list[Change] = []
        for key in sorted(old.keys() | new.keys()):
            p = (*path, key)
            if key not in new:
                changes.append(Change(p, "removed", old=old[key]))
            elif key not in old:
                changes.append(Change(p, "added", new=new[key]))
            else:
                changes.extend(diff(old[key], new[key], p))
        return changes
    if _is_scalar_list(old) and _is_scalar_list(new):
        removed = [v for v in old if v not in new]
        added = [v for v in new if v not in old]
        return [Change((*path, str(v)), "removed", old=v) for v in removed] + [
            Change((*path, str(v)), "added", new=v) for v in added
        ]
    if old != new:
        return [Change(path, "changed", old=old, new=new)]
    return []
