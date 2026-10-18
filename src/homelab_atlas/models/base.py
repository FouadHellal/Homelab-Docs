"""Model helpers: volatile/identity markers and the canonical form used for hashing and diffs.

* `volatile(...)` fields (uptime, counters, pids, timestamps) are kept in the current-state
  facet but stripped from snapshots, so they never produce a new snapshot or an event.
* `keyed(...)` list fields are set-like: canonicalised into a mapping by identity key, so
  ordering never matters and a diff talks about `sockets["tcp|0.0.0.0|22"]`, not `[3]`.
"""

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

IDENTITY_SEP = "|"


def volatile(default: Any = None, *, factory: Any = None) -> Any:
    if factory is not None:
        return Field(default_factory=factory, json_schema_extra={"volatile": True})
    return Field(default, json_schema_extra={"volatile": True})


def keyed(*identity: str) -> Any:
    if not identity:
        raise ValueError("keyed() needs at least one identity field")
    return Field(default_factory=list, json_schema_extra={"identity": list(identity)})


class Fact(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _extra(model: type[BaseModel], name: str) -> Mapping[str, Any]:
    extra = model.model_fields[name].json_schema_extra
    return extra if isinstance(extra, Mapping) else {}


def identity_of(item: BaseModel, fields: list[str]) -> str:
    return IDENTITY_SEP.join("" if (v := getattr(item, f)) is None else str(v) for f in fields)


def canonical(model: BaseModel) -> dict[str, Any]:
    """Volatile-free, order-free JSON-ready form. Equal facts give equal output."""
    out: dict[str, Any] = {}
    for name in type(model).model_fields:
        extra = _extra(type(model), name)
        if extra.get("volatile"):
            continue
        out[name] = _canon_value(getattr(model, name), extra.get("identity"))
    return out


def _canon_value(value: Any, identity: list[str] | None = None) -> Any:
    if isinstance(value, BaseModel):
        return canonical(value)
    if isinstance(value, list | tuple):
        if identity is not None:
            keyed_map: dict[str, Any] = {}
            for item in value:
                key = identity_of(item, identity)
                n, base = 1, key
                while key in keyed_map:  # duplicate identities stay distinguishable
                    n += 1
                    key = f"{base}#{n}"
                keyed_map[key] = _canon_value(item)
            return dict(sorted(keyed_map.items()))
        items = [_canon_value(v) for v in value]
        if all(not isinstance(v, dict | list) for v in items):
            return sorted(items, key=lambda v: (v is None, str(v)))
        return items
    if isinstance(value, Mapping):
        return {
            str(k): _canon_value(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))
        }
    return value
