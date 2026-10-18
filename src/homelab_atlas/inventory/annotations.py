"""Annotations: the human layer (SPEC §4.2). annotations/*.yaml is the source of truth.

One file per entity. The file name is derived from the entity key (slug + hash), never taken
from user input, so a key cannot address a path outside the directory. Writes are atomic
(temp file + replace) with stable key order, so diffs in git stay small.
"""

import hashlib
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete
from sqlalchemy.orm import Session

from homelab_atlas.store.tables import Annotation, utcnow

MAX_FILE: Final = 64 * 1024
Criticality = Literal["low", "medium", "high", "critical"]


class AnnotationError(ValueError):
    pass


class Link(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=128)
    url: str = Field(max_length=2048)

    @field_validator("url")
    @classmethod
    def _scheme(cls, v: str) -> str:
        if not re.match(r"https?://[^\s<>\"']+$", v, re.IGNORECASE):
            raise ValueError("links must be http(s) URLs")
        return v


class AnnotationDoc(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity: str = Field(min_length=1, max_length=256)
    owner: str | None = Field(default=None, max_length=128)
    purpose: str | None = Field(default=None, max_length=512)
    criticality: Criticality | None = None
    tags: list[str] = Field(default_factory=list, max_length=32)
    links: list[Link] = Field(default_factory=list, max_length=32)
    notes: str | None = Field(default=None, max_length=8192)
    acknowledged: bool = False

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}", t):
                raise ValueError(f"bad tag {t!r}")
        return sorted(set(v))

    @field_validator("entity")
    @classmethod
    def _entity(cls, v: str) -> str:
        if not v.isprintable():
            raise ValueError("entity key must be printable")
        return v


def file_name(entity_key: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", entity_key.lower()).strip("-")[:48] or "entity"
    return f"{slug}-{hashlib.sha256(entity_key.encode()).hexdigest()[:10]}.yaml"


def load_dir(directory: Path) -> tuple[list[AnnotationDoc], list[str]]:
    docs: list[AnnotationDoc] = []
    errors: list[str] = []
    if not directory.is_dir():
        return docs, errors
    seen: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            if path.stat().st_size > MAX_FILE:
                raise AnnotationError("file too large")
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
            doc = AnnotationDoc.model_validate(raw)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            errors.append(f"{path.name}: {str(exc).splitlines()[0][:200]}")
            continue
        if doc.entity in seen:
            errors.append(f"{path.name}: duplicate annotation for {doc.entity}")
            continue
        seen.add(doc.entity)
        docs.append(doc)
    return docs, errors


def dump(doc: AnnotationDoc) -> str:
    data: dict[str, Any] = doc.model_dump(mode="json", exclude_defaults=True)
    data["entity"] = doc.entity
    order = ["entity", "owner", "purpose", "criticality", "tags", "links", "notes", "acknowledged"]
    ordered = {k: data[k] for k in order if k in data}
    return yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, width=100)


def save(directory: Path, doc: AnnotationDoc) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / file_name(doc.entity)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(dump(doc))
        Path(tmp).replace(target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return target


def sync(s: Session, directory: Path) -> list[str]:
    """Rebuild the annotations index from YAML. Returns per-file errors (bad files skipped)."""
    docs, errors = load_dir(directory)
    s.execute(delete(Annotation))
    for d in docs:
        s.add(
            Annotation(
                entity_key=d.entity,
                owner=d.owner,
                purpose=d.purpose,
                criticality=d.criticality,
                tags=d.tags,
                links=[link.model_dump() for link in d.links],
                notes=d.notes,
                acknowledged=d.acknowledged,
                source_file=file_name(d.entity),
                updated_at=utcnow(),
            )
        )
    s.flush()
    return errors
