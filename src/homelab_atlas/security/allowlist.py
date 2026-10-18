"""Allowlist primitives: probe sections (SSH) and endpoint templates (HTTP).

Collectors declare what they need in terms of these objects. Transports accept nothing else,
so there is no string path from a collector to a target.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, unique
from types import MappingProxyType
from typing import Final, Literal

from pydantic import BaseModel

# ---------------------------------------------------------------------------- SSH


@unique
class ProbeSection(StrEnum):
    """Sections of the target-side `atlas-probe` script (ADR-002). No free-form arguments."""

    OS = "os"
    NET = "net"
    PORTS = "ports"
    STORAGE = "storage"
    SERVICES = "services"
    CRON = "cron"
    USERS = "users"
    PACKAGES = "packages"
    DOCKER = "docker"
    PI = "pi"
    VERSION = "version"


PROBE_COMMAND_RE: Final = re.compile(r"atlas-probe [a-z]{1,16}")


def _build_probe_commands() -> Mapping[ProbeSection, str]:
    table = {s: f"atlas-probe {s.value}" for s in ProbeSection}
    for cmd in table.values():
        if not PROBE_COMMAND_RE.fullmatch(cmd):  # pragma: no cover - import-time invariant
            raise RuntimeError(f"probe command violates invariant: {cmd!r}")
    return MappingProxyType(table)


#: The only strings that are ever sent over an SSH exec channel.
PROBE_COMMANDS: Final[Mapping[ProbeSection, str]] = _build_probe_commands()


# ---------------------------------------------------------------------------- HTTP

HttpMethod = Literal["GET", "POST"]

#: Path segments that are never reachable, even if someone registers them (defence in depth).
DENIED_SEGMENTS: Final = frozenset(
    {
        "actions",
        "action",
        "exec",
        "execute",
        "exec-status",
        "file-write",
        "file-read",
        "termproxy",
        "vncproxy",
        "vncshell",
        "vncwebsocket",
        "spiceproxy",
        "spiceshell",
        "mtunnel",
        "mtunnelwebsocket",
        "migrate",
        "remote_migrate",
        "clone",
        "template",
        "resize",
        "move_disk",
        "move_volume",
        "start",
        "stop",
        "shutdown",
        "reboot",
        "reset",
        "suspend",
        "resume",
        "rollback",
        "upgrade",
        "restart",
        "delete",
        "set-user-password",
        "fsfreeze-freeze",
        "fsfreeze-thaw",
        "fstrim",
        "cmd",
        "pending-devices",
    }
)

LITERAL_SEGMENT_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
VAR_SEGMENT_RE: Final = re.compile(r"\{([a-z][a-z0-9_]{0,31})\}")
#: Absolute ceiling on a path variable value, whatever the endpoint's own pattern says.
SAFE_VALUE_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}")
QUERY_KEY_RE: Final = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,31}")
SAFE_QUERY_VALUE_RE: Final = re.compile(r"[A-Za-z0-9 ._:@,()'=-]{0,256}")


def _check_template(template: str) -> tuple[str, ...]:
    if not template.startswith("/") or template.endswith("/") or "//" in template:
        raise ValueError(f"bad path template: {template!r}")
    segments = tuple(template[1:].split("/"))
    for seg in segments:
        if VAR_SEGMENT_RE.fullmatch(seg):
            continue
        if not LITERAL_SEGMENT_RE.fullmatch(seg) or seg in {".", ".."}:
            raise ValueError(f"bad literal segment {seg!r} in {template!r}")
        if seg.lower() in DENIED_SEGMENTS:
            raise ValueError(f"denied segment {seg!r} in {template!r}")
    return segments


@dataclass(frozen=True, slots=True)
class Endpoint:
    """A single allowlisted HTTP operation.

    `path_vars` maps each `{var}` in the template to a full-match regex. `query` maps each
    allowed query key to a full-match regex. POST is only legal with a `body_model` and a
    written justification of why the call is read-only (e.g. a session login).
    """

    id: str
    method: HttpMethod
    path_template: str
    path_vars: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    query: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    body_model: type[BaseModel] | None = None
    read_only_justification: str = ""

    def __post_init__(self) -> None:
        validate_endpoint(self)
        # Freeze mappings so a caller-held dict cannot be mutated after registration.
        object.__setattr__(self, "path_vars", MappingProxyType(dict(self.path_vars)))
        object.__setattr__(self, "query", MappingProxyType(dict(self.query)))

    def __hash__(self) -> int:
        return hash(
            (
                self.id,
                self.method,
                self.path_template,
                tuple(sorted(self.path_vars.items())),
                tuple(sorted(self.query.items())),
                self.body_model,
            )
        )

    @property
    def op(self) -> str:
        """Audit-safe operation label: method + template, never expanded values."""
        return f"{self.method} {self.path_template}"


def validate_endpoint(ep: Endpoint) -> None:
    """Structural checks. Run at construction and again before every request."""
    if ep.method not in ("GET", "POST"):
        raise ValueError(f"{ep.id}: method {ep.method!r} not allowed")
    segments = _check_template(ep.path_template)
    template_vars = [m.group(1) for s in segments if (m := VAR_SEGMENT_RE.fullmatch(s))]
    if len(set(template_vars)) != len(template_vars):
        raise ValueError(f"{ep.id}: duplicate path variable")
    if set(template_vars) != set(ep.path_vars):
        raise ValueError(f"{ep.id}: path_vars must match template variables exactly")
    for pattern in (*ep.path_vars.values(), *ep.query.values()):
        re.compile(pattern)
    for key in ep.query:
        if not QUERY_KEY_RE.fullmatch(key):
            raise ValueError(f"{ep.id}: bad query key {key!r}")
    if ep.method == "POST":
        if ep.body_model is None or not ep.read_only_justification.strip():
            raise ValueError(f"{ep.id}: POST requires body_model and read_only_justification")
    elif ep.body_model is not None:
        raise ValueError(f"{ep.id}: GET must not have a body")
