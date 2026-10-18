"""Parse the probe's framed output (see templates/atlas-probe.sh).

The boundary is 24 random hex chars chosen per run, so collected data (file contents,
process names) cannot forge part headers unless it guesses the boundary.
"""

import re
from dataclasses import dataclass, field
from typing import Final

from homelab_atlas.security.allowlist import ProbeSection

HEADER_RE: Final = re.compile(r"ATLAS-PROBE 1 ([a-z]{1,16}) ([0-9a-f]{24})")
PART_NAME_RE: Final = re.compile(r"[A-Za-z0-9._:/-]{1,256}")


class FrameError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Part:
    name: str
    content: str
    rc: int


@dataclass(slots=True)
class Frame:
    section: ProbeSection
    parts: dict[str, Part] = field(default_factory=dict)
    complete: bool = False
    errors: list[str] = field(default_factory=list)

    def text(self, name: str) -> str | None:
        """Content of a part that exited 0, else None."""
        part = self.parts.get(name)
        return part.content if part is not None and part.rc == 0 else None


def parse_frame(data: bytes, expected: ProbeSection) -> Frame:
    text = data.decode("utf-8", errors="replace")
    header, _, rest = text.partition("\n")
    m = HEADER_RE.fullmatch(header)
    if m is None:
        raise FrameError("missing or malformed probe header")
    if m.group(1) != expected.value:
        raise FrameError(f"section mismatch: expected {expected.value}")
    frame = Frame(section=expected)
    marker = f"--{m.group(2)} "
    current: str | None = None
    buf: list[str] = []
    for line in rest.splitlines(keepends=True):
        if not line.startswith(marker):
            if current is not None:
                buf.append(line)
            continue
        directive = line[len(marker) :].rstrip("\n")
        if directive.startswith("part ") and current is None:
            name = directive[5:]
            if not PART_NAME_RE.fullmatch(name):
                frame.errors.append("bad part name")
                continue
            current, buf = name, []
        elif directive.startswith("rc ") and current is not None:
            rc_text = directive[3:]
            content = "".join(buf)
            # The probe prints one "\n" before the trailer; remove exactly that one.
            content = content.removesuffix("\n")
            if current in frame.parts:
                frame.errors.append(f"duplicate part {current}")
            elif rc_text.isdigit():
                frame.parts[current] = Part(current, content, int(rc_text))
            else:
                frame.errors.append(f"bad rc for {current}")
            current = None
        elif directive == "end" and current is None:
            frame.complete = True
        else:
            frame.errors.append("unexpected frame directive")
    if current is not None:
        frame.errors.append(f"truncated part {current}")
    if not frame.complete:
        frame.errors.append("frame incomplete (no end marker)")
    return frame
