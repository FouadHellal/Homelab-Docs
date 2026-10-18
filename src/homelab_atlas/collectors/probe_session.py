"""Shared plumbing for SSH collectors that read `os` (identity) plus their own section."""

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel

from homelab_atlas.collectors.base import CollectContext, CollectorResult, FacetResult
from homelab_atlas.collectors.linux_ssh.collector import EXIT_HINTS, host_key
from homelab_atlas.collectors.linux_ssh.frame import Frame, FrameError, parse_frame
from homelab_atlas.collectors.linux_ssh.parse import parse_os
from homelab_atlas.security.allowlist import ProbeSection
from homelab_atlas.security.errors import SecurityRefusal, TransportError


@dataclass(slots=True)
class SectionRun:
    machine_id: str | None = None
    frame: Frame | None = None
    errors: list[str] = field(default_factory=list)


async def run_with_identity(
    ctx: CollectContext, target: str, section: ProbeSection, requires: frozenset[ProbeSection]
) -> SectionRun:
    """Run `os` then `section` over one session. Raises SecurityRefusal / TransportError on
    connect failure; per-section problems are collected in `errors`."""
    host = ctx.inventory.host(target)
    run = SectionRun()
    ssh_target = ctx.inventory.ssh_target(host, requires)
    async with ctx.ssh.session(ssh_target) as session:
        for sec in (ProbeSection.OS, section):
            try:
                out = await session.run(sec)
            except (SecurityRefusal, TransportError) as exc:
                run.errors.append(f"{sec.value}: {type(exc).__name__}")
                continue
            if out.exit_status != 0:
                run.errors.append(
                    f"{sec.value}: {EXIT_HINTS.get(out.exit_status, f'exit {out.exit_status}')}"
                )
                continue
            try:
                frame = parse_frame(out.stdout, sec)
            except FrameError as exc:
                run.errors.append(f"{sec.value}: frame: {exc}")
                continue
            if sec is ProbeSection.OS:
                run.machine_id = getattr(parse_os(frame).values.get("os"), "machine_id", None)
            else:
                run.frame = frame
                run.errors.extend(f"{sec.value}: {e}" for e in frame.errors)
    return run


async def collect_section(
    ctx: CollectContext,
    target: str,
    *,
    collector: str,
    section: ProbeSection,
    requires: frozenset[ProbeSection],
    build: Callable[[Frame, list[str]], BaseModel | None],
    children: Callable[[str, str, BaseModel], list[FacetResult]] | None = None,
) -> CollectorResult:
    """Standard result for an identity+section collector (docker, pi)."""
    start = time.monotonic()
    result = CollectorResult(collector, target, "failed")
    try:
        run = await run_with_identity(ctx, target, section, requires)
    except SecurityRefusal as exc:
        result.status, result.errors = "refused", [f"refused: {exc.reason.value}"]
    except TransportError as exc:
        result.errors = [f"unreachable: {exc}"]
    else:
        result.errors = run.errors
        model = build(run.frame, run.errors) if run.frame is not None else None
        if model is not None:
            hkey = host_key(run.machine_id, target)
            result.facets = [FacetResult(hkey, "linux-host", target, model)]
            if children is not None:
                result.facets += children(hkey, target, model)
            result.complete = True
            result.status = "partial" if run.errors else "ok"
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
