"""Docker change events (SPEC §8): image updates, container lifecycle, published ports."""

from collections import defaultdict
from typing import Any

from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity


def _short(image_id: Any) -> str:
    text = str(image_id or "?")
    return text.removeprefix("sha256:")[:12]


def _port(v: dict[str, Any]) -> str:
    return f"{v.get('host_ip')}:{v.get('host_port')}->{v.get('container_port')}/{v.get('proto')}"


def docker_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []
    env: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"added": [], "removed": []})
    config: dict[str, set[str]] = defaultdict(set)
    grouped: dict[str, int] = defaultdict(int)
    unclaimed: list[Change] = []

    def ev(t: str, sev: Severity, summary: str, c: Change | None = None) -> None:
        out.append(
            EventSpec(
                key,
                t,
                sev,
                f"{name}: {summary}",
                c.dotted if c else "",
                c.old if c else None,
                c.new if c else None,
            )
        )

    for c in changes:
        p, k = c.path, c.kind
        if p[0] == "containers" and len(p) == 2:
            ctr = p[1]
            v = c.new if k == "added" else c.old
            image = v.get("image") if isinstance(v, dict) else "?"
            if k == "added":
                ev("container.added", "notice", f"container {ctr} ({image}) added", c)
                if isinstance(v, dict) and (v.get("privileged") or v.get("docker_socket")):
                    why = "privileged" if v.get("privileged") else "docker.sock mounted"
                    ev("container.risky", "warning", f"container {ctr} is {why}", c)
            else:
                ev("container.removed", "notice", f"container {ctr} ({image}) removed", c)
        elif p[0] == "containers" and len(p) >= 3:
            ctr, field = p[1], p[2]
            if field == "image_id":
                ev(
                    "image.updated",
                    "notice",
                    f"container {ctr} image updated ({_short(c.old)} -> {_short(c.new)})",
                    c,
                )
            elif field == "image":
                ev(
                    "container.image_changed",
                    "notice",
                    f"container {ctr} image {c.old} -> {c.new}",
                    c,
                )
            elif field == "status":
                if c.new in ("exited", "dead"):
                    ev("container.stopped", "warning", f"container {ctr} {c.new} (was {c.old})", c)
                elif c.new == "running":
                    ev("container.started", "info", f"container {ctr} running (was {c.old})", c)
                else:
                    ev("container.state_changed", "info", f"container {ctr} {c.old} -> {c.new}", c)
            elif field == "health":
                if c.new == "unhealthy":
                    ev("container.unhealthy", "warning", f"container {ctr} unhealthy", c)
                else:
                    ev(
                        "container.health_changed",
                        "info",
                        f"container {ctr} health {c.old} -> {c.new}",
                        c,
                    )
            elif field == "restart_count":
                if isinstance(c.old, int) and isinstance(c.new, int) and c.new > c.old:
                    ev(
                        "container.restarted",
                        "notice",
                        f"container {ctr} restarted {c.new - c.old}x (total {c.new})",
                        c,
                    )
            elif field == "ports" and len(p) == 4 and k in ("added", "removed"):
                v = c.new if k == "added" else c.old
                verb = "published" if k == "added" else "unpublished"
                ev(f"port.{verb}", "notice", f"container {ctr} {verb} {_port(v)}", c)
            elif field == "env_names" and len(p) == 4 and k in ("added", "removed"):
                env[ctr][k].append(p[3])
            elif field in ("privileged", "docker_socket") and c.new is True:
                ev(
                    "container.risky",
                    "warning",
                    f"container {ctr} now {field.replace('_', ' ')}",
                    c,
                )
            else:
                config[ctr].add(field)
        elif p[0] in ("images", "volumes", "networks", "compose_projects") and len(p) >= 2:
            if p[0] == "compose_projects" and len(p) == 2:
                ev(f"compose.project_{k}", "notice", f"compose project {p[1]} {k}", c)
            elif p[0] == "networks" and len(p) == 2:
                ev(f"docker_network.{k}", "info", f"docker network {p[1]} {k}", c)
            elif p[0] == "volumes" and len(p) == 2:
                ev(f"volume.{k}", "info", f"volume {p[1]} {k}", c)
            else:
                grouped[p[0]] += 1
        elif p == ("engine_version",):
            ev("docker.upgraded", "notice", f"docker engine {c.old} -> {c.new}", c)
        elif p == ("api_version",):
            pass  # follows engine_version
        else:
            unclaimed.append(c)

    for ctr, kinds in sorted(env.items()):
        parts = [f"{k} {', '.join(sorted(v))}" for k, v in kinds.items() if v]
        ev("container.env_changed", "notice", f"container {ctr} env vars {'; '.join(parts)}")
    for ctr, fields in sorted(config.items()):
        ev(
            "container.config_changed",
            "info",
            f"container {ctr} changed: {', '.join(sorted(fields))}",
        )
    for what, n in sorted(grouped.items()):
        ev(f"{what}.changed", "info", f"{n} {what.replace('_', ' ')} change(s)")
    if unclaimed:
        where = sorted({".".join(c.path[:2]) for c in unclaimed})
        ev("facts.changed", "info", f"{len(unclaimed)} other changes in {', '.join(where[:8])}")
    return out
