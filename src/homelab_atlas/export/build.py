"""Build one export document from the database, then render it in several formats.

The document is plain JSON-able data (schema `atlas-export/1`). Sanitizing happens on the
document before rendering, so every format gets the same treatment.
"""

import csv
import hashlib
import html
import io
import json
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from homelab_atlas import __version__
from homelab_atlas.export.sanitize import Sanitizer
from homelab_atlas.store.facets import facet_views
from homelab_atlas.store.tables import Annotation, Entity, Facet
from homelab_atlas.web import queries, topology

SCHEMA: Final = "atlas-export/1"
#: OWASP CSV injection: cells starting with these are evaluated by spreadsheet apps.
CSV_FORMULA_START: Final = frozenset("=+-@\t\r")
KIND_PREFIX: Final = {
    "linux-host": "host",
    "pve-vm": "vm",
    "pve-lxc": "ct",
    "pve-node": "node",
    "pve-cluster": "cluster",
    "unifi-device": "net",
    "unifi-site": "site",
    "container": "ctr",
    "compose-project": "proj",
    "nas": "nas",
    "unknown-device": "dev",
}


def build(s: Session) -> dict[str, Any]:
    entities = [
        e
        for e in s.scalars(select(Entity).order_by(Entity.kind, Entity.display_name))
        if e.status != "gone"
    ]
    facets: dict[str, dict[str, Any]] = {}
    for f in facet_views(s.scalars(select(Facet))):
        facets.setdefault(f.entity_key, {})[f.collector] = f.data
    notes = {a.entity_key: a for a in s.scalars(select(Annotation))}
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "atlas_version": __version__,
        "entities": [
            {
                "key": e.key,
                "name": e.display_name,
                "kind": e.kind,
                "status": e.status,
                "parent": e.parent_key,
                "same_as": e.same_as,
                "first_seen": e.first_seen.isoformat(),
                "last_seen": e.last_seen.isoformat(),
                "annotation": (
                    {
                        "owner": a.owner,
                        "purpose": a.purpose,
                        "criticality": a.criticality,
                        "tags": a.tags,
                        "links": a.links,
                        "notes": a.notes,
                    }
                    if (a := notes.get(e.key))
                    else None
                ),
                "facets": facets.get(e.key, {}),
            }
            for e in entities
        ],
        "ips": queries.ip_table(s),
        "vlans": queries.vlan_table(s),
        "ports": queries.port_table(s),
        "unknown": [
            {k: v for k, v in u.items() if k != "entity"} | {"name": u["entity"].display_name}
            for u in queries.unknown_devices(s)
        ],
        "changes": [
            {
                "at": r["at"].isoformat(),
                "type": r["event"].type,
                "severity": r["event"].severity,
                "entity": r["event"].entity_key,
                "summary": r["event"].summary,
            }
            for r in queries.changes(s, limit=500)
        ],
        "topology": {
            "physical": topology.build(s, "physical"),
            "logical": topology.build(s, "logical"),
        },
    }


def register_names(san: Sanitizer, entities: Iterable[dict[str, Any]]) -> None:
    """Every name worth hiding: entity names plus hostnames, SSIDs, clients, domains in facets.

    Shared by `--sanitize` exports and `atlas mcp --sanitize` so both hide the same things.
    """
    for e in entities:
        prefix = KIND_PREFIX.get(e["kind"], "obj")
        names = {e["name"], *e["name"].replace("(", " ").split()}
        san.register(
            [n for n in names if len(n) > 2 and not n.isupper() and not n.isdigit()], prefix
        )
        for f in e["facets"].values():
            if not isinstance(f, dict):
                continue
            if isinstance(f.get("os"), dict):
                san.register([f["os"].get("hostname") or ""], prefix)
            for ssid in f.get("ssids") or []:
                san.register([ssid.get("name") or ""], "ssid")
            for c in f.get("clients") or []:
                san.register([c.get("name") or ""], "client")
            for d in f.get("search_domains") or []:
                san.register([d], "domain")


def sanitizer_from_db(s: Session, key: bytes) -> Sanitizer:
    facets: dict[str, dict[str, Any]] = {}
    for f in s.scalars(select(Facet)):
        facets.setdefault(f.entity_key, {})[f.collector] = f.data
    san = Sanitizer(key)
    register_names(
        san,
        (
            {"name": e.display_name, "kind": e.kind, "facets": facets.get(e.key, {})}
            for e in s.scalars(select(Entity).order_by(Entity.kind, Entity.display_name))
        ),
    )
    return san


def sanitize(doc: dict[str, Any], key: bytes) -> dict[str, Any]:
    san = Sanitizer(key)
    register_names(san, doc["entities"])
    out: dict[str, Any] = san.data(doc)
    for e in out["entities"]:
        e["annotation"] = None  # owner/purpose/notes/links never leave in sanitized exports
    out["sanitized"] = True
    return out


# ------------------------------------------------------------------ renderers


def to_json(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False, sort_keys=True) + "\n"


def _csv_cell(value: Any) -> Any:
    """Lists joined; text that a spreadsheet would run as a formula gets a leading quote."""
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    if isinstance(value, str) and value[:1] in CSV_FORMULA_START:
        return "'" + value
    return value


def csv_table(rows: list[dict[str, Any]], cols: list[str]) -> str:
    """CSV text with a header; formula-looking cells are neutralised (see _csv_cell)."""
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore", lineterminator="\n")
    w.writeheader()
    for r in rows:
        w.writerow({c: _csv_cell(r.get(c)) for c in cols})
    return buf.getvalue()


def to_csv(doc: dict[str, Any]) -> dict[str, str]:
    table = csv_table

    containers = [
        {
            "host": e["name"],
            **c,
            "ports": [
                f"{p['host_ip']}:{p['host_port']}->{p['container_port']}/{p['proto']}"
                for p in c.get("ports", [])
            ],
        }
        for e in doc["entities"]
        for c in (e["facets"].get("docker") or {}).get("containers", [])
    ]
    return {
        "hosts.csv": table(
            doc["entities"], ["name", "kind", "status", "key", "parent", "same_as", "last_seen"]
        ),
        "ips.csv": table(
            doc["ips"], ["ip", "prefix", "name", "mac", "iface", "network", "vlan", "source"]
        ),
        "ports.csv": table(doc["ports"], ["port", "proto", "address", "name", "what", "source"]),
        "vlans.csv": table(
            doc["vlans"], ["vlan", "name", "subnet", "gateway", "dhcp", "ssids", "members"]
        ),
        "containers.csv": table(
            containers,
            [
                "host",
                "key",
                "image",
                "status",
                "health",
                "ports",
                "compose_project",
                "restart_policy",
            ],
        ),
        "unknown.csv": table(
            doc["unknown"], ["name", "mac", "ip", "network", "vlan", "uplink", "seen_via"]
        ),
    }


def _short_hash(text: str, n: int = 6) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:n]  # stable across runs, unlike hash()


def _mm_id(text: str) -> str:
    return "n" + re.sub(r"[^A-Za-z0-9_]", "_", text)[:40] + _short_hash(text)


def _mm_label(text: str) -> str:
    # Also used for YAML double-quoted nav labels, hence the backslash.
    return re.sub(r'["\[\]{}()<>|#;`\\&]', " ", text).replace("\n", " ").strip()[:60] or "?"


def to_mermaid(elements: list[dict[str, Any]]) -> str:
    ids = {e["data"]["id"]: _mm_id(e["data"]["id"]) for e in elements if "source" not in e["data"]}
    lines = ["flowchart TB"]
    for e in elements:
        d = e["data"]
        if "source" not in d:
            lines.append(f'  {ids[d["id"]]}["{_mm_label(d.get("label", d["id"]))}"]')
    for e in elements:
        d = e["data"]
        if "source" in d and d["source"] in ids and d["target"] in ids:
            arrow = "-.->" if d.get("kind") == "wireless" else "-->"
            lines.append(f"  {ids[d['source']]} {arrow} {ids[d['target']]}")
    return "\n".join(lines) + "\n"


MD_SPECIAL_RE: Final = re.compile(r"([\\`*_\[\]|!~{}])")


def _md_text(text: str) -> str:
    """Target data as inert Markdown text: no HTML, links, emphasis, code or new blocks.

    MkDocs renders raw HTML, so a container label like `<script>` or `[x](javascript:..)`
    would otherwise execute on a published site.
    """
    one_line = " ".join(text.split())
    return MD_SPECIAL_RE.sub(r"\\\1", html.escape(one_line, quote=False))


def _md_safe(obj: Any) -> Any:
    if isinstance(obj, str):
        return _md_text(obj)
    if isinstance(obj, dict):
        return {k: _md_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_md_safe(v) for v in obj]
    return obj


def _md_table(rows: list[dict[str, Any]], cols: list[str]) -> str:
    """Rows must already be `_md_safe` (so `|` is escaped and nothing spans lines)."""

    def cell(v: Any) -> str:
        if isinstance(v, list):
            v = ", ".join(map(str, v))
        return "" if v is None else str(v)

    head = "| " + " | ".join(cols) + " |\n|" + "---|" * len(cols) + "\n"
    return head + "".join("| " + " | ".join(cell(r.get(c)) for c in cols) + " |\n" for r in rows)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:60] or "entity"


def _entity_md(e: dict[str, Any]) -> str:
    out = [f"# {e['name']}\n", f"{e['key']} · {e['kind']} · {e['status']}\n"]
    if a := e.get("annotation"):
        out.append(_md_table([a], ["owner", "purpose", "criticality", "tags"]))
        if a.get("notes"):
            out.append(f"\n{a['notes']}\n")
    f = e["facets"]
    if (lx := f.get("linux-ssh")) and lx.get("os"):
        os_ = lx["os"]
        out.append(f"\n## Linux\n\n{os_.get('os_pretty')} · kernel {os_.get('kernel')}\n\n")
        out.append(
            _md_table(
                [
                    {
                        "name": i["name"],
                        "mac": i.get("mac"),
                        "addresses": [a["address"] for a in i["addresses"]],
                    }
                    for i in lx.get("interfaces", [])
                ],
                ["name", "mac", "addresses"],
            )
        )
        out.append(
            "\n### Listening\n\n"
            + _md_table(lx.get("sockets", []), ["proto", "address", "port", "process"])
        )
    if d := f.get("docker"):
        out.append(f"\n## Docker {d.get('engine_version')}\n\n")
        out.append(_md_table(d.get("containers", []), ["key", "image", "status", "health"]))
    if p := f.get("proxmox"):
        if "vmid" in p:
            out.append(
                f"\n## Proxmox guest\n\n{p['type']} {p['vmid']} on {p['node']} · {p['status']} · "
                f"{p.get('cores')} cores · {p.get('memory_mb')} MiB · "
                f"backed up: {p.get('backed_up')}\n\n"
            )
            out.append(_md_table(p.get("nics", []), ["slot", "model", "mac", "bridge", "vlan_tag"]))
        elif "pve_version" in p:
            out.append(
                f"\n## Proxmox node\n\nPVE {p.get('pve_version')} · kernel {p.get('kernel')}\n\n"
            )
            out.append(
                _md_table(
                    p.get("interfaces", []), ["iface", "type", "cidr", "vlan_id", "bridge_ports"]
                )
            )
    if (u := f.get("unifi")) and "mac" in u:
        out.append(
            f"\n## UniFi device\n\n{u.get('model')} · fw {u.get('firmware')} · {u.get('state')}\n"
        )
    return "\n".join(out) + "\n"


def to_markdown(doc: dict[str, Any]) -> str:
    topo = doc["topology"]  # mermaid labels have their own sanitiser
    doc = _md_safe({k: v for k, v in doc.items() if k != "topology"})
    parts = [
        f"# Homelab inventory\n\nGenerated {doc['generated_at']} by atlas {doc['atlas_version']}"
        f"{' (sanitized)' if doc.get('sanitized') else ''}.\n",
        "## Machines and devices\n",
        _md_table(doc["entities"], ["name", "kind", "status", "same_as"]),
        "\n## VLANs\n",
        _md_table(doc["vlans"], ["vlan", "name", "subnet", "ssids", "members"]),
        "\n## IP addresses\n",
        _md_table(doc["ips"], ["ip", "name", "mac", "network", "vlan"]),
        "\n## Ports\n",
        _md_table(doc["ports"], ["port", "proto", "address", "name", "what"]),
        "\n## Unknown devices\n",
        _md_table(doc["unknown"], ["name", "mac", "ip", "network", "vlan"]),
        "\n## Physical topology\n\n```mermaid\n" + to_mermaid(topo["physical"]) + "```\n",
        "\n## Recent changes\n",
        _md_table(doc["changes"][:100], ["at", "severity", "type", "summary"]),
    ]
    return "\n".join(parts)


def write_mkdocs(doc: dict[str, Any], out: Path) -> list[Path]:
    """A plain MkDocs site; mermaid blocks render with mkdocs-material + pymdownx.superfences."""
    pages = out / "docs"
    (pages / "hosts").mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    def w(path: Path, text: str) -> None:
        path.write_bytes(text.encode())
        written.append(path)

    nav_hosts = []
    for e in doc["entities"]:
        if e["kind"] in ("container", "compose-project"):
            continue
        name = f"{_slug(e['name'])}-{_short_hash(e['key'])}.md"
        w(pages / "hosts" / name, _entity_md(_md_safe(e)))
        nav_hosts.append(f'      - "{_mm_label(e["name"])}": hosts/{name}')
    w(pages / "index.md", to_markdown(doc))
    w(
        pages / "topology.md",
        "# Topology\n\n## Physical\n\n```mermaid\n"
        + to_mermaid(doc["topology"]["physical"])
        + "```\n\n## Logical\n\n```mermaid\n"
        + to_mermaid(doc["topology"]["logical"])
        + "```\n",
    )
    w(
        out / "mkdocs.yml",
        "\n".join(
            [
                "site_name: Homelab inventory",
                "theme:",
                "  name: material",
                "markdown_extensions:",
                "  - tables",
                "  - toc:",
                "      permalink: true",
                "  - pymdownx.superfences:",
                "      custom_fences:",
                "        - name: mermaid",
                "          class: mermaid",
                "          format: !!python/name:pymdownx.superfences.fence_code_format",
                "nav:",
                "  - Overview: index.md",
                "  - Topology: topology.md",
                "  - Hosts:",
                *sorted(nav_hosts),
                "",
            ]
        ),
    )
    return written
