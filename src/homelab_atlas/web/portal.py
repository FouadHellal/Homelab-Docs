"""Portal: shortcuts to the owner's web UIs, editable in the UI, optionally public (ADR-049).

Shortcuts are user data, never target data: they live in their own tables, are validated
here (http/https only, no credentials in the URL, bounded lengths) and are only ever rendered
through autoescaped templates. Nothing here makes a network request: logos are vendored
Simple Icons paths (brands.json), so the portal works offline and the CSP stays strict.
"""

import itertools
import json
import re
import zlib
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal
from urllib.parse import urlsplit

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from homelab_atlas.store.tables import PortalCategory, PortalLink, PortalSetting, utcnow

MAX_NAME: Final = 80
MAX_CATEGORY: Final = 64
MAX_DESC: Final = 160
MAX_URL: Final = 2048
MAX_LINKS: Final = 500
MAX_CATEGORIES: Final = 40
TINTS: Final = 8
SEED_FILE: Final = "portal-seed.yaml"
MAX_SEED_BYTES: Final = 256 * 1024

BRANDS: Final[dict[str, dict[str, str]]] = json.loads(
    (files("homelab_atlas.web") / "brands.json").read_text(encoding="utf-8")
)

#: Simple line glyphs for services without a recognisable logo (24x24, stroked).
GLYPHS: Final[dict[str, tuple[str, str]]] = {
    "globe": (
        "Website",
        "M12 3a9 9 0 1 0 0 18 9 9 0 1 0 0-18ZM3 12h18"
        "M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z",
    ),
    "mail": ("Mail", "M4 6h16v12H4zM4 7l8 6 8-6"),
    "power": ("Power / Wake-on-LAN", "M12 3v8M6.3 6.8a8 8 0 1 0 11.4 0"),
    "calendar": ("Calendar", "M5 5h14v15H5zM5 10h14M9 3v4M15 3v4"),
    "folder": (
        "Folder",
        "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z",
    ),
    "server": ("Server", "M4 4h16v7H4zM4 13h16v7H4zM8 7.5h.01M8 16.5h.01"),
    "router": (
        "Router",
        "M3 14h18v6H3zM7 17h.01M11 17h.01M8.5 10.5a5 5 0 0 1 7 0M6 8a8.5 8.5 0 0 1 12 0",
    ),
    "chart": ("Monitoring", "M4 20V4M4 20h16M8 16v-5M12 16V8M16 16v-3"),
    "shield": ("Security", "M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6Z"),
    "task": (
        "Tasks / tickets",
        "M10 6h10M10 12h10M10 18h10M4 6l1.2 1.2L7.5 5M4 12l1.2 1.2 2.3-2.2M4 18l1.2 1.2 2.3-2.2",
    ),
    "cloud": ("Cloud", "M7 18a4.5 4.5 0 1 1 .9-8.9A6 6 0 0 1 19 11a3.5 3.5 0 0 1-.5 7Z"),
    "terminal": ("Terminal", "M4 5h16v14H4zM8 10l3 2.5L8 15M13 15h3"),
    "cap": ("University", "M2 9l10-5 10 5-10 5ZM6 11v5c3 2.5 9 2.5 12 0v-5M22 9v5"),
    "doc": ("Document", "M6 3h8l4 4v14H6zM14 3v4h4M9 12h6M9 16h6"),
    "book": ("Book / course", "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3ZM5 17a3 3 0 0 1 3-3h10"),
}

#: Name/host words that mean a brand whose slug differs from the word.
ALIASES: Final[dict[str, str]] = {
    "unifi": "ubiquiti",
    "omada": "tplink",
    "tplinkcloud": "tplink",
    "mosquitto": "eclipsemosquitto",
    "traefik": "traefikproxy",
    "nginxproxy": "nginxproxymanager",
    "pve": "proxmox",
    "hass": "homeassistant",
    "paperless": "paperlessngx",
    "azure": "azure",
}
#: Words that pick a glyph when no brand matched.
GLYPH_WORDS: Final[dict[str, str]] = {
    "mail": "mail",
    "webmail": "mail",
    "wol": "power",
    "wake": "power",
    "calendar": "calendar",
    "events": "calendar",
    "drive": "folder",
    "files": "folder",
    "monitor": "chart",
    "dashboard": "chart",
    "router": "router",
    "gateway": "router",
    "firewall": "shield",
    "vpn": "shield",
    "ssh": "terminal",
    "moodle": "book",
    "course": "book",
    "university": "cap",
}

_WORD = re.compile(r"[a-z0-9]+")


class PortalError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Icon:
    kind: Literal["brand", "letters", "glyph", "atlas"]
    title: str
    css: str  # colour class: b-<slug> or t-<n>
    path: str = ""  # SVG path (brand fill or glyph stroke)
    text: str = ""  # lettermark text


def _tint(seed: str) -> str:
    return f"t-{zlib.crc32(seed.encode()) % TINTS}"


def initials(name: str) -> str:
    words: list[str] = re.findall(r"[A-Za-z0-9]+", name.split("·", maxsplit=1)[0])
    if not words:
        return "?"
    if len(words) == 1:
        w = words[0]
        return (w[0].upper() + w[1:2].lower()) if len(w) > 1 else w.upper()
    return (words[0][0] + words[1][0]).upper()


def _words(name: str, url: str) -> list[str]:
    host = (urlsplit(url).hostname or "") if url else ""
    words = _WORD.findall(name.lower()) + _WORD.findall(host.lower())
    joined = "".join(_WORD.findall(name.lower()))
    pairs = [a + b for a, b in itertools.pairwise(words)]
    return [*words, *pairs, joined]


def auto_icon(name: str, url: str) -> str:
    """The icon value 'automatic' resolves to: a brand, a glyph, or letters."""
    words = _words(name, url)
    for w in words:
        slug = ALIASES.get(w, w)
        if slug in BRANDS:
            return f"brand:{slug}"
    for w in words:
        if w in GLYPH_WORDS:
            return f"glyph:{GLYPH_WORDS[w]}"
    return "letters"


def resolve_icon(icon: str, name: str, url: str) -> Icon:
    value = icon or auto_icon(name, url)
    kind, _, arg = value.partition(":")
    if value == "atlas":
        return Icon("atlas", "atlas", "t-atlas")
    if kind == "brand" and arg in BRANDS:
        b = BRANDS[arg]
        return Icon("brand", b["title"], f"b-{arg}", path=b.get("path", ""), text=b.get("text", ""))
    if kind == "glyph" and arg in GLYPHS:
        return Icon("glyph", GLYPHS[arg][0], _tint(name), path=GLYPHS[arg][1])
    return Icon("letters", name, _tint(name), text=initials(name))


def icon_choices() -> dict[str, list[tuple[str, str]]]:
    """For the editor's icon <select>: group -> [(value, label)]."""
    return {
        "Logos": [(f"brand:{k}", v["title"]) for k, v in BRANDS.items()],
        "Symbols": sorted(((f"glyph:{k}", v[0]) for k, v in GLYPHS.items()), key=lambda x: x[1]),
        "Other": [("letters", "Letters from the name"), ("atlas", "atlas logo")],
    }


def valid_icon(value: str) -> bool:
    kind, _, arg = value.partition(":")
    return (
        value in ("", "letters", "atlas")
        or (kind == "brand" and arg in BRANDS)
        or (kind == "glyph" and arg in GLYPHS)
    )


def clean_url(raw: str) -> str:
    url = raw.strip()
    if not url:
        raise PortalError("Add a URL, for example https://10.0.0.100:8006/")
    if len(url) > MAX_URL:
        raise PortalError(f"That URL is longer than {MAX_URL} characters.")
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise PortalError("Remove the spaces from the URL.")
    if "://" not in url:
        raise PortalError("Start the URL with http:// or https://")
    try:
        parts = urlsplit(url)
        host, _port = parts.hostname, parts.port  # .port raises on a bad port
    except ValueError:
        raise PortalError("That URL could not be read; check the host and port.") from None
    if parts.scheme.lower() not in ("http", "https"):
        raise PortalError("Only http:// and https:// links are allowed.")
    if not host:
        raise PortalError("The URL needs a host name or IP address.")
    if parts.username is not None or parts.password is not None:
        raise PortalError(
            "Remove the user name or password from the URL; shortcuts never store credentials."
        )
    return url


def host_label(url: str) -> str:
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        port = parts.port
    except ValueError:
        return ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}" if port else host


def _text(raw: str, limit: int, what: str, *, required: bool = False) -> str:
    value = " ".join(raw.split())  # one line, no control characters
    if required and not value:
        raise PortalError(f"Add a {what}.")
    if len(value) > limit:
        raise PortalError(f"Keep the {what} under {limit} characters.")
    return value


# ---------------------------------------------------------------- settings


def is_public(s: Session) -> bool:
    row = s.get(PortalSetting, "public")
    return row is not None and row.value == "1"


def set_public(s: Session, on: bool) -> None:
    row = s.get(PortalSetting, "public")
    if row is None:
        s.add(PortalSetting(key="public", value="1" if on else "0"))
    else:
        row.value = "1" if on else "0"


# ---------------------------------------------------------------- read


def categories(s: Session) -> list[PortalCategory]:
    return list(
        s.scalars(select(PortalCategory).order_by(PortalCategory.position, PortalCategory.id))
    )


def _links(s: Session) -> list[PortalLink]:
    return list(s.scalars(select(PortalLink).order_by(PortalLink.position, PortalLink.id)))


def link_view(link: PortalLink, category: str = "") -> dict[str, Any]:
    host = host_label(link.url)
    return {
        "id": link.id,
        "name": link.name,
        "url": link.url,
        "description": link.description,
        "host": host,
        "icon": resolve_icon(link.icon, link.name, link.url),
        "icon_value": link.icon,
        "favorite": link.favorite,
        "public": link.public,
        "category_id": link.category_id,
        "category": category,
        "search": " ".join([link.name, link.description, host, category]).lower(),
    }


def view(s: Session, *, signed_in: bool) -> dict[str, Any]:
    """What the portal shows: everything when signed in, else public shortcuts (if enabled)."""
    public = is_public(s)
    show_any = signed_in or public
    cats = categories(s)
    names = {c.id: c.name for c in cats}
    by_cat: dict[int, list[dict[str, Any]]] = {c.id: [] for c in cats}
    for link in _links(s) if show_any else []:
        if not signed_in and not link.public:
            continue
        if link.category_id in by_cat:
            by_cat[link.category_id].append(link_view(link, names[link.category_id]))
    groups: list[dict[str, Any]] = [
        {"id": c.id, "name": c.name, "slug": f"c{c.id}", "links": by_cat[c.id]}
        for c in cats
        if by_cat[c.id] or signed_in
    ]
    favorites = [x for g in groups for x in g["links"] if x["favorite"]]
    hidden = 0
    if not signed_in:
        total = s.scalar(select(func.count()).select_from(PortalLink)) or 0
        hidden = total - sum(len(g["links"]) for g in groups)
    return {
        "groups": groups,
        "favorites": favorites,
        "public": public,
        "hidden": hidden,
        "count": sum(len(g["links"]) for g in groups),
    }


def known_urls(s: Session) -> set[str]:
    return {_norm(u) for u in s.scalars(select(PortalLink.url))}


def _norm(url: str) -> str:
    try:
        p = urlsplit(url.strip())
        return f"{p.scheme.lower()}://{(p.hostname or '').lower()}:{p.port or ''}"
    except ValueError:
        return url


def suggestions(s: Session, quick: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Web UIs atlas found in the inventory that no shortcut points at yet (same host:port)."""
    have = known_urls(s)
    out, seen = [], set()
    for q in quick:
        url = str(q.get("url") or "")
        key = _norm(url)
        if not url or key in have or key in seen:
            continue
        try:
            clean_url(url)
        except PortalError:
            continue
        seen.add(key)
        name = str(q.get("name") or "")
        where = str(q.get("where") or "")
        label = f"{name} · {where}" if where and where not in ("pinned", "gateway") else name
        out.append(
            {
                "name": label[:MAX_NAME],
                "url": url,
                "host": host_label(url),
                "icon": resolve_icon("", name, url),
            }
        )
    return out


# ---------------------------------------------------------------- write


def _renumber(rows: list[Any]) -> None:
    for i, r in enumerate(rows, start=1):
        r.position = i * 10


def _category(s: Session, cid: int) -> PortalCategory:
    cat = s.get(PortalCategory, cid)
    if cat is None:
        raise PortalError("That category no longer exists.")
    return cat


def _link(s: Session, lid: int) -> PortalLink:
    link = s.get(PortalLink, lid)
    if link is None:
        raise PortalError("That shortcut no longer exists.")
    return link


def save_category(s: Session, cid: int | None, name: str) -> PortalCategory:
    clean = _text(name, MAX_CATEGORY, "category name", required=True)
    if cid is not None:
        cat = _category(s, cid)
        cat.name = clean
        return cat
    if (s.scalar(select(func.count()).select_from(PortalCategory)) or 0) >= MAX_CATEGORIES:
        raise PortalError(f"atlas keeps at most {MAX_CATEGORIES} categories.")
    last = s.scalar(select(func.max(PortalCategory.position))) or 0
    cat = PortalCategory(name=clean, position=last + 10)
    s.add(cat)
    s.flush()
    return cat


def delete_category(s: Session, cid: int) -> tuple[str, int]:
    cat = _category(s, cid)
    n = s.execute(delete(PortalLink).where(PortalLink.category_id == cid)).rowcount or 0  # type: ignore[attr-defined]
    s.delete(cat)
    return cat.name, n


def save_link(
    s: Session,
    lid: int | None,
    *,
    category_id: int,
    name: str,
    url: str,
    description: str = "",
    icon: str = "",
    favorite: bool = False,
    public: bool = False,
) -> PortalLink:
    cat = _category(s, category_id)
    clean_name = _text(name, MAX_NAME, "name", required=True)
    clean_desc = _text(description, MAX_DESC, "description")
    clean = clean_url(url)
    icon = icon.strip()
    if not valid_icon(icon):
        raise PortalError("Pick an icon from the list.")
    if lid is None:
        if (s.scalar(select(func.count()).select_from(PortalLink)) or 0) >= MAX_LINKS:
            raise PortalError(f"atlas keeps at most {MAX_LINKS} shortcuts.")
        link = PortalLink(category_id=cat.id, name=clean_name, url=clean)
        s.add(link)
    else:
        link = _link(s, lid)
    if link.category_id != cat.id or lid is None:
        last = s.scalar(
            select(func.max(PortalLink.position)).where(PortalLink.category_id == cat.id)
        )
        link.position = (last or 0) + 10
    link.category_id = cat.id
    link.name, link.url, link.description, link.icon = clean_name, clean, clean_desc, icon
    link.favorite, link.public = favorite, public
    link.updated_at = utcnow()
    s.flush()
    return link


def delete_link(s: Session, lid: int) -> str:
    link = _link(s, lid)
    s.delete(link)
    return link.name


def toggle(s: Session, lid: int, field: Literal["favorite", "public"]) -> PortalLink:
    link = _link(s, lid)
    setattr(link, field, not getattr(link, field))
    link.updated_at = utcnow()
    return link


def _swap(rows: list[Any], target: Any, direction: str) -> None:
    _renumber(rows)
    i = rows.index(target)
    j = i - 1 if direction == "up" else i + 1
    if 0 <= j < len(rows):
        rows[i].position, rows[j].position = rows[j].position, rows[i].position


def move_link(s: Session, lid: int, direction: str) -> PortalLink:
    link = _link(s, lid)
    rows = list(
        s.scalars(
            select(PortalLink)
            .where(PortalLink.category_id == link.category_id)
            .order_by(PortalLink.position, PortalLink.id)
        )
    )
    _swap(rows, link, direction)
    return link


def move_category(s: Session, cid: int, direction: str) -> PortalCategory:
    cat = _category(s, cid)
    _swap(categories(s), cat, direction)
    return cat


# ---------------------------------------------------------------- import / seed


def parse_seed(text: str) -> dict[str, Any]:
    """Validate a portal YAML document (the seed file, or what was pasted in the editor).

    public: true                      # optional: show public shortcuts before login
    categories:
      - name: Home Lab
        links:
          - {name: Proxmox, url: "https://10.0.0.2:8006/", icon: brand:proxmox, favorite: true}

    Every link is checked like a form entry; nothing is written unless all of them pass.
    """
    if len(text.encode()) > MAX_SEED_BYTES:
        raise PortalError("That is more than 256 KB; import it in parts.")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise PortalError(f"That is not valid YAML{where}.") from None
    if not isinstance(doc, dict) or not isinstance(doc.get("categories"), list):
        raise PortalError("Start with 'categories:', a list of {name, links}.")
    public = doc.get("public")
    if public is not None and not isinstance(public, bool):
        raise PortalError("'public' is true or false.")
    out: list[dict[str, Any]] = []
    for cat in doc["categories"]:
        if not isinstance(cat, dict) or not isinstance(cat.get("links", []), list):
            raise PortalError("Each category needs a name and a list of links.")
        cname = _text(str(cat.get("name") or ""), MAX_CATEGORY, "category name", required=True)
        links = []
        for raw in cat.get("links") or []:
            if not isinstance(raw, dict):
                raise PortalError(f"{cname}: each link is a mapping with name and url.")
            name = str(raw.get("name") or "")
            try:
                link: dict[str, Any] = {
                    "name": _text(name, MAX_NAME, "name", required=True),
                    "url": clean_url(str(raw.get("url") or "")),
                    "description": _text(
                        str(raw.get("description") or ""), MAX_DESC, "description"
                    ),
                    "icon": str(raw.get("icon") or "").strip(),
                    "favorite": raw.get("favorite") is True,
                    "public": raw["public"] is True if "public" in raw else public is True,
                }
            except PortalError as exc:
                raise PortalError(f"{cname} > {name or '?'}: {exc}") from None
            if not valid_icon(link["icon"]):
                raise PortalError(f"{cname} > {name}: unknown icon {link['icon'][:40]!r}.")
            links.append(link)
        out.append({"name": cname, "links": links})
    if sum(len(c["links"]) for c in out) > MAX_LINKS:
        raise PortalError(f"atlas keeps at most {MAX_LINKS} shortcuts.")
    return {"public": public, "categories": out}


def import_seed(s: Session, doc: dict[str, Any]) -> tuple[int, int]:
    """Add what `parse_seed` returned. A link already present (same name and URL) is skipped,
    so importing the same file twice never duplicates anything. Returns (added, skipped)."""
    have = {(x.name, x.url) for x in _links(s)}
    by_name = {c.name.lower(): c for c in categories(s)}
    added = skipped = 0
    for cat in doc["categories"]:
        row = by_name.get(cat["name"].lower()) or save_category(s, None, cat["name"])
        by_name[row.name.lower()] = row
        for link in cat["links"]:
            if (link["name"], link["url"]) in have:
                skipped += 1
                continue
            save_link(s, None, category_id=row.id, **link)
            have.add((link["name"], link["url"]))
            added += 1
    if doc.get("public") is not None:
        set_public(s, bool(doc["public"]))
    return added, skipped


def seed_once(s: Session, path: Path | None) -> tuple[int, int] | None:
    """Import `config/portal-seed.yaml` the first time atlas sees it, then never again: a
    marker in the database keeps later edits and deletions from being overwritten."""
    if path is None or s.get(PortalSetting, "seeded") is not None or not path.is_file():
        return None
    doc = parse_seed(path.read_text(encoding="utf-8"))
    result = import_seed(s, doc)
    s.add(PortalSetting(key="seeded", value=utcnow().isoformat(timespec="seconds")))
    return result
