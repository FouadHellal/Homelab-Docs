"""jellyfin collector (ADR-039): server health, libraries, tasks and sessions over the API.

Sources: the Jellyfin OpenAPI (api.jellyfin.org, openapi/jellyfin-openapi-stable.json, read
2026-11-01): security scheme = header `Authorization` (`MediaBrowser Token="<key>"`);
`GET /System/Info` (Version, ServerName, OperatingSystemDisplayName, HasUpdateAvailable,
HasPendingRestart), `GET /Sessions` (SessionInfoDto: NowPlayingItem, PlayState.PlayMethod /
IsPaused / PositionTicks, TranscodingInfo.IsVideoDirect / IsAudioDirect /
HardwareAccelerationType / CompletionPercentage / TranscodeReasons), `GET /Items/Counts`
(ItemCounts), `GET /Library/VirtualFolders` (Name, CollectionType, Locations,
RefreshStatus), `GET /ScheduledTasks` (TaskInfo.State, LastExecutionResult.Status/EndTimeUtc/
ErrorMessage), `GET /Items` (sortBy, sortOrder, recursive, limit, includeItemTypes, fields).

GET only. The API key is admin-capable in Jellyfin (keys are not scoped), so atlas declares
the exact read endpoints it uses and nothing else is reachable through its client.
Only /System/Info is fatal; every other call degrades to a section error.
"""

import hashlib
import time
from collections.abc import Mapping
from typing import Any, Final

from homelab_atlas.collectors.base import ApiSource, CollectContext, CollectorResult, FacetResult
from homelab_atlas.engine.diff import Change
from homelab_atlas.engine.events import EventSpec, Severity
from homelab_atlas.inventory.hosts import Inventory, JellyfinSource
from homelab_atlas.models.jellyfin import (
    JellyfinFacts,
    JellyfinItem,
    JellyfinLibrary,
    JellyfinSession,
    JellyfinTask,
)
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.errors import HttpStatusError, SecurityRefusal, TransportError
from homelab_atlas.security.http import ReadOnlyHttpClient

SYSTEM_INFO = Endpoint("jellyfin.system_info", "GET", "/System/Info")
SESSIONS = Endpoint(
    "jellyfin.sessions", "GET", "/Sessions", query={"activeWithinSeconds": r"[0-9]{1,5}"}
)
COUNTS = Endpoint("jellyfin.counts", "GET", "/Items/Counts")
FOLDERS = Endpoint("jellyfin.virtual_folders", "GET", "/Library/VirtualFolders")
TASKS = Endpoint("jellyfin.scheduled_tasks", "GET", "/ScheduledTasks")
RECENT = Endpoint(
    "jellyfin.recent_items",
    "GET",
    "/Items",
    query={
        "sortBy": "DateCreated",
        "sortOrder": "Descending",
        "recursive": "true",
        "limit": r"[0-9]{1,2}",
        "includeItemTypes": "Movie,Episode",
        "fields": "DateCreated",
    },
)
ENDPOINTS: Final = frozenset({SYSTEM_INFO, SESSIONS, COUNTS, FOLDERS, TASKS, RECENT})
#: Only sessions seen in the last 10 minutes count as current.
ACTIVE_WITHIN_S: Final = 600
RECENT_LIMIT: Final = 12
TICKS_PER_S: Final = 10_000_000
COUNT_FIELDS: Final = {
    "MovieCount": "movies",
    "SeriesCount": "series",
    "EpisodeCount": "episodes",
    "SongCount": "songs",
    "AlbumCount": "albums",
    "BookCount": "books",
    "MusicVideoCount": "music_videos",
}


def _s(v: Any, limit: int = 128) -> str | None:
    return v[:limit] if isinstance(v, str) and v else None


def _d(v: Any) -> dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _l(v: Any) -> list[Any]:
    return v if isinstance(v, list) else []


def _b(v: Any) -> bool | None:
    return v if isinstance(v, bool) else None


def _secs(ticks: Any) -> int | None:
    if isinstance(ticks, int) and not isinstance(ticks, bool) and ticks >= 0:
        return ticks // TICKS_PER_S
    return None


def pseudonym(server: str, user_id: Any) -> str:
    """A stable, non-reversible label per user and server: viewer-3f9a."""
    raw = f"{server}|{user_id if isinstance(user_id, str) else '?'}".encode()
    return "viewer-" + hashlib.sha256(raw).hexdigest()[:4]


def session(server: str, raw: Mapping[str, Any]) -> JellyfinSession | None:
    """One SessionInfoDto, or None for an idle session (nothing playing)."""
    item = _d(raw.get("NowPlayingItem"))
    if not item:
        return None
    state = _d(raw.get("PlayState"))
    tr = _d(raw.get("TranscodingInfo"))
    pct = tr.get("CompletionPercentage")
    hw = _s(tr.get("HardwareAccelerationType"), 16)
    return JellyfinSession(
        viewer=pseudonym(server, raw.get("UserId")),
        client=_s(raw.get("Client"), 64),
        device=_s(raw.get("DeviceName"), 64),
        item=_s(item.get("Name"), 160),
        item_type=_s(item.get("Type"), 32),
        series=_s(item.get("SeriesName"), 160),
        paused=_b(state.get("IsPaused")),
        play_method=_s(state.get("PlayMethod"), 16),
        position_s=_secs(state.get("PositionTicks")),
        runtime_s=_secs(item.get("RunTimeTicks")),
        video_direct=_b(tr.get("IsVideoDirect")) if tr else None,
        audio_direct=_b(tr.get("IsAudioDirect")) if tr else None,
        # "none" is what Jellyfin reports for software transcoding: keep it, it is evidence.
        hw_accel=hw.lower() if hw else None,
        transcode_pct=float(pct) if isinstance(pct, int | float) and 0 <= pct <= 100 else None,
        transcode_reasons=[r[:48] for r in _l(tr.get("TranscodeReasons")) if isinstance(r, str)][
            :8
        ],
        video_codec=_s(tr.get("VideoCodec"), 16),
    )


def sessions(server: str, body: Any) -> list[JellyfinSession]:
    out = [session(server, r) for r in _l(body) if isinstance(r, dict)]
    return [s for s in out if s is not None][:50]


def libraries(body: Any) -> list[JellyfinLibrary]:
    out = []
    for f in _l(body):
        if isinstance(f, dict) and _s(f.get("Name")):
            out.append(
                JellyfinLibrary(
                    name=str(f["Name"])[:128],
                    collection_type=_s(f.get("CollectionType"), 32),
                    locations=[x[:512] for x in _l(f.get("Locations")) if isinstance(x, str)][:32],
                    refresh_status=_s(f.get("RefreshStatus"), 32),
                )
            )
    return out


def tasks(body: Any) -> list[JellyfinTask]:
    out = []
    for t in _l(body):
        if not isinstance(t, dict) or not _s(t.get("Name")) or t.get("IsHidden") is True:
            continue
        last = _d(t.get("LastExecutionResult"))
        out.append(
            JellyfinTask(
                name=str(t["Name"])[:96],
                category=_s(t.get("Category"), 48),
                state=_s(t.get("State"), 16),
                last_status=_s(last.get("Status"), 16),
                last_end=_s(last.get("EndTimeUtc"), 40),
                last_error=_s(last.get("ErrorMessage"), 240),
            )
        )
    return out[:80]


def recent(body: Any) -> list[JellyfinItem]:
    return [
        JellyfinItem(
            name=str(i["Name"])[:160],
            type=_s(i.get("Type"), 32),
            series=_s(i.get("SeriesName"), 160),
            added=_s(i.get("DateCreated"), 40),
        )
        for i in _l(_d(body).get("Items"))
        if isinstance(i, dict) and _s(i.get("Name"))
    ][:RECENT_LIMIT]


def counts(body: Any) -> dict[str, int]:
    d = _d(body)
    return {
        out: v
        for src, out in COUNT_FIELDS.items()
        if isinstance(v := d.get(src), int) and not isinstance(v, bool) and v >= 0
    }


def jellyfin_events(key: str, name: str, changes: list[Change]) -> list[EventSpec]:
    out: list[EventSpec] = []

    def ev(t: str, sev: Severity, summary: str, c: Change) -> None:
        out.append(EventSpec(key, t, sev, f"{name}: {summary}", c.dotted, c.old, c.new))

    for c in changes:
        p = c.path
        if p == ("version",):
            ev("media.upgraded", "notice", f"Jellyfin {c.old} -> {c.new}", c)
        elif p[0] == "libraries" and len(p) == 2:
            ev(f"media.library_{c.kind}", "notice", f"library {p[1]} {c.kind}", c)
        elif p[0] == "libraries" and p[-1] == "locations":
            ev("media.library_paths", "notice", f"library {p[1]} folders changed", c)
    return out


class JellyfinCollector:
    name = "jellyfin"
    requires: frozenset[ProbeSection] = frozenset()
    endpoints = ENDPOINTS

    def targets(self, inventory: Inventory) -> list[str]:
        return [s.name for s in inventory.sources.jellyfin]

    def events(self, key: str, name: str, changes: list[Change]) -> list[EventSpec]:
        return jellyfin_events(key, name, changes)

    @staticmethod
    def source(inventory: Inventory, name: str) -> ApiSource:
        src: JellyfinSource = next(s for s in inventory.sources.jellyfin if s.name == name)
        return ApiSource(
            src.name, src.url, src.credential, src.tls, "jellyfin-token", src.allow_http
        )

    async def collect(self, target: str, ctx: CollectContext) -> CollectorResult:
        start = time.monotonic()
        result = CollectorResult(self.name, target, "failed")
        if ctx.http is None:
            result.errors = ["no HTTP factory configured"]
            return result
        try:
            client = ctx.http(self.source(ctx.inventory, target), self.endpoints)
            async with client:
                facts = await _collect(client, target)
        except SecurityRefusal as exc:
            result.status, result.errors = "refused", [f"refused: {exc.reason.value}: {exc.detail}"]
            return _done(result, start)
        except HttpStatusError as exc:
            result.errors = [http_hint(exc.status)]
            return _done(result, start)
        except TransportError as exc:
            result.errors = [f"unreachable: {exc}"]
            return _done(result, start)
        except ValueError:
            result.errors = ["/System/Info did not return JSON (is this Jellyfin?)"]
            return _done(result, start)
        result.facets = [
            FacetResult(f"jellyfin:{target}", "media-server", f"{target} (Jellyfin)", facts)
        ]
        result.errors = list(facts.section_errors)
        result.status = "partial" if result.errors else "ok"
        result.complete = True
        return _done(result, start)


def http_hint(status: int) -> str:
    if status == 401:
        return "HTTP 401: the API key was refused (Dashboard > API Keys > +, then paste it here)"
    if status == 403:
        return "HTTP 403: this key may not read the server information"
    return f"HTTP {status} from Jellyfin"


async def _collect(client: ReadOnlyHttpClient, target: str) -> JellyfinFacts:
    info = _d((await client.get(SYSTEM_INFO)).json())
    errors: list[str] = []

    async def soft(label: str, ep: Endpoint, query: Mapping[str, str | int] | None = None) -> Any:
        try:
            return (await client.get(ep, None, query)).json()
        except HttpStatusError as exc:
            errors.append(f"{label}: HTTP {exc.status}")
        except (TransportError, SecurityRefusal) as exc:
            errors.append(f"{label}: {type(exc).__name__}")
        except ValueError:
            errors.append(f"{label}: invalid JSON")
        return None

    server = _s(info.get("Id"), 64) or target
    sess = await soft("sessions", SESSIONS, {"activeWithinSeconds": ACTIVE_WITHIN_S})
    folders = await soft("libraries", FOLDERS)
    cnt = await soft("counts", COUNTS)
    tsk = await soft("scheduled tasks", TASKS)
    rec = await soft(
        "recently added",
        RECENT,
        {
            "sortBy": "DateCreated",
            "sortOrder": "Descending",
            "recursive": "true",
            "limit": RECENT_LIMIT,
            "includeItemTypes": "Movie,Episode",
            "fields": "DateCreated",
        },
    )
    return JellyfinFacts(
        source=target,
        server_name=_s(info.get("ServerName")),
        version=_s(info.get("Version"), 32),
        os=_s(info.get("OperatingSystemDisplayName") or info.get("OperatingSystem"), 64),
        has_update=_b(info.get("HasUpdateAvailable")),
        pending_restart=_b(info.get("HasPendingRestart")),
        libraries=libraries(folders),
        counts=counts(cnt),
        tasks=tasks(tsk),
        sessions=sessions(server, sess) if sess is not None else [],
        recent=recent(rec),
        section_errors=errors,
    )


def _done(result: CollectorResult, start: float) -> CollectorResult:
    result.duration_ms = int((time.monotonic() - start) * 1000)
    return result
