"""Jellyfin facts (ADR-039): server, libraries, tasks, sessions. Everything but the server
identity and library layout is volatile: counts and sessions change all the time.

Privacy: user names are never stored. A session carries a short pseudonym (stable per user
for this server) and the live page shows real names only when the owner turns that on.
"""

from pydantic import Field

from homelab_atlas.models.base import Fact, keyed, volatile


class JellyfinLibrary(Fact):
    name: str
    collection_type: str | None = None  # movies, tvshows, music, ... (None = mixed)
    locations: list[str] = Field(default_factory=list)
    refresh_status: str | None = volatile()


class JellyfinTask(Fact):
    name: str
    category: str | None = None
    state: str | None = volatile()  # Idle, Running, Cancelling
    last_status: str | None = volatile()  # Completed, Failed, Cancelled, Aborted
    last_end: str | None = volatile()
    last_error: str | None = volatile()


class JellyfinSession(Fact):
    viewer: str  # pseudonym, e.g. "viewer-3f9a"
    client: str | None = None
    device: str | None = None
    item: str | None = None
    item_type: str | None = None
    series: str | None = None
    paused: bool | None = None
    #: DirectPlay, DirectStream or Transcode, as Jellyfin reports it (PlayState.PlayMethod).
    play_method: str | None = None
    position_s: int | None = None
    runtime_s: int | None = None
    video_direct: bool | None = None
    audio_direct: bool | None = None
    #: TranscodingInfo.HardwareAccelerationType when Jellyfin reports one; None = not reported.
    hw_accel: str | None = None
    transcode_pct: float | None = None
    transcode_reasons: list[str] = Field(default_factory=list)
    video_codec: str | None = None


class JellyfinItem(Fact):
    name: str
    type: str | None = None
    series: str | None = None
    added: str | None = None


class JellyfinFacts(Fact):
    source: str
    server_name: str | None = None
    version: str | None = None
    os: str | None = None
    has_update: bool | None = volatile()
    pending_restart: bool | None = volatile()
    libraries: list[JellyfinLibrary] = keyed("name")
    counts: dict[str, int] = volatile(factory=dict)
    tasks: list[JellyfinTask] = volatile(factory=list)
    sessions: list[JellyfinSession] = volatile(factory=list)
    recent: list[JellyfinItem] = volatile(factory=list)
    #: Calls that failed without failing the run (e.g. a permission this key lacks).
    section_errors: list[str] = volatile(factory=list)
