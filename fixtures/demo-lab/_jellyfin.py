"""Synthetic Jellyfin API answers for the demo lab (ADR-039). Nothing here is real.

State A: healthy, one direct-play session and one hardware transcode.
State B: the API still answers, but the NAS share is no longer mounted on media01, so the
library folders sit on the container's own disk (generate.py drops the mount): the media
diagnosis must call it a storage problem, not "Jellyfin down".
"""

from typing import Any

SERVER_ID = "4f1d7c2a9b8e4d6fa1c3e5b7d9f02468"
RECENT = ("/Items?sortBy=DateCreated&sortOrder=Descending&recursive=true&limit=12"
          "&includeItemTypes=Movie%2CEpisode&fields=DateCreated")  # fmt: skip


def _ok(body: Any) -> dict[str, Any]:
    return {"status": 200, "body": body}


def _session(user: str, item: dict[str, Any], play: dict[str, Any],
             transcoding: dict[str, Any] | None = None) -> dict[str, Any]:  # fmt: skip
    s: dict[str, Any] = {
        "Id": f"sess-{user}", "UserId": f"user-{user}", "UserName": f"{user}-ATLASFAKE",
        "Client": "Jellyfin Web", "DeviceName": "Living room TV", "IsActive": True,
        "NowPlayingItem": item, "PlayState": play,
    }  # fmt: skip
    if transcoding is not None:
        s["TranscodingInfo"] = transcoding
    return s


def render(state: str) -> dict[str, Any]:
    movie = {"Name": "Big Buck Bunny", "Type": "Movie", "RunTimeTicks": 5_960_000_000}
    ep = {"Name": "Pilot", "Type": "Episode", "SeriesName": "Sintel Stories",
          "RunTimeTicks": 26_400_000_000}  # fmt: skip
    sessions = [
        _session("alice", movie, {"IsPaused": False, "PlayMethod": "DirectPlay",
                                  "PositionTicks": 1_800_000_000}),
        _session("bob", ep, {"IsPaused": False, "PlayMethod": "Transcode",
                             "PositionTicks": 9_000_000_000},
                 {"IsVideoDirect": False, "IsAudioDirect": True, "VideoCodec": "h264",
                  "HardwareAccelerationType": "vaapi", "CompletionPercentage": 41.5,
                  "TranscodeReasons": ["VideoCodecNotSupported"]}),
        {"Id": "idle", "UserId": "user-carol", "Client": "Jellyfin Android", "IsActive": True},
    ]  # fmt: skip
    if state == "B":
        sessions.append(
            _session("carol", {"Name": "Tears of Steel", "Type": "Movie",
                               "RunTimeTicks": 7_340_000_000},
                     {"IsPaused": True, "PlayMethod": "DirectStream", "PositionTicks": 600_000_000})
        )  # fmt: skip
    tasks = [
        {"Name": "Scan Media Library", "Category": "Library", "State": "Idle",
         "LastExecutionResult": {"Status": "Completed" if state == "A" else "Failed",
                                 "EndTimeUtc": "2026-11-01T03:00:12Z",
                                 **({"ErrorMessage": "Access to the path '/mnt/media/movies' is denied."}
                                    if state == "B" else {})}},
        {"Name": "Clean Transcode Directory", "Category": "Maintenance", "State": "Idle",
         "LastExecutionResult": {"Status": "Completed", "EndTimeUtc": "2026-11-01T00:00:03Z"}},
        {"Name": "Hidden helper", "IsHidden": True},
    ]  # fmt: skip
    return {
        "/System/Info": _ok({
            "Id": SERVER_ID, "ServerName": "media01", "Version": "10.11.2",
            "OperatingSystemDisplayName": "Linux", "HasUpdateAvailable": state == "B",
            "HasPendingRestart": False,
        }),  # fmt: skip
        "/Sessions?activeWithinSeconds=600": _ok(sessions),
        "/Items/Counts": _ok({"MovieCount": 412, "SeriesCount": 37, "EpisodeCount": 1288,
                              "SongCount": 0, "AlbumCount": 0, "BookCount": 9}),  # fmt: skip
        "/Library/VirtualFolders": _ok([
            {"Name": "Movies", "CollectionType": "movies", "Locations": ["/mnt/media/movies"],
             "RefreshStatus": "Idle"},
            {"Name": "Shows", "CollectionType": "tvshows", "Locations": ["/mnt/media/tv"],
             "RefreshStatus": "Idle"},
        ]),  # fmt: skip
        "/ScheduledTasks": _ok(tasks),
        RECENT: _ok({"Items": [
            {"Name": "Cosmos Laundromat", "Type": "Movie", "DateCreated": "2026-10-31T21:04:00Z"},
            {"Name": "Episode 4", "Type": "Episode", "SeriesName": "Sintel Stories",
             "DateCreated": "2026-10-30T18:30:00Z"},
        ]}),  # fmt: skip
    }
