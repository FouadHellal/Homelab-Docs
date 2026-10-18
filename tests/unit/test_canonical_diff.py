from homelab_atlas.engine.diff import Change, body_sha256, diff
from homelab_atlas.engine.events import is_key_package, linux_events
from homelab_atlas.models.base import canonical
from homelab_atlas.models.linux import LinuxHostFacts, ListeningSocket, LocalUser, OsInfo


def facts(**kw: object) -> LinuxHostFacts:
    return LinuxHostFacts.model_validate(kw)


def test_volatile_stripped_and_order_free() -> None:
    a = facts(
        os=OsInfo(hostname="h", uptime_s=1.0),
        sockets=[
            ListeningSocket(proto="tcp", address="0.0.0.0", port=22, pid=1),
            ListeningSocket(proto="udp", address="::", port=53, pid=2),
        ],
        section_errors={"x": ["y"]},
    )
    b = facts(
        os=OsInfo(hostname="h", uptime_s=999.0),
        sockets=[
            ListeningSocket(proto="udp", address="::", port=53, pid=7),
            ListeningSocket(proto="tcp", address="0.0.0.0", port=22, pid=8),
        ],
    )
    assert canonical(a) == canonical(b)
    assert body_sha256(canonical(a)) == body_sha256(canonical(b))
    body = canonical(a)
    assert "uptime_s" not in body["os"]
    assert "section_errors" not in body
    assert "neighbors" not in body
    assert list(body["sockets"]) == ["tcp|0.0.0.0|22", "udp|::|53"]


def test_duplicate_identities_kept() -> None:
    f = facts(
        sockets=[
            ListeningSocket(proto="tcp", address="*", port=1, process="a"),
            ListeningSocket(proto="tcp", address="*", port=1, process="b"),
        ]
    )
    assert set(canonical(f)["sockets"]) == {"tcp|*|1", "tcp|*|1#2"}


def test_diff_paths_and_scalar_lists() -> None:
    old = {"a": {"x": 1, "gone": 2}, "l": ["p", "q"], "s": "v"}
    new = {"a": {"x": 2, "new": 3}, "l": ["q", "r"], "s": "v"}
    assert diff(old, new) == [
        Change(("a", "gone"), "removed", old=2),
        Change(("a", "new"), "added", new=3),
        Change(("a", "x"), "changed", old=1, new=2),
        Change(("l", "p"), "removed", old="p"),
        Change(("l", "r"), "added", new="r"),
    ]
    assert diff(old, old) == []


def test_events_privileged_group_and_unclaimed() -> None:
    before = canonical(
        facts(users=[LocalUser(name="ops", uid=1000, gid=1000, home="/h", shell="/bin/sh")])
    )
    after = canonical(
        facts(
            users=[
                LocalUser(
                    name="ops", uid=1000, gid=1000, home="/h", shell="/bin/zsh", groups=["sudo"]
                )
            ]
        )
    )
    evs = linux_events("host:x", "web01", diff(before, after))
    assert [(e.type, e.severity) for e in evs] == [
        ("user.groups_changed", "warning"),
        ("facts.changed", "info"),
    ]
    assert evs[1].summary == "web01: 1 other changes in users.ops"


def test_key_packages() -> None:
    assert is_key_package("linux-image-6.1.0-26-amd64")
    assert is_key_package("openssh-server")
    assert not is_key_package("tzdata")
    assert not is_key_package("openssh-client")
