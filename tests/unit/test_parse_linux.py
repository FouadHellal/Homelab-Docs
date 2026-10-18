import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from homelab_atlas.collectors.linux_ssh import parse
from homelab_atlas.collectors.linux_ssh.frame import Frame, FrameError, Part, parse_frame
from homelab_atlas.security.allowlist import ProbeSection


def frame(section: ProbeSection, **parts: str | tuple[str, int]) -> Frame:
    f = Frame(section=section, complete=True)
    for name, value in parts.items():
        content, rc = value if isinstance(value, tuple) else (value, 0)
        f.parts[name.replace("_", "-")] = Part(name, content, rc)
    return f


SS = "\n".join(
    [
        'tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=812,fd=3))',
        'tcp   LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=812,fd=4))',
        'tcp   LISTEN 0 4096 *:8006 *:* users:(("pveproxy worker",pid=1500,fd=6))',
        'udp   UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=600,fd=13))',
        "udp   UNCONN 0 0 [fe80::be24:11ff:fe00:80]%eth0:546 [::]:*",
        'tcp   LISTEN 0 4096 [2001:0db8:0000::0011]:443 [::]:* users:(("caddy",pid=9,fd=1))',
        'tcp   LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=813,fd=3))',
        "raw   UNCONN 0 0 *:icmp *:*",
        "garbage",
        "tcp LISTEN 0 1 nonsense:port x",
    ]
)


def test_ss_endpoints_and_processes() -> None:
    out = parse.parse_ports(frame(ProbeSection.PORTS, listen=SS))
    got = {(s.proto, s.address, s.port, s.process) for s in out.values["sockets"]}
    assert got == {
        ("tcp", "0.0.0.0", 22, "sshd"),
        ("tcp", "::", 22, "sshd"),
        ("tcp", "*", 8006, "pveproxy worker"),
        ("udp", "127.0.0.53", 53, "systemd-resolve"),
        ("udp", "fe80::be24:11ff:fe00:80", 546, None),
        ("tcp", "2001:db8::11", 443, "caddy"),
    }
    assert out.errors == ["listen: unparsable endpoint"]


def test_os_release_quotes_and_machine_id() -> None:
    rel = (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'ID=debian\nVERSION_ID="12"\nbad line\nlower=x'
    )
    f = frame(
        ProbeSection.OS,
        os_release=rel,
        kernel="6.1.0-25-amd64\n",
        hostname="médiathèque\n",
        machine_id="NOT-A-MACHINE-ID",
        virt=("none\n", 1),
        uptime="12.5 99",
    )
    out = parse.parse_os(f)
    os_ = out.values["os"]
    assert (os_.os_id, os_.os_version_id, os_.hostname) == ("debian", "12", "médiathèque")
    assert os_.virtualization == "none"
    assert os_.machine_id is None
    assert os_.uptime_s == 12.5
    assert "machine-id: missing or malformed" in out.errors


def test_net_veth_vlan_ipv6_mac() -> None:
    addr = [
        {
            "ifname": "eth0",
            "address": "BC:24:11:AA:BB:CC",
            "mtu": 1500,
            "operstate": "UP",
            "addr_info": [
                {"family": "inet6", "local": "2001:0db8:0020::0011", "prefixlen": 64},
                {"family": "inet", "local": "10.0.20.11", "prefixlen": 24},
                {"family": "packet", "local": "x"},
            ],
        },
        {"ifname": "vmbr0.20", "address": "bc:24:11:aa:bb:cc", "addr_info": []},
        {"ifname": "veth1234", "address": "aa:aa:aa:aa:aa:aa", "addr_info": []},
        "junk",
    ]
    link = [
        {"ifname": "vmbr0.20", "linkinfo": {"info_kind": "vlan", "info_data": {"id": 20}}},
        {"ifname": "veth1234", "linkinfo": {"info_kind": "veth"}},
    ]
    f = frame(
        ProbeSection.NET,
        addr=json.dumps(addr),
        link=json.dumps(link),
        route4="[]",
        route6="[]",
        neigh="[]",
        resolv="nameserver 10.0.20.1\nsearch lab.example x\n",
    )
    out = parse.parse_net(f)
    ifs = {i.name: i for i in out.values["interfaces"]}
    assert set(ifs) == {"eth0", "vmbr0.20"}
    assert out.values["veth_count"] == 1
    assert ifs["eth0"].mac == "bc:24:11:aa:bb:cc"
    assert [a.address for a in ifs["eth0"].addresses] == ["2001:db8:20::11/64", "10.0.20.11/24"]
    assert (ifs["vmbr0.20"].kind, ifs["vmbr0.20"].vlan_id) == ("vlan", 20)
    assert out.values["search_domains"] == ["lab.example", "x"]


def test_storage_filters_pseudo_and_loop() -> None:
    lsblk = {
        "blockdevices": [
            {"name": "loop0", "type": "loop"},
            {
                "name": "sda",
                "type": "disk",
                "size": 10,
                "children": [{"name": "sda1", "type": "part", "size": 9}],
            },
        ]
    }
    fm = {
        "filesystems": [
            {
                "target": "/",
                "source": "/dev/sda1",
                "fstype": "ext4",
                "size": 9,
                "children": [
                    {"target": "/proc", "fstype": "proc"},
                    {"target": "/var/lib/docker/overlay2/x", "fstype": "overlay"},
                    {"target": "/mnt/nas", "source": "nas:/x", "fstype": "nfs4"},
                ],
            }
        ]
    }
    out = parse.parse_storage(
        frame(ProbeSection.STORAGE, lsblk=json.dumps(lsblk), findmnt=json.dumps(fm))
    )
    assert [d.name for d in out.values["block_devices"]] == ["sda", "sda1"]
    assert [m.target for m in out.values["mounts"]] == ["/", "/mnt/nas"]
    bad = parse.parse_storage(frame(ProbeSection.STORAGE, lsblk="{nope", findmnt=("", 1)))
    assert bad.errors == ["lsblk: invalid JSON", "findmnt: missing or failed"]


def test_users_drop_gecos_and_merge_groups() -> None:
    passwd = "ops:x:1000:1000:Secret Person ATLASFAKE,,,:/home/ops:/bin/bash\nbroken:line\n"
    group = "ops:x:1000:\nsudo:x:27:ops\ndocker:x:999:ops,other\n"
    out = parse.parse_users(frame(ProbeSection.USERS, passwd=passwd, group=group))
    (u,) = out.values["users"]
    assert u.groups == ["docker", "ops", "sudo"]
    assert "ATLASFAKE" not in u.model_dump_json()


def test_packages_only_installed() -> None:
    text = "bash\t5.2\tii \nfoo\t1.0\trc \nbar\t2.0\tiU \nbad"
    out = parse.parse_packages(frame(ProbeSection.PACKAGES, dpkg=text))
    assert [p.name for p in out.values["packages"]] == ["bash"]


def test_cron_skips_comments_and_failed_parts() -> None:
    f = frame(ProbeSection.CRON)
    f.parts["cron:/etc/crontab"] = Part("cron:/etc/crontab", "# c\n\nSHELL=/bin/sh\n0 * * * * x", 0)
    f.parts["cron:/etc/cron.d/x"] = Part("cron:/etc/cron.d/x", "1 * * * * y", 1)
    out = parse.parse_cron(f)
    assert [(e.source, e.line) for e in out.values["cron"]] == [
        ("/etc/crontab", "SHELL=/bin/sh"),
        ("/etc/crontab", "0 * * * * x"),
    ]


def test_version_mismatch() -> None:
    f = frame(
        ProbeSection.VERSION,
        version="0.9.0\n",
        sha256=("a" * 64) + "  /usr/local/libexec/atlas-probe",
    )
    out = parse.parse_version(f, "b" * 64)
    assert out.values["probe"].matches is False
    assert parse.parse_version(frame(ProbeSection.VERSION), "b" * 64).errors == [
        "version: unreadable"
    ]


PARSERS = [
    (ProbeSection.OS, parse.parse_os),
    (ProbeSection.NET, parse.parse_net),
    (ProbeSection.PORTS, parse.parse_ports),
    (ProbeSection.STORAGE, parse.parse_storage),
    (ProbeSection.SERVICES, parse.parse_services),
    (ProbeSection.CRON, parse.parse_cron),
    (ProbeSection.USERS, parse.parse_users),
    (ProbeSection.PACKAGES, parse.parse_packages),
]
json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children, max_size=4)
    ),
    max_leaves=20,
)


@settings(max_examples=200, deadline=None)
@given(
    idx=st.integers(0, len(PARSERS) - 1),
    names=st.lists(
        st.sampled_from(
            [
                "addr",
                "link",
                "route4",
                "route6",
                "neigh",
                "resolv",
                "listen",
                "lsblk",
                "findmnt",
                "units",
                "unit-files",
                "timers",
                "passwd",
                "group",
                "dpkg",
                "os-release",
                "hostname",
                "machine-id",
                "uptime",
                "cron:/etc/crontab",
            ]
        ),
        max_size=8,
    ),
    payload=st.one_of(st.text(max_size=200), json_values.map(json.dumps)),
    rc=st.integers(0, 3),
)
def test_parsers_are_total(idx: int, names: list[str], payload: str, rc: int) -> None:
    section, fn = PARSERS[idx]
    f = Frame(section=section, complete=True)
    for n in names:
        f.parts[n] = Part(n, payload, rc)
    fn(f)  # must never raise


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=400))
def test_frame_parser_total(data: bytes) -> None:
    try:
        parse_frame(b"ATLAS-PROBE 1 os 0123456789abcdef01234567\n" + data, ProbeSection.OS)
    except FrameError:
        pytest.fail("frame errors after a valid header must be reported, not raised")
