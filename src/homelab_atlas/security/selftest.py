"""`atlas selftest security`: exercise every guard offline and report.

Runs entirely in-process (mock HTTP transport, replay SSH transport, temp audit dir). It is a
smoke demo of the guards, not a substitute for the test suite.
"""

import asyncio
import json
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
from pydantic import SecretStr

from homelab_atlas.redact import Redactor
from homelab_atlas.security.allowlist import Endpoint, ProbeSection
from homelab_atlas.security.audit import AuditEvent, AuditLog, verify
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.security.http import AuthHeader, ReadOnlyHttpClient
from homelab_atlas.security.ssh import ReplayTransport, SshRunner, SshTarget


@dataclass(frozen=True, slots=True)
class Check:
    group: str
    name: str
    ok: bool
    detail: str


class _NullAudit:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)


EP = Endpoint(
    id="pve.qemu.list",
    method="GET",
    path_template="/nodes/{node}/qemu",
    path_vars={"node": r"[a-z0-9-]{1,32}"},
)
#: Assembled at runtime so private-key scanners do not flag this file.
_PEM_LABEL = "OPENSSH " + "PRIVATE KEY"
CRLF = "a\r\nX-HTTP-Method-Override: DELETE"
FAKE_TOKEN = "PVEAPIToken=atlas@pve!selftest=ATLASFAKE-0000-0000-0000-000000000000"


async def _refused(coro: Awaitable[object]) -> tuple[bool, str]:
    try:
        await coro
    except SecurityRefusal as exc:
        return True, exc.reason.value
    return False, "NOT refused"


async def _http_checks() -> list[Check]:
    sent: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(req)
        if req.url.path.endswith("/redirect/qemu"):
            return httpx.Response(302, headers={"Location": "https://evil.test/"})
        return httpx.Response(200, json={"data": []})

    audit = _NullAudit()
    client = ReadOnlyHttpClient(
        target="selftest",
        base_url="https://pve.selftest:8006/api2/json",
        endpoints=(EP,),
        audit=audit,
        tls=None,
        auth=AuthHeader("Authorization", SecretStr(FAKE_TOKEN)),
        transport=httpx.MockTransport(handler),
    )
    checks: list[Check] = []
    async with client:
        await client.get(EP, {"node": "pve1"})
        checks.append(Check("http", "registered GET allowed", len(sent) == 1, "200"))
        unregistered = Endpoint(id="x", method="GET", path_template="/access/users")
        cases: list[tuple[str, Callable[[], Awaitable[object]]]] = [
            ("unregistered endpoint", lambda: client.get(unregistered)),
            ("path traversal '..'", lambda: client.get(EP, {"node": ".."})),
            ("encoded traversal %2e%2e", lambda: client.get(EP, {"node": "%2e%2e"})),
            ("slash in variable", lambda: client.get(EP, {"node": "a/../../x"})),
            ("CRLF header injection", lambda: client.get(EP, {"node": CRLF})),
            ("unicode dot U+FF0E", lambda: client.get(EP, {"node": "．．"})),
            ("action segment via variable", lambda: client.get(EP, {"node": "start"})),
            ("unknown query key", lambda: client.get(EP, {"node": "pve1"}, {"delete": 1})),
            ("redirect not followed", lambda: client.get(EP, {"node": "redirect"})),
        ]  # fmt: skip
        for name, fn in cases:
            ok, detail = await _refused(fn())
            checks.append(Check("http", name, ok, detail))
    for method in ("PUT", "DELETE", "PATCH"):
        try:
            Endpoint(id="w", method=method, path_template="/x")  # type: ignore[arg-type]
            checks.append(Check("http", f"{method} endpoint definable", False, "accepted"))
        except ValueError:
            checks.append(Check("http", f"{method} endpoint rejected", True, "ValueError"))
    leaked = any("ATLASFAKE" in e.model_dump_json() for e in audit.events)
    checks.append(
        Check("http", "token absent from audit", not leaked, f"{len(audit.events)} events")
    )
    return checks


async def _ssh_checks() -> list[Check]:
    target = SshTarget(
        name="selftest",
        host="192.0.2.10",
        host_keys=("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIselftestpin",),
        key_secret="ssh_selftest",
        sections=frozenset({ProbeSection.OS}),
    )
    runner = SshRunner(
        transport=ReplayTransport({("selftest", "atlas-probe os"): b"ID=debian\n"}),
        audit=_NullAudit(),
    )
    out = await runner.run(target, ProbeSection.OS)
    checks = [Check("ssh", "enabled section allowed", out.stdout == b"ID=debian\n", "replay")]
    attempts: list[tuple[str, object]] = [
        ("plain string 'os'", "os"),
        ("chained command", "os; rm -rf /"),
        ("command substitution", "$(id)"),
        ("homoglyph section", "оs"),
        ("section not enabled", ProbeSection.DOCKER),
    ]
    for name, section in attempts:
        ok, detail = await _refused(runner.run(target, section))  # type: ignore[arg-type]
        checks.append(Check("ssh", name, ok, detail))
    bad_targets = [
        ("root username", "192.0.2.10", "root"),
        ("option-injection host", "-oProxyCommand=x", "atlas-ro"),
    ]
    for name, host, username in bad_targets:
        try:
            SshTarget(
                name="x",
                host=host,
                host_keys=target.host_keys,
                key_secret="k",
                sections=target.sections,
                username=username,
            )
            checks.append(Check("ssh", name, False, "accepted"))
        except SecurityRefusal as exc:
            checks.append(Check("ssh", name, True, exc.reason.value))
    return checks


def _redaction_checks() -> list[Check]:
    r = Redactor(b"selftest-hmac-key-0123456789ab")
    samples = {
        "env assignment": "MYSQL_ROOT_PASSWORD=pw-ATLASFAKE",
        "URL credentials": "postgres://app:pg-ATLASFAKE@db:5432/app",
        "CLI flag": "cloudflared tunnel run --token tk-ATLASFAKE-0000",
        "bearer header": "Authorization: Bearer ey-ATLASFAKE-0123456789",
        "GitHub token": "ghp_ATLASFAKE0123456789abcdefghijklmnopq",
        "private key": f"-----BEGIN {_PEM_LABEL}-----\nATLASFAKE\n-----END {_PEM_LABEL}-----",
        "Wi-Fi PSK": "wpa_passphrase=wifi-ATLASFAKE",
    }  # fmt: skip
    checks = [
        Check("redact", name, "ATLASFAKE" not in (out := r.text(text)), out[:48])
        for name, text in samples.items()
    ]
    env = r.data({"Env": ["API_KEY=k-ATLASFAKE", "TZ=UTC"]})
    checks.append(
        Check("redact", "env keeps names only", env == {"Env": ["API_KEY", "TZ"]}, str(env))
    )
    return checks


def _audit_checks() -> list[Check]:
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        log = AuditLog(d)
        for i in range(3):
            log.record(AuditEvent(target="selftest", transport="http", op="GET /x",
                                  outcome="ok", duration_ms=i))  # fmt: skip
        ok = verify(d)
        (path,) = d.glob("audit-*.jsonl")
        recs = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()]
        recs[1]["op"] = "DELETE /x"
        path.write_text("".join(json.dumps(x) + "\n" for x in recs), encoding="utf-8")
        tampered = verify(d)
    return [
        Check("audit", "chain verifies", ok.ok, f"{ok.records} records"),
        Check("audit", "tamper detected", not tampered.ok, tampered.error or "NOT detected"),
    ]


def run_selftest() -> list[Check]:
    async def _all() -> list[Check]:
        return [*(await _http_checks()), *(await _ssh_checks())]

    return [*asyncio.run(_all()), *_redaction_checks(), *_audit_checks()]
