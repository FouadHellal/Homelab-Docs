"""atlas ↔ real Taskora, end to end (ADR-042 definition of done).

Runs only when ATLAS_TASKORA_CHECKOUT points to a Taskora checkout (0.3.0+, `npm install`
done): it starts Taskora's own harness (apps/api/test/e2e/atlas-e2e-server.ts: the real API
over an in-memory PostgreSQL on 127.0.0.1) and drives atlas's real engine against it. The only
shim is the HTTP transport, which forwards atlas's requests to 127.0.0.1 after
ReadOnlyHttpClient has applied every check (atlas itself never allows plain HTTP to loopback).
A technician acts through Taskora's normal session API.
"""

import asyncio
import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from datetime import timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr
from sqlalchemy import select

from homelab_atlas.engine import taskora as tk
from homelab_atlas.lab import load_lab
from homelab_atlas.runtime import Runtime
from homelab_atlas.store.tables import Incident, TaskoraLink, utcnow
from tests.helpers import MemoryAudit, scanned_lab

CHECKOUT = os.environ.get("ATLAS_TASKORA_CHECKOUT", "")
LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"
pytestmark = pytest.mark.skipif(not CHECKOUT, reason="set ATLAS_TASKORA_CHECKOUT to run")


@pytest.fixture(scope="module")
def taskora(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    handoff = tmp_path_factory.mktemp("taskora") / "handoff.json"
    npx = shutil.which("npx")
    assert npx, "Node.js (npx) is required"
    proc = subprocess.Popen(  # noqa: S603 - fixed argv, test harness only
        [npx, "tsx", "test/e2e/atlas-e2e-server.ts", str(handoff)],
        cwd=Path(CHECKOUT) / "apps" / "api",
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 120
        while not handoff.is_file() and time.monotonic() < deadline:
            assert proc.poll() is None, "Taskora harness exited early"
            time.sleep(0.5)
        assert handoff.is_file(), "Taskora harness did not start"
        yield json.loads(handoff.read_text("utf-8"))
    finally:
        if proc.stdin:
            proc.stdin.close()
        try:
            proc.wait(15)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def opened() -> Iterator[list[httpx.Client]]:
    clients: list[httpx.Client] = []
    yield clients
    for c in clients:
        c.close()


class Tech:
    """A Taskora technician using the normal session API (cookie + CSRF)."""

    def __init__(self, info: dict[str, Any], opened: list[httpx.Client]) -> None:
        self.c = httpx.Client(base_url=info["url"], timeout=30)
        opened.append(self.c)
        r = self.c.post(
            "/api/v1/auth/login",
            json={"email": info["techEmail"], "password": info["techPassword"]},
        )
        assert r.status_code == 200, r.text
        self.c.headers["x-csrf-token"] = r.json()["csrfToken"]
        self.lookups = self.get("/api/v1/lookups")

    def get(self, path: str, **params: Any) -> Any:
        r = self.c.get(path, params=params)
        assert r.status_code == 200, (path, r.text)
        return r.json()

    def patch(self, path: str, body: dict[str, Any]) -> Any:
        r = self.c.patch(path, json=body)
        assert r.status_code == 200, (path, r.text)
        return r.json()

    def status(self, name: str) -> int:
        return int(next(x["id"] for x in self.lookups["statuses"] if x["name"] == name))

    def ticket(self, tid: int) -> Any:
        return self.get(f"/api/v1/tickets/{tid}")

    def notes(self, tid: int) -> list[str]:
        items = self.get(f"/api/v1/tickets/{tid}/timeline")["data"]
        return [i["note"]["body"] for i in items if i["kind"] == "note"]


def forwarder(url: str, opened: list[httpx.Client]) -> httpx.MockTransport:
    real = httpx.Client(base_url=url, timeout=30)
    opened.append(real)

    def forward(req: httpx.Request) -> httpx.Response:
        headers = {
            k: v
            for k, v in req.headers.items()
            if k.lower() in ("authorization", "content-type", "accept")
        }
        r = real.request(
            req.method, req.url.raw_path.decode("ascii"), content=req.content, headers=headers
        )
        return httpx.Response(
            r.status_code,
            content=r.content,
            headers={"content-type": r.headers.get("content-type", "")},
        )

    return httpx.MockTransport(forward)


def test_definition_of_done(
    taskora: dict[str, Any], tmp_path: Path, opened: list[httpx.Client]
) -> None:
    rt: Runtime = scanned_lab(tmp_path)
    inv, _ = load_lab("B", LAB)
    settings = tk.TaskoraSettings(
        url="https://taskora.e2e.test", instance="atlas-e2e", incidents=True
    )
    client = tk.TaskoraClient(
        settings,
        SecretStr(taskora["token"]),
        MemoryAudit(),
        transport=forwarder(taskora["url"], opened),
    )
    tech = Tech(taskora, opened)
    t0 = utcnow() + timedelta(minutes=10)

    def tick(minutes: int = 0) -> dict[str, int]:
        with rt.sessions() as s:
            return asyncio.run(
                tk.tick(
                    s,
                    inv,
                    client,
                    atlas_url="https://atlas.e2e.test",
                    now=t0 + timedelta(minutes=minutes),
                )
            )

    def tickets() -> list[dict[str, Any]]:
        return list(
            tech.get("/api/v1/tickets", companyId=taskora["companyId"], pageSize=100)["data"]
        )

    def cis() -> list[dict[str, Any]]:
        return list(
            tech.get("/api/v1/configuration-items", companyId=taskora["companyId"], pageSize=200)[
                "data"
            ]
        )

    def incident(kind: str) -> Incident:
        with rt.sessions() as s:
            return next(
                i
                for i in s.scalars(select(Incident).where(Incident.resolved_at.is_(None)))
                if i.kind == kind
            )

    def link(inc_id: int) -> TaskoraLink:
        with rt.sessions() as s:
            return s.get_one(TaskoraLink, inc_id)

    # 0. The connection works.
    assert asyncio.run(client.health())["companyConfigured"] is True

    # 1. CMDB preview writes nothing; apply links docker01 to its Action1 CI, creates the rest.
    before = cis()
    with rt.sessions() as s:
        preview = asyncio.run(tk.inventory_sync(s, client, "preview"))
        s.commit()
    assert cis() == before
    assert any(p["action"] == "link" and p["name"] == "docker01" for p in preview["plan"])
    with rt.sessions() as s:
        applied = asyncio.run(tk.inventory_sync(s, client, "apply"))
        s.commit()
    assert applied["stats"].get("create", 0) >= 5
    after = cis()
    a1 = next(c for c in after if c["id"] == taskora["action1CiId"])
    assert a1["name"] == "DOCKER01" and a1["source"] == "action1"
    assert a1["osName"] == "Debian 12 (reported by Action1)"  # Action1 owns it: untouched
    assert (
        sum(1 for c in after if (c.get("hostname") or "").lower() == "docker01") == 1
    )  # no duplicate
    media01 = next(c for c in after if c["name"] == "media01")
    assert media01["source"] == "atlas"
    # Same sync again: nothing new.
    with rt.sessions() as s:
        again = asyncio.run(tk.inventory_sync(s, client, "apply"))
        s.commit()
    assert again["stats"].get("create", 0) == 0 and len(cis()) == len(after)

    # 2. Incidents → one ticket each; the Jellyfin storage outage is linked to media01's CI.
    out = tick()
    assert out["delivered"] >= 3 and out["failed"] == 0, out
    first = tickets()
    assert len(first) == out["delivered"]
    media = incident("media.storage")
    lk = link(media.id)
    assert lk.ticket_id is not None and lk.ticket_number
    t = tech.ticket(lk.ticket_id)
    assert t["configurationItemId"] == media01["id"]
    assert "atlas" in t["tags"] and t["priorityName"] == "High"

    # 3. Repeated scans: heartbeats add nothing; new evidence adds one internal note.
    notes_before = len(tech.notes(lk.ticket_id))
    with rt.sessions() as s:
        s.get_one(Incident, media.id).last_seen_at = t0 + timedelta(minutes=5)
        s.commit()
    assert tick(5)["delivered"] == 0
    with rt.sessions() as s:
        row = s.get_one(Incident, media.id)
        row.evidence = [*row.evidence, "Library scan: 3 folders unreachable"]
        s.commit()
    assert tick(6)["delivered"] == 1
    assert len(tech.notes(lk.ticket_id)) == notes_before + 1
    assert len(tickets()) == len(first)

    # 4. A technician takes the ticket: atlas shows it acknowledged, and does not echo it.
    tech.patch(
        f"/api/v1/tickets/{lk.ticket_id}",
        {"statusId": tech.status("In Progress"), "assignedUserId": taskora["techId"]},
    )
    notes_before = len(tech.notes(lk.ticket_id))
    tick(7)
    with rt.sessions() as s:
        row = s.get_one(Incident, media.id)
        assert row.acknowledged_by == "Taskora: Sam Tech"
        assert s.get_one(TaskoraLink, media.id).ticket_status == "In Progress"
    tick(8)
    assert len(tech.notes(lk.ticket_id)) == notes_before

    # 5. Ticket closed while the NAS pool is still degraded: reopened, "still failing".
    pool = incident("nas.pool")
    plk = link(pool.id)
    assert plk.ticket_id is not None
    tech.patch(
        f"/api/v1/tickets/{plk.ticket_id}",
        {"statusId": tech.status("Resolved"), "resolution": "Replaced the disk"},
    )
    tick(9)  # feed: resolved while failing
    tick(10)  # delivery: persisting
    pool_ticket = tech.ticket(plk.ticket_id)
    assert pool_ticket["statusCategory"] != "resolved"
    assert any("still observes" in n for n in tech.notes(plk.ticket_id))

    # 6. atlas sees the Jellyfin storage recover: the ticket is resolved by policy.
    with rt.sessions() as s:
        s.get_one(Incident, media.id).resolved_at = t0 + timedelta(minutes=11)
        s.commit()
    tick(11)
    resolved = tech.ticket(lk.ticket_id)
    assert resolved["statusCategory"] == "resolved"
    assert any("verified recovery" in n for n in tech.notes(lk.ticket_id))

    # 7. Replay everything (e.g. after a Taskora restore): no duplicates, nothing reverts.
    with rt.sessions() as s:
        assert tk.replay_all(s) >= 3
        s.commit()
    tick(12)
    assert len(tickets()) == len(first)
    assert tech.ticket(lk.ticket_id)["statusCategory"] == "resolved"

    # 8. Action1 data still intact.
    a1_panel = tech.get(f"/api/v1/configuration-items/{taskora['action1CiId']}/action1")
    assert a1_panel["linked"] is True
    a1_after = next(c for c in cis() if c["id"] == taskora["action1CiId"])
    assert (a1_after["name"], a1_after["source"], a1_after["osName"]) == (
        "DOCKER01",
        "action1",
        "Debian 12 (reported by Action1)",
    )
