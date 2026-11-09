"""Taskora integration (ADR-042) against a stateful fake of Taskora's atlas API.

The fake follows docs/integrations/taskora.md: revision guard, one ticket per key, recovery
resolves, `persisting` reopens, a feed of technician events. The real API is exercised by
tests/integration/test_taskora_e2e.py when a Taskora checkout is available.
"""

import asyncio
import json
from collections.abc import Callable
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
from homelab_atlas.store.tables import Incident, TaskoraLink, TaskoraState, utcnow
from tests.helpers import MemoryAudit, scanned_lab

TOKEN = "tki_ATLASFAKE0000000000000000000000000000000"
LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


class FakeTaskora:
    def __init__(self) -> None:
        self.links: dict[str, dict[str, Any]] = {}
        self.tickets: dict[int, dict[str, Any]] = {}
        self.events: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str, dict[str, Any] | None]] = []
        self.fail: list[int] = []
        self.inventories: list[dict[str, Any]] = []
        self.auto_create = True  # Taskora's "create tickets automatically"

    def snapshot(self, tid: int) -> dict[str, Any]:
        t = self.tickets[tid]
        return {
            "id": tid,
            "number": f"TKA-{tid:06d}",
            "title": t["title"],
            "status": t["status"],
            "statusCategory": t["category"],
            "priority": "High",
            "assignee": t.get("assignee"),
            "path": f"/tickets/{tid}",
        }

    def technician(self, key: str, type_: str, category: str | None = None, **kw: Any) -> None:
        tid = self.links[key]["ticket"]
        if category:
            self.tickets[tid]["category"] = category
            self.tickets[tid]["status"] = category.title()
        if type_ == "assigned":
            self.tickets[tid]["assignee"] = "Sam Tech"
        self.events.append(
            {
                "id": len(self.events) + 1,
                "externalKey": key,
                "type": type_,
                "at": "2026-11-03T02:00:00Z",
                "actor": kw.get("actor", "Sam Tech"),
                "automation": kw.get("automation", False),
                "ticket": self.snapshot(tid),
            }
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        path = request.url.path
        self.requests.append((request.method, path, body))
        if request.headers.get("authorization") != f"Bearer {TOKEN}":
            return httpx.Response(401, json={"error": {"code": "unauthorized"}})
        if self.fail:
            return httpx.Response(self.fail.pop(0), json={"error": {"code": "x"}})
        if path.endswith("/health"):
            return httpx.Response(
                200, json={"ok": True, "integration": "atlas", "apiVersion": 1, "enabled": True}
            )
        if "/incidents/" in path and request.method == "POST":
            code, payload = self.upsert(path.rsplit("/", 1)[1], body or {})
            return httpx.Response(code, json=payload)
        if path.endswith("/ticket-events"):
            after = int(request.url.params.get("after", "0"))
            evs = [e for e in self.events if e["id"] > after]
            return httpx.Response(
                200,
                json={"events": evs, "nextCursor": evs[-1]["id"] if evs else after, "more": False},
            )
        if path.endswith("/inventory"):
            self.inventories.append(body or {})
            plan = [
                {
                    "key": e["key"],
                    "name": e["name"],
                    "action": "create",
                    "ciNumber": None,
                    "note": "Would create",
                }
                for e in (body or {}).get("entities", [])
            ]
            return httpx.Response(
                200,
                json={
                    "mode": body["mode"] if body else "",
                    "cmdbMode": "link_only",
                    "stats": {"create": len(plan)},
                    "plan": plan,
                },
            )
        return httpx.Response(404, json={})

    def upsert(self, key: str, ev: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        link = self.links.setdefault(
            key, {"revision": 0, "ticket": None, "state": "new", "persisting": False}
        )
        open_without_ticket = (
            link["ticket"] is None
            and self.auto_create
            and ev["state"] != "resolved"
            and link["state"] != "resolved"
        )
        if ev["revision"] <= link["revision"] and not open_without_ticket:  # 0.3.3: catch-up
            return 200, {
                "applied": False,
                "created": False,
                "ticket": self.snapshot(link["ticket"]) if link["ticket"] else None,
            }
        created = False
        if link["ticket"] is None and not self.auto_create:
            link.update(revision=ev["revision"], state=ev["state"], last=ev)
            return 200, {
                "applied": True,
                "created": False,
                "ticket": None,
                "note": "Automatic ticket creation is off",
            }
        if link["ticket"] is None and ev["state"] != "resolved":
            tid = len(self.tickets) + 1
            self.tickets[tid] = {
                "title": ev["title"],
                "status": "New",
                "category": "new",
                "entity": ev["entity"],
            }
            link["ticket"], created = tid, True
        elif link["ticket"]:
            t = self.tickets[link["ticket"]]
            terminal = t["category"] in ("resolved", "closed")
            if ev["state"] == "resolved" and link["state"] != "resolved":
                t["category"], t["status"] = "resolved", "Resolved"
            elif ev["persisting"] and not link["persisting"] and terminal:
                t["category"], t["status"] = "open", "In Progress"
        link.update(
            revision=ev["revision"], state=ev["state"], persisting=ev["persisting"], last=ev
        )
        return (201 if created else 200), {
            "applied": True,
            "created": created,
            "ticket": self.snapshot(link["ticket"]) if link["ticket"] else None,
        }


@pytest.fixture(scope="module")
def lab_rt(tmp_path_factory: pytest.TempPathFactory) -> Runtime:
    return scanned_lab(tmp_path_factory.mktemp("taskora"))


@pytest.fixture
def rt(lab_rt: Runtime) -> Runtime:
    with lab_rt.sessions() as s:
        s.query(TaskoraLink).delete()
        s.query(TaskoraState).delete()
        for i in s.scalars(select(Incident)):
            i.acknowledged_at = i.acknowledged_by = None
        s.commit()
    return lab_rt


SETTINGS = tk.TaskoraSettings(
    url="https://taskora.example.test", instance="atlas-home", incidents=True
)


def client(
    fake: Callable[[httpx.Request], httpx.Response], token: str | None = TOKEN, **kw: Any
) -> tk.TaskoraClient:
    return tk.TaskoraClient(
        kw.pop("settings", SETTINGS),
        SecretStr(token) if token else None,
        MemoryAudit(),
        transport=httpx.MockTransport(fake),
        **kw,
    )


def later(minutes: int = 10) -> Any:
    return utcnow() + timedelta(minutes=minutes)


def run(rt: Runtime, fake: FakeTaskora, now: Any = None, **kw: Any) -> dict[str, int]:
    inv, _ = load_lab("B", LAB)
    with rt.sessions() as s:
        return asyncio.run(
            tk.tick(s, inv, client(fake, **kw), atlas_url="https://atlas.lan", now=now or later())
        )


def test_incidents_become_one_ticket_each_with_the_affected_machine(rt: Runtime) -> None:
    fake = FakeTaskora()
    out = run(rt, fake)
    assert out["delivered"] == out["staged"] >= 3
    keys = set(fake.links)
    assert len(keys) == len(fake.tickets) == out["delivered"]
    media = next(lk["last"] for lk in fake.links.values() if lk["last"]["kind"] == "media.storage")
    assert media["entity"]["name"] == "media01"
    assert media["entity"]["kind"] in ("pve-lxc", "pve-vm", "linux-host")
    assert media["link"] == "https://atlas.lan/incidents"
    assert media["state"] == "open" and media["evidence"]
    # Optional nested fields are absent, never null (Taskora's contract).
    assert all(v is not None for v in media["entity"].values())
    with rt.sessions() as s:
        links = list(s.scalars(select(TaskoraLink)))
        assert all(lk.ticket_number and lk.sent_revision == lk.revision for lk in links)

    # Nothing changed: nothing is sent again.
    before = len(fake.requests)
    again = run(rt, fake)
    assert again["staged"] == again["delivered"] == 0
    assert [r for r in fake.requests[before:] if r[0] == "POST"] == []


def test_replay_is_harmless(rt: Runtime) -> None:
    fake = FakeTaskora()
    run(rt, fake)
    with rt.sessions() as s:
        assert tk.replay_all(s) >= 3
        s.commit()
    tickets = len(fake.tickets)
    out = run(rt, fake)
    assert out["delivered"] >= 3
    assert len(fake.tickets) == tickets  # Taskora ignored revisions it already had


def test_technician_ack_is_reflected_without_echo(rt: Runtime) -> None:
    fake = FakeTaskora()
    run(rt, fake)
    key = next(k for k, v in fake.links.items() if v["last"]["kind"] == "media.storage")
    fake.technician(key, "status_changed", "open")
    fake.technician(key, "note_added", actor="Automation", automation=True)
    before = len(fake.requests)
    out = run(rt, fake)
    assert out["feed"] == 2
    with rt.sessions() as s:
        inc = s.get_one(Incident, int(key.split(":")[1]))
        assert inc.acknowledged_by == "Taskora: Sam Tech"
        link = s.get_one(TaskoraLink, inc.id)
        assert link.ack_source == "taskora" and link.ticket_status == "Open"
    # The acknowledgement came from Taskora: nothing is sent back for it.
    assert [r for r in fake.requests[before:] if r[0] == "POST"] == []


def test_ticket_closed_while_still_failing_reopens_once_then_recovery_resolves(rt: Runtime) -> None:
    fake = FakeTaskora()
    run(rt, fake)
    key = next(k for k, v in fake.links.items() if v["last"]["kind"] == "media.storage")
    fake.technician(key, "resolved", "resolved")
    run(rt, fake)  # feed: ticket resolved, incident still open -> persisting staged
    out = run(rt, fake)  # delivered: Taskora reopens
    assert out["delivered"] >= 1
    assert fake.links[key]["last"]["persisting"] is True
    tid = fake.links[key]["ticket"]
    assert fake.tickets[tid]["category"] == "open"
    # Taskora's answer says the ticket is open again: the flag clears once, then quiet.
    run(rt, fake)
    stable = len(fake.requests)
    run(rt, fake)
    assert [r for r in fake.requests[stable:] if r[0] == "POST"] == []
    # atlas sees recovery: the ticket is resolved by policy.
    with rt.sessions() as s:
        inc = s.get_one(Incident, int(key.split(":")[1]))
        inc.resolved_at = utcnow()
        s.commit()
    run(rt, fake)
    assert fake.links[key]["last"]["state"] == "resolved"
    assert fake.tickets[tid]["category"] == "resolved"
    with rt.sessions() as s:
        s.get_one(Incident, int(key.split(":")[1])).resolved_at = None  # leave the lab as found
        s.commit()


def test_retries_back_off_and_errors_are_classified(rt: Runtime) -> None:
    fake = FakeTaskora()
    fake.fail = [503]
    now = later()
    out = run(rt, fake, now=now)
    assert out["failed"] == 1 and out["delivered"] == 0  # stops at the first failure: order kept
    with rt.sessions() as s:
        bad = [lk for lk in s.scalars(select(TaskoraLink)) if lk.error_kind]
        assert len(bad) == 1 and bad[0].error_kind == "retry" and bad[0].attempts == 1
        assert bad[0].next_attempt_at is not None and bad[0].next_attempt_at > now
        assert "503" in (bad[0].last_error or "")
    assert run(rt, fake, now=now)["delivered"] >= 2  # the others go; the failed one waits
    assert run(rt, fake, now=now + timedelta(minutes=2))["delivered"] == 1
    with rt.sessions() as s:
        assert not [lk for lk in s.scalars(select(TaskoraLink)) if lk.error_kind]


def test_revoked_token_is_a_configuration_error_and_bad_payloads_are_held(rt: Runtime) -> None:
    fake = FakeTaskora()
    out = run(rt, fake, token="tki_ATLASFAKEwrongwrongwrongwrongwrongwrong0")
    assert out["failed"] == 1
    with rt.sessions() as s:
        lk = next(x for x in s.scalars(select(TaskoraLink)) if x.error_kind)
        assert lk.error_kind == "config" and "token refused" in (lk.last_error or "")
        due = lk.next_attempt_at
        assert due is not None and due - later() > timedelta(minutes=15)
        tk.retry_held(s)
        s.commit()
    fake.fail = [400]
    run(rt, fake)
    with rt.sessions() as s:
        held = [x for x in s.scalars(select(TaskoraLink)) if x.error_kind == "permanent"]
        assert len(held) == 1 and held[0].next_attempt_at is None
        assert tk.retry_held(s) == 1
        s.commit()
    run(rt, fake)
    with rt.sessions() as s:
        assert not [x for x in s.scalars(select(TaskoraLink)) if x.error_kind]


def test_incident_taken_without_a_ticket_is_sent_again_until_taskora_opens_one(
    rt: Runtime,
) -> None:
    fake = FakeTaskora()
    fake.auto_create = False
    now = later()
    out = run(rt, fake, now=now)
    assert out["delivered"] >= 3 and fake.tickets == {}
    with rt.sessions() as s:
        links = list(s.scalars(select(TaskoraLink)))
        assert all(lk.error_kind == "config" and lk.sent_revision < lk.revision for lk in links)
        assert all(
            lk.last_error == "Taskora created no ticket: Automatic ticket creation is off"
            for lk in links
        )
        assert tk.status(s)["failing"] == len(links)  # the Integrations page shows why
    before = len(fake.requests)
    run(rt, fake, now=now + timedelta(minutes=1))
    assert [r for r in fake.requests[before:] if r[0] == "POST"] == []  # no hammering
    # Turned on in Taskora: the next re-send opens the tickets; then all is quiet.
    fake.auto_create = True
    out = run(rt, fake, now=now + timedelta(minutes=31))
    assert len(fake.tickets) == out["delivered"] == len(links)
    with rt.sessions() as s:
        assert all(
            lk.ticket_number and not lk.error_kind and lk.sent_revision == lk.revision
            for lk in s.scalars(select(TaskoraLink))
        )


def test_blips_and_old_resolved_incidents_never_become_tickets(rt: Runtime) -> None:
    fake = FakeTaskora()
    out = run(rt, fake, now=utcnow())  # incidents opened moments ago: not yet sustained
    assert out["staged"] == 0 and fake.tickets == {}


def test_incidents_off_sends_nothing(rt: Runtime) -> None:
    fake = FakeTaskora()
    off = SETTINGS.model_copy(update={"incidents": False})
    out = run(rt, fake, settings=off)
    assert out == {"staged": 0, "delivered": 0, "failed": 0, "feed": 0}
    assert fake.requests == []


def test_inventory_preview_shape_and_relations(rt: Runtime) -> None:
    fake = FakeTaskora()
    with rt.sessions() as s:
        result = asyncio.run(tk.inventory_sync(s, client(fake), "preview"))
        s.commit()
        st = s.get_one(TaskoraState, 1)
        assert st.inventory_mode == "preview" and st.inventory_result == result
    body = fake.inventories[0]
    assert body["mode"] == "preview" and body["complete"] is True
    kinds = {e["kind"] for e in body["entities"]}
    assert {
        "pve-node",
        "pve-vm",
        "pve-lxc",
        "nas",
        "unifi-switch",
        "unifi-ap",
        "unifi-gateway",
    } <= kinds
    assert not kinds - set(tk.CMDB_KINDS)  # never phones, TVs or IoT clients
    assert not [e for e in body["entities"] if "template" in e["name"]]  # templates are not CIs
    vm = next(e for e in body["entities"] if e["key"] == "pve:vm:homelab/101")
    assert vm["name"] == "docker01" and vm["vmid"] == 101 and vm["pveNode"] == "pve1"
    assert "bc:24:11:46:66:ca" in vm["macs"]
    assert all(not m.startswith(("02:42",)) for e in body["entities"] for m in e["macs"])
    rels = {(r["from"], r["type"], r["to"]) for r in body["relations"]}
    assert ("pve:vm:homelab/101", "hosted_on", "pve:node:homelab/pve1") in rels
    assert ("unifi:dev:e4:38:83:00:00:03", "connected_to", "unifi:dev:e4:38:83:00:00:02") in rels
    port = [
        r
        for r in body["relations"]
        if r["from"] == "pve:lxc:homelab/201" and r["type"] == "connected_to"
    ]
    assert port and port[0]["detail"] == "port 5"
    text = json.dumps(body)
    assert "ATLASFAKE" not in text and "redacted" not in text.lower()
    assert result["stats"]["create"] == len(body["entities"])


def test_an_apply_while_taskora_cmdb_is_off_is_recorded_as_a_preview(rt: Runtime) -> None:
    class Off(FakeTaskora):
        def __call__(self, request: httpx.Request) -> httpx.Response:
            res = super().__call__(request)
            if request.url.path.endswith("/inventory"):
                body = res.json() | {"mode": "preview", "cmdbMode": "off"}
                return httpx.Response(200, json=body)
            return res

    with rt.sessions() as s:
        result = asyncio.run(tk.inventory_sync(s, client(Off()), "apply"))
        s.commit()
        st = s.get_one(TaskoraState, 1)
        assert st.inventory_mode == "preview" and result["cmdbMode"] == "off"


def test_auto_inventory_applies_once_per_scan(rt: Runtime) -> None:
    fake = FakeTaskora()
    auto = SETTINGS.model_copy(update={"cmdb_auto": True, "incidents": False})
    run(rt, fake, settings=auto)
    run(rt, fake, settings=auto)
    assert [b["mode"] for b in fake.inventories] == ["apply"]


def test_settings_validation(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="private LAN IP"):
        tk.save_settings(
            tmp_path, tk.TaskoraSettings(url="http://taskora.example.test", allow_http=True)
        )
    with pytest.raises(ValueError, match="private LAN IP"):
        tk.save_settings(tmp_path, tk.TaskoraSettings(url="http://10.0.0.5:8080"))
    ok = tk.TaskoraSettings(url="http://10.0.0.5:8080", allow_http=True, instance="atlas-home")
    tk.save_settings(tmp_path, ok)
    assert tk.load_settings(tmp_path) == ok
    with pytest.raises(ValueError):
        tk.TaskoraSettings(url="https://taskora.example.test/../x")
    with pytest.raises(ValueError):
        tk.TaskoraSettings(url="https://taskora.example.test", instance="Bad Instance")


def test_untrusted_ticket_snapshots_are_ignored() -> None:
    link = TaskoraLink(incident_id=1, revision=1, sent_revision=1)
    now = utcnow()
    tk._remember_ticket(
        link,
        {
            "id": 3,
            "number": "TKA-3",
            "status": "x",
            "statusCategory": "new",
            "path": "javascript:alert(1)",
        },
        now,
    )
    assert link.ticket_id is None
    tk._remember_ticket(
        link,
        {
            "id": 3,
            "number": "TKA-3",
            "status": "x",
            "statusCategory": "hacked",
            "path": "/tickets/3",
        },
        now,
    )
    assert link.ticket_id is None
    tk._remember_ticket(
        link,
        {
            "id": 3,
            "number": "TKA-3",
            "status": "New",
            "statusCategory": "new",
            "path": "/tickets/3",
        },
        now,
    )
    stored: tuple[object, object] = (link.ticket_id, link.ticket_path)
    assert stored == (3, "/tickets/3")


def test_backoff_grows_and_is_capped() -> None:
    import random  # noqa: PLC0415

    rng = random.Random(1)  # noqa: S311 - deterministic jitter for the test
    waits = [tk.backoff(n, rng).total_seconds() for n in (1, 2, 3, 10, 30)]
    assert 24 <= waits[0] <= 36 and waits[1] > waits[0] and waits[2] > waits[1]
    assert waits[-1] <= tk.BACKOFF_MAX_S * 1.2


def test_migration_creates_taskora_tables(tmp_path: Path) -> None:
    rt = Runtime.open(tmp_path, mode="demo")
    with rt.sessions() as s:
        assert s.scalars(select(TaskoraLink)).all() == []
        assert s.get(TaskoraState, 1) is None


def test_saved_settings_without_a_token_do_not_break_the_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a missing vault secret raised SecretError (not KeyError) -> page 500."""
    from homelab_atlas.engine.notify import save_webhook_settings  # noqa: PLC0415

    monkeypatch.setenv("ATLAS_CONFIG_DIR", str(tmp_path / "cfg"))
    rt = Runtime.open(tmp_path / "data", mode="live")
    tk.save_settings(rt.data_dir, SETTINGS)
    save_webhook_settings(rt.data_dir, "https://n8n.example.test/webhook/atlas", False)
    client = rt.taskora()
    assert client is not None and client.has_token is False
    notifier = rt.notifier()
    assert notifier is not None and notifier.has_token is False
