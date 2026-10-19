"""Targets-page testers (SSH login, API connection) and the container healthcheck probe."""

import asyncio
import http.server
import ssl
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

from homelab_atlas import runtime
from homelab_atlas.security.health import probe
from homelab_atlas.web.tls import ensure_self_signed
from tests.helpers import MemoryAudit

LAB = Path(__file__).resolve().parents[2] / "fixtures" / "demo-lab"


@pytest.fixture
def lab_live(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the 'live' testers see the replayed demo lab (no network)."""
    monkeypatch.setenv("ATLAS_LAB_DIR", str(LAB))
    monkeypatch.setattr(runtime, "live_inputs", lambda data_dir=None: runtime.lab_inputs("B"))


@pytest.mark.usefixtures("lab_live")
def test_ssh_login_tester(tmp_path: Path) -> None:
    ok, text = asyncio.run(runtime.test_ssh_login(tmp_path, MemoryAudit(), "docker01"))
    assert ok, text
    assert "logged in as" in text
    assert "probe" in text
    ok, text = asyncio.run(runtime.test_ssh_login(tmp_path, MemoryAudit(), "no-such-host"))
    assert not ok
    assert "not in the inventory" in text
    ok, text = asyncio.run(runtime.test_ssh_login(tmp_path, MemoryAudit(), "ghost01"))
    assert not ok  # recorded as unreachable in the lab


@pytest.mark.usefixtures("lab_live")
def test_source_tester(tmp_path: Path) -> None:
    ok, text = asyncio.run(runtime.test_source(tmp_path, MemoryAudit(), "unifi", "ucg"))
    assert ok, text
    assert "10.6.106" in text
    ok, text = asyncio.run(runtime.test_source(tmp_path, MemoryAudit(), "proxmox", "homelab"))
    assert ok, text
    ok, text = asyncio.run(runtime.test_source(tmp_path, MemoryAudit(), "unas", "unas"))
    assert not ok
    assert "use Scan" in text
    ok, text = asyncio.run(runtime.test_source(tmp_path, MemoryAudit(), "unifi", "nope"))
    assert not ok


class _Health(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args: object) -> None:
        pass


def _serve(tls: tuple[Path, Path] | None) -> Iterator[int]:
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    if tls is not None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*tls)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        srv.server_close()


def test_healthcheck_http_and_https(tmp_path: Path) -> None:
    for port in _serve(None):
        assert probe([(port, False)])
        assert not probe([(port, True)])  # wrong scheme fails, and the next entry is tried
    for port in _serve(ensure_self_signed(tmp_path, ["localhost"])):
        assert probe([(0, True), (port, True)])  # invalid port skipped
        assert probe([(1, False), (port, True)], timeout=1.0)
    assert not probe([(1, False)], timeout=0.5)
