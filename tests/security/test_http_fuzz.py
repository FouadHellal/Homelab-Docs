"""Property tests: whatever goes into a path variable or a template, nothing escapes."""

import asyncio
import contextlib
import re

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from homelab_atlas.security.allowlist import DENIED_SEGMENTS, Endpoint
from homelab_atlas.security.errors import SecurityRefusal
from homelab_atlas.security.http import ReadOnlyHttpClient
from tests.helpers import MemoryAudit

pytestmark = pytest.mark.security

EP = Endpoint(
    id="loose", method="GET", path_template="/nodes/{node}/qemu", path_vars={"node": r".+"}
)
SAFE_FINAL = re.compile(r"/api2/json/nodes/[A-Za-z0-9][A-Za-z0-9._:@-]*/qemu")

TRICKS = ["..", ".", "%2e", "%2f", "%5c", "%25", "/", "\\", ";", "?", "#", "&", "\x00", "\n",
          "\r", " ", "．", "∕", "⁄", "start", "actions", "exec", "@", ":", "~"]  # fmt: skip
evil_values = st.one_of(
    st.text(min_size=0, max_size=40),
    st.lists(st.sampled_from([*TRICKS, "pve1", "a", "1"]), min_size=1, max_size=8).map("".join),
)


def _attempt(value: str) -> list[httpx.Request]:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={})

    async def go() -> None:
        async with ReadOnlyHttpClient(
            target="t",
            base_url="https://pve.test:8006/api2/json",
            endpoints=(EP,),
            audit=MemoryAudit(),
            tls=None,
            transport=httpx.MockTransport(handler),
        ) as c:
            with contextlib.suppress(SecurityRefusal):
                await c.get(EP, {"node": value})

    asyncio.run(go())
    return seen


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(evil_values)
def test_path_var_never_escapes(value: str) -> None:
    for req in _attempt(value):
        path = req.url.path
        assert req.method == "GET"
        assert req.url.host == "pve.test"
        assert SAFE_FINAL.fullmatch(path), path
        assert req.url.raw_path == path.encode()  # no percent-encoding survived
        segments = path.split("/")
        assert len(segments) == 6
        assert not {s.lower() for s in segments} & DENIED_SEGMENTS
        assert ".." not in path


segment = st.one_of(
    st.from_regex(r"[A-Za-z0-9._-]{1,12}", fullmatch=True),
    st.sampled_from(TRICKS),
    st.text(max_size=6),
)


@settings(max_examples=400, deadline=None)
@given(st.lists(segment, min_size=1, max_size=6))
def test_template_validation_is_total(segments: list[str]) -> None:
    template = "/" + "/".join(segments)
    try:
        ep = Endpoint(id="f", method="GET", path_template=template)
    except ValueError:
        return
    for seg in ep.path_template[1:].split("/"):
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", seg)
        assert seg.lower() not in DENIED_SEGMENTS
        assert seg not in {".", ".."}
