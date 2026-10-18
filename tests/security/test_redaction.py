"""Redactor: nasty corpus, false positives, structures, idempotence, properties, logging."""

import io
import json
from pathlib import Path
from typing import Any

import pytest
import structlog
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import BaseModel

from homelab_atlas.log import configure_logging
from homelab_atlas.redact import MARKER_RE, Redactor, is_secret_key

pytestmark = pytest.mark.security

CORPUS = json.loads(
    (Path(__file__).parent / "corpus" / "redaction.json").read_text(encoding="utf-8")
)
KEY = b"test-hmac-key-0123456789abcdef"


@pytest.fixture
def r() -> Redactor:
    return Redactor(KEY)


@pytest.mark.parametrize("case", CORPUS["secrets"], ids=lambda c: c["id"])
def test_corpus_secrets_removed(r: Redactor, case: dict[str, Any]) -> None:
    out = r.text(case["text"])
    for secret in case["secrets"]:
        assert secret not in out, f"{case['id']}: leaked in {out!r}"
    assert "ATLASFAKE" not in out or MARKER_RE.search(out)
    assert MARKER_RE.search(out)


@pytest.mark.parametrize("text", [b["text"] for b in CORPUS["benign"]])
def test_benign_unchanged(r: Redactor, text: str) -> None:
    assert r.text(text) == text


@pytest.mark.parametrize("case", CORPUS["argv"], ids=lambda c: " ".join(c["argv"])[:30])
def test_argv_lists(r: Redactor, case: dict[str, Any]) -> None:
    out = r.data({"cmd": case["argv"]})["cmd"]
    joined = "\n".join(out)
    for secret in case["secrets"]:
        assert secret not in joined
    for keep in case["keep"]:
        assert keep in out


def test_keeps_variable_names(r: Redactor) -> None:
    out = r.text("MYSQL_ROOT_PASSWORD=hunter2-ATLASFAKE other=1")
    assert out.startswith("MYSQL_ROOT_PASSWORD=«redacted:")
    assert out.endswith(" other=1")
    out = r.text("postgres://immich:pg-ATLASFAKE@db:5432/immich")
    assert out.startswith("postgres://immich:«redacted:url_userinfo:")
    assert out.endswith("@db:5432/immich")


def test_idempotent(r: Redactor) -> None:
    for case in CORPUS["secrets"]:
        once = r.text(case["text"])
        assert r.text(once) == once, case["id"]


def test_markers_are_keyed_and_stable() -> None:
    a, b = Redactor(KEY), Redactor(b"another-key-0123456789abcdef")
    s = "API_KEY=k-ATLASFAKE-1"
    assert a.text(s) == a.text(s)
    assert a.text(s) != b.text(s)
    assert a.text(s) != a.text("API_KEY=k-ATLASFAKE-2")


def test_short_hmac_key_rejected() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        Redactor(b"short")


# --------------------------------------------------------------------------- structures


def test_env_list_and_dict_keep_names_only(r: Redactor) -> None:
    data: dict[str, Any] = {
        "Config": {
            "Env": ["POSTGRES_PASSWORD=pg-ATLASFAKE", "TZ=Europe/Paris", "PATH=/usr/bin", "=bad"],
        },
        "environment": {"API_KEY": "k-ATLASFAKE", "TZ": "UTC"},
    }
    out = r.data(data)
    assert out["Config"]["Env"][:3] == ["POSTGRES_PASSWORD", "TZ", "PATH"]
    assert MARKER_RE.fullmatch(out["Config"]["Env"][3])
    assert out["environment"] == ["API_KEY", "TZ"]
    assert "ATLASFAKE" not in json.dumps(out)
    assert "Europe/Paris" not in json.dumps(out)


@pytest.mark.parametrize(
    "key",
    [
        "password", "Password", "db_password", "MYSQL_ROOT_PASSWORD", "apiKey", "api_key",
        "x_passphrase", "wpa_psk", "privateKey", "client_secret", "accessToken", "auth_token",
        "Authorization", "cookie", "dsn", "smtp_pass", "webhookUrl", "secret", "csrfToken",
    ],
)  # fmt: skip
def test_secret_keys(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize(
    "key",
    [
        "keyboard", "monkey", "public_key", "ssh_host_key_fingerprint", "password_set",
        "token_expiry", "psk_enabled", "passthrough", "pass_through", "compass", "key",
        "hostkey", "password_file", "token_id", "secret_ref", "name", "bypass",
    ],
)  # fmt: skip
def test_non_secret_keys(key: str) -> None:
    assert not is_secret_key(key)


def test_secret_key_values(r: Redactor) -> None:
    data: dict[str, Any] = {
        "password": "pw-ATLASFAKE",
        "password_set": True,
        "x_passphrase": "wifi-ATLASFAKE",
        "wpa_psk": 12345678,
        "api_key": None,
        "token": "",
        "credentials": {"user": "u", "pass": "p-ATLASFAKE"},
        "tokens": ["t1-ATLASFAKE", "t2-ATLASFAKE"],
        "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKeep",
        "name": "nas",
    }
    out = r.data(data)
    dumped = json.dumps(out, ensure_ascii=False)
    assert "ATLASFAKE" not in dumped
    assert "12345678" not in dumped
    assert out["password_set"] is True
    assert out["api_key"] is None
    assert out["token"] == ""
    assert out["public_key"] == data["public_key"]
    assert out["name"] == "nas"
    assert all(MARKER_RE.fullmatch(t) for t in out["tokens"])


def test_nested_leak_scan(r: Redactor) -> None:
    """Every corpus secret buried in a realistic collector-shaped document must vanish."""
    texts = [c["text"] for c in CORPUS["secrets"]]
    doc = {
        "host": "docker01",
        "containers": [
            {
                "name": f"c{i}",
                "cmd": ["sh", "-c", t],
                "labels": {f"l{i}": t},
                "healthcheck": {"test": ["CMD-SHELL", t]},
            }
            for i, t in enumerate(texts)
        ],
        "cron": texts,
        "deep": {"a": [{"b": [{"c": t} for t in texts]}]},
    }
    dumped = json.dumps(r.data(doc), ensure_ascii=False)
    for case in CORPUS["secrets"]:
        for secret in case["secrets"]:
            assert secret not in dumped, case["id"]


def test_depth_bomb(r: Redactor) -> None:
    doc: Any = "x"
    for _ in range(200):
        doc = [doc]
    out = r.data(doc)
    assert "redacted:depth" in json.dumps(out)


def test_model_roundtrip(r: Redactor) -> None:
    class Container(BaseModel):
        name: str
        cmd: list[str]
        env: list[str]

    c = Container(name="db", cmd=["--password=pw-ATLASFAKE"], env=["PGPASSWORD=x-ATLASFAKE"])
    out = r.model(c)
    assert isinstance(out, Container)
    assert out.env == ["PGPASSWORD"]
    assert "ATLASFAKE" not in out.model_dump_json()


def test_counts(r: Redactor) -> None:
    r.text("API_KEY=a-ATLASFAKE ghp_ATLASFAKE0123456789abcdefghijklmnopq")
    assert r.counts["assign"] >= 1
    assert r.counts["github"] == 1


# --------------------------------------------------------------------------- properties

token_body = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd"), max_codepoint=127),
    min_size=12,
    max_size=40,
)
TEMPLATES = [
    "--token {s}",
    "--password={s}",
    "API_KEY={s}",
    "MY_SECRET: {s}",
    "https://user:{s}@host.lan/x",
    "Authorization: Bearer {s}",
    "GET /x?access_token={s}&y=1",
    "x_passphrase={s}",
]


@settings(max_examples=400, deadline=None)
@given(body=token_body, template=st.sampled_from(TEMPLATES), prefix=st.text(max_size=20))
def test_property_secret_never_survives(body: str, template: str, prefix: str) -> None:
    secret = "Zz9" + body  # ensure a non-trivial token
    text = prefix + " " + template.format(s=secret)
    out = Redactor(KEY).text(text)
    assert secret not in out


@settings(max_examples=300, deadline=None)
@given(st.text(max_size=200))
def test_property_idempotent_and_total(text: str) -> None:
    r = Redactor(KEY)
    once = r.text(text)
    assert r.text(once) == once


# --------------------------------------------------------------------------- logging


def test_logging_redacts_values_and_tracebacks() -> None:
    buf = io.StringIO()
    configure_logging("DEBUG")
    structlog.configure(logger_factory=structlog.PrintLoggerFactory(file=buf))
    log = structlog.get_logger()
    log.info(
        "connect",
        dsn="postgres://u:pg-ATLASFAKE@db/x",
        headers={"Authorization": "Bearer ey-ATLASFAKE-0123456789"},
        api_key="k-ATLASFAKE",
    )

    def fail() -> None:
        raise RuntimeError("failed with --password=pw-ATLASFAKE")

    try:
        fail()
    except RuntimeError:
        log.exception("boom")
    out = buf.getvalue()
    assert "ATLASFAKE" not in out
    assert out.count("redacted:") >= 4
    structlog.reset_defaults()
