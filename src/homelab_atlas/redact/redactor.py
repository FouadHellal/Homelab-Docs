"""Redactor: applied to every collector result before persistence, logging or export.

Secrets become `«redacted:<rule>:<hmac8>»`. The HMAC is keyed per installation, so a
changed secret still shows up as a change in diffs, but the marker cannot be reversed or
dictionary-attacked without the key.
"""

import functools
import hashlib
import hmac
import itertools
import math
import re
import secrets
from collections import Counter
from collections.abc import Mapping
from typing import Any, Final, TypeVar

from pydantic import BaseModel

from homelab_atlas.redact.rules import (
    ENV_KEY_WORDS,
    META_KEY_WORDS,
    SAFE_KEYS,
    SECRET_KEY_PAIRS,
    SECRET_KEY_WORDS,
    TEXT_RULES,
    TRAILING_SECRET_WORDS,
)

MARKER_PREFIX: Final = "«redacted:"
MARKER_RE: Final = re.compile(r"«redacted:[a-z0-9_]+:[0-9a-f]{8}»")
_CAMEL_RE: Final = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT_RE: Final = re.compile(r"[^A-Za-z0-9]+")
_ENTROPY_CANDIDATE_RE: Final = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/=_-]{24,}(?![A-Za-z0-9+/=_-])"
)
_HEX_RE: Final = re.compile(r"[0-9a-fA-F]+")
_UUID_RE: Final = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
_WORDISH_RE: Final = re.compile(r"[a-z]{3,}|[A-Z][a-z]{2,}|[A-Z]{3,}")
#: OpenSSH public key blobs (ssh-ed25519 AAAAC3..., ssh-rsa AAAAB3...) are not secrets.
_SSH_PUBKEY_RE: Final = re.compile(r"AAAA[BCE][0-9A-Za-z+/]+={0,2}")
#: Short flags that take a secret only for certain tools (separate-argument form).
CONTEXT_FLAGS: Final = (
    (("sshpass",), frozenset({"-p"})),
    (("redis-cli",), frozenset({"-a"})),
    (("mysql", "mariadb", "mysqldump", "mysqladmin"), frozenset({"--password"})),
)
ENTROPY_MIN_LEN: Final = 24
ENTROPY_THRESHOLD: Final = 3.5
MAX_DEPTH: Final = 64

J = TypeVar("J")
M = TypeVar("M", bound=BaseModel)


def key_words(key: str) -> list[str]:
    return [w.lower() for w in _SPLIT_RE.split(_CAMEL_RE.sub("_", key)) if w]


def is_secret_key(key: str) -> bool:
    words = key_words(key)
    if not words or "_".join(words) in SAFE_KEYS:
        return False
    hit = (
        any(w in SECRET_KEY_WORDS for w in words)
        or any(p in SECRET_KEY_PAIRS for p in itertools.pairwise(words))
        or words[-1] in TRAILING_SECRET_WORDS
    )
    return hit and not any(w in META_KEY_WORDS for w in words)


def is_env_key(key: str) -> bool:
    words = key_words(key)
    return bool(words) and words[-1] in ENV_KEY_WORDS


def shannon_entropy(s: str) -> float:
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_random(token: str) -> bool:
    if (
        len(token) < ENTROPY_MIN_LEN
        or _HEX_RE.fullmatch(token)
        or _UUID_RE.fullmatch(token)
        or _SSH_PUBKEY_RE.fullmatch(token)
    ):
        return False
    classes = sum(
        (
            any(c.islower() for c in token),
            any(c.isupper() for c in token),
            any(c.isdigit() for c in token),
            any(c in "+/=_-" for c in token),
        )
    )
    if classes < 3:
        return False
    # Identifiers built from words (my-long-container-name-01, CamelCaseThing) are not secrets.
    parts = [p for p in re.split(r"[/_.=+-]", token) if p]
    wordish = sum(len(m) for p in parts for m in _WORDISH_RE.findall(p))
    if wordish >= len(token) * 0.5:
        return False
    return shannon_entropy(token) >= ENTROPY_THRESHOLD


class Redactor:
    def __init__(self, hmac_key: bytes, *, entropy: bool = True) -> None:
        if len(hmac_key) < 16:
            raise ValueError("hmac_key must be at least 16 bytes")
        self._key = hmac_key
        self._entropy = entropy
        self.counts: Counter[str] = Counter()

    # ------------------------------------------------------------------ markers

    def marker(self, rule: str, secret: str) -> str:
        digest = hmac.new(self._key, secret.encode("utf-8", "surrogatepass"), hashlib.sha256)
        self.counts[rule] += 1
        return f"{MARKER_PREFIX}{rule}:{digest.hexdigest()[:8]}»"

    # ------------------------------------------------------------------ text

    def text(self, s: str, context: str = "") -> str:
        """Redact one string. `context` widens contextual rules (e.g. a whole argv)."""
        if not s:
            return s
        lowered = f"{s.lower()} {context}"
        for rule in TEXT_RULES:
            if rule.context and not any(word in lowered for word in rule.context):
                continue
            s = rule.pattern.sub(
                functools.partial(
                    self._replace, rule=rule.name, group=rule.group, key_group=rule.key_group
                ),
                s,
            )
        if self._entropy:
            s = _ENTROPY_CANDIDATE_RE.sub(self._entropy_sub, s)
        return s

    def _replace(self, m: re.Match[str], *, rule: str, group: int, key_group: int | None) -> str:
        secret = m.group(group)
        if not secret or secret.startswith(MARKER_PREFIX) or MARKER_RE.fullmatch(secret):
            return m.group(0)
        words = key_words(m.group(key_group)) if key_group is not None else []
        if words and words[-1] in META_KEY_WORDS:
            return m.group(0)
        start, end = m.start(group) - m.start(0), m.end(group) - m.start(0)
        whole = m.group(0)
        return whole[:start] + self.marker(rule, secret) + whole[end:]

    def _entropy_sub(self, m: re.Match[str]) -> str:
        token = m.group(0)
        return self.marker("entropy", token) if _looks_random(token) else token

    # ------------------------------------------------------------------ structures

    def data(self, obj: J) -> J:
        return self._walk(obj, 0)  # type: ignore[no-any-return]

    def model(self, model: M) -> M:
        """Redact a model via its JSON form. Secret-bearing fields must be `str`-typed."""
        return type(model).model_validate(self.data(model.model_dump(mode="json")))

    def _walk(self, obj: Any, depth: int) -> Any:
        if depth > MAX_DEPTH:
            return self.marker("depth", repr(type(obj)))
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, Mapping):
            return {k: self._walk_item(str(k), v, depth + 1) for k, v in obj.items()}
        if isinstance(obj, list | tuple):
            if len(obj) > 1 and all(isinstance(v, str) for v in obj):
                return self._argv(list(obj))
            return [self._walk(v, depth + 1) for v in obj]
        return obj  # int, float, bool, None

    def _argv(self, items: list[str]) -> list[str]:
        """String lists may be argv (container cmd, healthcheck): a secret-named flag such as
        `--http-api-token` redacts the following element; contextual rules see the whole line."""
        ctx = " ".join(items).lower()
        context_flags = {
            f for words, flags in CONTEXT_FLAGS if any(w in ctx for w in words) for f in flags
        }
        out: list[str] = []
        redact_next = False
        for item in items:
            if redact_next and not item.startswith("-"):
                out.append(item if MARKER_RE.fullmatch(item) else self.marker("argv", item))
                redact_next = False
                continue
            out.append(self.text(item, context=ctx))
            name = item.lstrip("-")
            redact_next = (
                item.startswith("-")
                and "=" not in item
                and bool(name)
                and (is_secret_key(name) or item in context_flags)
            )
        return out

    def _walk_item(self, key: str, value: Any, depth: int) -> Any:
        if is_env_key(key):
            return self._env(value, depth)
        if is_secret_key(key):
            return self._secret_value(key, value, depth)
        return self._walk(value, depth)

    def _secret_value(self, key: str, value: Any, depth: int) -> Any:
        if value is None or isinstance(value, bool) or value == "":
            return value  # presence flags carry no secret
        if isinstance(value, str) and MARKER_RE.fullmatch(value):
            return value
        if isinstance(value, Mapping):
            return {k: self._secret_value(str(k), v, depth + 1) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self._secret_value(key, v, depth + 1) for v in value]
        return self.marker("key", str(value))

    def _env(self, value: Any, depth: int) -> Any:
        """Environments keep variable NAMES only (security requirement 4)."""
        if isinstance(value, Mapping):
            return sorted(str(k) for k in value)
        if isinstance(value, list | tuple):
            names: list[str] = []
            for item in value:
                if isinstance(item, str):
                    name = item.split("=", 1)[0]
                    names.append(
                        name
                        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name)
                        else self.marker("env", item)
                    )
                else:
                    names.append(self._walk(item, depth + 1))
            return names
        return self._walk(value, depth)


_default = Redactor(secrets.token_bytes(32))


def redact_text(s: str) -> str:
    """Process-wide redaction for logs and audit details (markers stable per process)."""
    return _default.text(s)


def redact_data[J](obj: J) -> J:
    return _default.data(obj)
