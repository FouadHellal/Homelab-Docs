"""Redaction rules (ADR-009). Ordered most-specific first.

A `TextRule` names the capture group holding the secret; everything else in the match is
kept, so `MYSQL_PASSWORD=hunter2` becomes `MYSQL_PASSWORD=«redacted:assign:…»`.
"""

import re
from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class TextRule:
    name: str
    pattern: re.Pattern[str]
    group: int = 0  # 0 = whole match is the secret
    #: Only applied if the string contains one of these (case-insensitive) words.
    context: tuple[str, ...] = ()
    #: Group holding a variable name; the match is skipped if that name is metadata
    #: (PASSWORD_FILE=/run/secrets/x is a path, not a secret).
    key_group: int | None = None


def _r(p: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


_I = re.IGNORECASE

_SECRET_WORDS = (
    r"password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|privkey|"
    r"access[_-]?key|auth[_-]?key|auth[_-]?token|client[_-]?secret|psk|credentials?|"
    r"webhook[_-]?url|dsn|encryption[_-]?key|master[_-]?key|signing[_-]?key|"
    r"basicauth|htpasswd|x[_-]passphrase|wpa[_-]?key|[_.-]pass(?![A-Za-z])"
)

TEXT_RULES: Final[tuple[TextRule, ...]] = (
    # --- key material -------------------------------------------------------------
    TextRule(
        "pem",
        _r(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
            re.DOTALL,
        ),
    ),
    TextRule("wireguard", _r(r"(?i)(PrivateKey|PresharedKey)(\s*=\s*)([A-Za-z0-9+/]{42,44}=?)"), 3),
    # --- credentials embedded in URLs and headers ---------------------------------
    TextRule("url_userinfo", _r(r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]*:([^\s/@]+)@"), 1),
    TextRule("pve_token", _r(r"(?i)PVEAPIToken=[^\s=!]+![^\s=]+=([0-9a-f-]{8,})"), 1),
    TextRule("bearer", _r(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})"), 1),
    TextRule("basic", _r(r"(?i)\bbasic\s+(?=[A-Za-z0-9+/=]*[0-9=])([A-Za-z0-9+/=]{8,})"), 1),
    TextRule(
        "token_word",
        _r(r"(?i)\btoken\s+(?=[A-Za-z0-9._~+/=-]*\d)([A-Za-z0-9._~+/=-]{16,})"),
        1,
    ),
    TextRule(
        "header",
        _r(r"(?i)\b(?:x-api-key|x-auth-token|api-key|x-csrf-token)\s*[:=]\s*[\"']?([^\s\"',;]+)"),
        1,
    ),
    TextRule(
        "webhook",
        _r(
            r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|"
            r"[a-z0-9.-]*webhook\.office\.com)/[^\s\"']+"
        ),
    ),
    # --- well-known token formats (whole match) -----------------------------------
    TextRule("jwt", _r(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    TextRule("github", _r(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    TextRule("gitlab", _r(r"\bglpat-[A-Za-z0-9_-]{20,}")),
    TextRule("aws_akid", _r(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")),
    TextRule("slack", _r(r"\bxox[abprse]-[A-Za-z0-9-]{10,}")),
    TextRule("stripe", _r(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}")),
    TextRule("google_api", _r(r"\bAIza[0-9A-Za-z_-]{35}")),
    TextRule("anthropic", _r(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    TextRule("openai", _r(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    TextRule("npm", _r(r"\bnpm_[A-Za-z0-9]{36}")),
    TextRule("docker_pat", _r(r"\bdckr_pat_[A-Za-z0-9_-]{20,}")),
    TextRule("vault", _r(r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}")),
    TextRule("tailscale", _r(r"\btskey-[A-Za-z0-9-]{20,}")),
    TextRule("telegram", _r(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    # --- password hashes ----------------------------------------------------------
    TextRule("bcrypt", _r(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}")),
    TextRule("shacrypt", _r(r"\$[56]\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{43,86}")),
    TextRule("apr1", _r(r"\$apr1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}")),
    TextRule("yescrypt", _r(r"\$y\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+\$[./A-Za-z0-9]{20,}")),
    TextRule(
        "argon2",
        _r(r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+"),
    ),
    # --- command lines ------------------------------------------------------------
    TextRule(
        "cli_flag",
        _r(
            r"(?i)(?<![\w-])--?(?:password|passwd|pass|pwd|token|secret|api[-_]?key|apikey|"
            r"auth[-_]?token|access[-_]?key|secret[-_]?key|client[-_]?secret|private[-_]?key|"
            r"psk|passphrase|credentials?|bearer|requirepass|masterauth)"
            r"(?:=|\s+)[\"']?([^\s\"']+)"
        ),
        1,
    ),
    TextRule(
        "mysql_p",
        _r(r"(?<![\w-])-p([^\s-][^\s]*)"),
        1,
        context=("mysql", "mariadb", "mysqldump", "mysqladmin"),
    ),
    TextRule("sshpass", _r(r"(?<![\w-])-p\s+([^\s]+)"), 1, context=("sshpass",)),
    TextRule("redis_cli", _r(r"(?<![\w-])-a\s+([^\s\"']+)"), 1, context=("redis-cli",)),
    TextRule(
        "redis_auth",
        _r(r"(?i)\b(?:requirepass|masterauth|AUTH)\s+([^\s\"']+)"),
        1,
        context=("redis",),
    ),
    # --- query strings and assignments --------------------------------------------
    TextRule(
        "query",
        _r(
            r"(?i)[?&;](?:access_token|token|api_key|apikey|key|password|passwd|secret|sig|"
            r"signature|auth|client_secret|private_token|x-amz-signature|x-amz-credential)"
            r"=([^&#\s\"']+)"
        ),
        1,
    ),
    TextRule(
        "assign",
        _r(
            r"(?i)(?<![A-Za-z0-9])([A-Za-z0-9_.-]*?(?:" + _SECRET_WORDS + r")[A-Za-z0-9_.-]*)"
            r"[\"']?\s*[=:]\s*[\"']?([^\s\"'&;,}]+)"
        ),
        2,
        key_group=1,
    ),
)

# ----------------------------------------------------------------------- key rules

#: Words in a mapping key that mark its value as secret.
SECRET_KEY_WORDS: Final = frozenset(
    {
        "password", "passwd", "pwd", "passphrase", "secret", "secrets", "token", "tokens",
        "apikey", "psk", "credential", "credentials", "cookie", "cookies", "dsn",
        "authorization", "bearer", "privkey", "htpasswd", "basicauth", "salt", "signature",
        "otp", "totp", "csrf",
    }
)  # fmt: skip
#: Adjacent word pairs that mark a key as secret.
SECRET_KEY_PAIRS: Final = frozenset(
    {
        ("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key"),
        ("client", "secret"), ("auth", "key"), ("auth", "token"), ("wpa", "key"),
        ("encryption", "key"), ("master", "key"), ("signing", "key"), ("webhook", "url"),
        ("session", "id"), ("x", "passphrase"),
    }
)  # fmt: skip
#: "pass" only counts as the last word (db_pass, smtp_pass), not pass_through.
TRAILING_SECRET_WORDS: Final = frozenset({"pass", "pw", "pin"})
#: Words that make a key metadata *about* a secret rather than the secret itself.
META_KEY_WORDS: Final = frozenset(
    {
        "public", "fingerprint", "expiry", "expires", "expiration", "ttl", "length", "len",
        "type", "enabled", "enable", "set", "configured", "required", "file", "path", "policy",
        "id", "ids", "name", "names", "count", "algorithm", "algo", "version", "age",
        "changed", "last", "min", "max", "strength", "format",
    }
)  # fmt: skip
#: Keys whose value is an environment (list of NAME=VALUE or mapping NAME -> VALUE).
ENV_KEY_WORDS: Final = frozenset({"env", "environment", "envs", "environ"})

#: Allowlisted exact keys that would otherwise trip a rule.
SAFE_KEYS: Final = frozenset(
    {"token_id", "tokenid", "session_id_hash", "secret_ref", "credential_ref"}
)
