"""Local accounts: argon2id hashes, lockout, server-side sessions with CSRF tokens (ADR-013)."""

import contextlib
import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from homelab_atlas.store.tables import User, WebSession, utcnow

USERNAME_RE: Final = re.compile(r"[a-z][a-z0-9_.-]{2,63}")
MIN_PASSWORD: Final = 12
MAX_PASSWORD: Final = 1024
MAX_FAILURES: Final = 5
LOCKOUT: Final = timedelta(minutes=15)
IDLE: Final = timedelta(minutes=30)
ABSOLUTE: Final = timedelta(hours=12)

_hasher = PasswordHasher()  # argon2id, library defaults (RFC 9106 low-memory profile)
#: Verified against when the user does not exist, so timing does not reveal valid names.
_DUMMY_HASH: Final = _hasher.hash(secrets.token_urlsafe(16))


class AuthError(ValueError):
    pass


def token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class LoginResult:
    token: str | None
    reason: str = ""


@dataclass(frozen=True, slots=True)
class CurrentUser:
    id: int
    username: str
    csrf: str
    session_id: str


def create_user(s: Session, username: str, password: str) -> User:
    if not USERNAME_RE.fullmatch(username):
        raise AuthError("username: 3-64 chars, lowercase letters, digits, . _ -")
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise AuthError(f"password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
    if s.scalar(select(User).where(User.username == username)) is not None:
        raise AuthError("user exists")
    user = User(username=username, password_hash=_hasher.hash(password))
    s.add(user)
    s.flush()
    return user


def set_password(s: Session, username: str, password: str) -> None:
    user = s.scalar(select(User).where(User.username == username))
    if user is None:
        raise AuthError("no such user")
    if not MIN_PASSWORD <= len(password) <= MAX_PASSWORD:
        raise AuthError(f"password must be {MIN_PASSWORD}-{MAX_PASSWORD} characters")
    user.password_hash = _hasher.hash(password)
    user.failed_logins, user.locked_until = 0, None
    s.execute(delete(WebSession).where(WebSession.user_id == user.id))  # log out everywhere


def login(s: Session, username: str, password: str, now: datetime | None = None) -> LoginResult:
    now = now or utcnow()
    user = s.scalar(select(User).where(User.username == username)) if len(username) <= 64 else None
    password = password[:MAX_PASSWORD]
    if user is None:
        with contextlib.suppress(VerificationError):
            _hasher.verify(_DUMMY_HASH, password)
        return LoginResult(None, "invalid credentials")
    if user.locked_until is not None and user.locked_until > now:
        return LoginResult(None, "account temporarily locked")
    try:
        _hasher.verify(user.password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        user.failed_logins += 1
        if user.failed_logins >= MAX_FAILURES:
            user.locked_until, user.failed_logins = now + LOCKOUT, 0
        return LoginResult(None, "invalid credentials")
    if _hasher.check_needs_rehash(user.password_hash):
        user.password_hash = _hasher.hash(password)
    user.failed_logins, user.locked_until, user.last_login = 0, None, now
    token = secrets.token_urlsafe(32)
    s.add(
        WebSession(
            id=token_id(token),
            user_id=user.id,
            csrf=secrets.token_urlsafe(32),
            created_at=now,
            last_seen=now,
            expires_at=now + ABSOLUTE,
        )
    )
    return LoginResult(token)


def resolve(s: Session, token: str | None, now: datetime | None = None) -> CurrentUser | None:
    if not token or len(token) > 128:
        return None
    now = now or utcnow()
    sess = s.get(WebSession, token_id(token))
    if sess is None:
        return None
    if sess.expires_at <= now or sess.last_seen + IDLE <= now:
        s.delete(sess)
        return None
    sess.last_seen = now
    user = s.get(User, sess.user_id)
    if user is None:
        return None
    return CurrentUser(user.id, user.username, sess.csrf, sess.id)


def logout(s: Session, token: str | None) -> None:
    if token:
        s.execute(delete(WebSession).where(WebSession.id == token_id(token)))


def csrf_ok(expected: str, supplied: str | None) -> bool:
    return bool(supplied) and hmac.compare_digest(expected.encode(), (supplied or "").encode())
