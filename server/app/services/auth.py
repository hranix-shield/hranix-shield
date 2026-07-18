from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.config import Settings, get_settings, jwt_secret_file
from app.db.models import User
from app.db.session import async_session_maker

JWT_ALGORITHM = "HS256"
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _now_utc_naive() -> datetime:
    """Naive UTC now, matching the non-timezone-aware DateTime columns in db/models.py."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def hash_password(password: str) -> str:
    return _pwd_context.hash(password)


def verify_password(password: str, hashed_password: str) -> bool:
    return _pwd_context.verify(password, hashed_password)


class TokenError(Exception):
    """Raised when a bearer token is missing, malformed, or expired."""


def resolve_jwt_secret(
    settings: Settings | None = None, *, secret_file: Path | None = None
) -> str:
    """Resolve the real JWT signing secret — never a value baked into source.

    An explicit `JWT_SECRET` (env var / .env) always wins. Otherwise, a random
    secret is generated once and persisted to `secret_file` so previously
    issued tokens keep validating across restarts. There is intentionally no
    fallback to a fixed in-code string: this repository is AGPL-licensed, so
    any such constant is public and would let anyone forge a valid admin JWT
    without ever calling /auth/login (found in A-3 security review, fixed
    2026-07-14).

    `secret_file` defaults to None here, resolved to `app.config.jwt_secret_file()`
    *inside the function body* rather than as the signature's default value
    (A-19) — a bound default is captured once, at function-DEFINITION time
    (i.e. import time), so it would silently freeze on whichever mode
    (packaged/not) was active when this module first loaded, never
    reflecting `is_packaged()` again afterwards. `services.backup.service
    .resolve_backup_password_file` already hit exactly this class of bug
    with `RESTIC_PASSWORD_FILE` (see that function's own docstring for the
    real incident) — resolving at call time here avoids re-introducing it
    now that `jwt_secret_file()` is mode-dependent too.
    """
    settings = settings or get_settings()
    if secret_file is None:
        secret_file = jwt_secret_file()
    if settings.jwt_secret:
        return settings.jwt_secret

    if secret_file.exists():
        stored = secret_file.read_text().strip()
        if stored:
            return stored

    secret_file.parent.mkdir(parents=True, exist_ok=True)
    generated = secrets.token_hex(32)
    secret_file.write_text(generated)
    secret_file.chmod(0o600)
    return generated


def create_access_token(username: str, role: str, expires_seconds: int | None = None) -> str:
    settings = get_settings()
    ttl = expires_seconds if expires_seconds is not None else settings.jwt_expiry_seconds
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(seconds=ttl),
    }
    return jwt.encode(payload, resolve_jwt_secret(settings), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    settings = get_settings()
    try:
        return jwt.decode(token, resolve_jwt_secret(settings), algorithms=[JWT_ALGORITHM])
    except JWTError as exc:
        raise TokenError(str(exc)) from exc


def is_account_locked(user: User, *, now: datetime | None = None) -> bool:
    if user.locked_until is None:
        return False
    reference = now or _now_utc_naive()
    return user.locked_until > reference


def register_failed_login(user: User, *, now: datetime | None = None) -> None:
    reference = now or _now_utc_naive()
    user.failed_login_attempts += 1
    if user.failed_login_attempts >= MAX_FAILED_LOGIN_ATTEMPTS:
        user.locked_until = reference + timedelta(minutes=LOCKOUT_DURATION_MINUTES)


def register_successful_login(user: User) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None


async def ensure_bootstrap_admin(
    session_maker: async_sessionmaker[AsyncSession] | None = None,
) -> None:
    """Create the single first admin from env vars if `users` is empty.

    No public registration exists in this single-tenant panel; this is the only
    account-creation path. Skipped entirely when bootstrap credentials are unset,
    or when at least one user already exists.
    """
    settings = get_settings()
    if not settings.bootstrap_admin_username or not settings.bootstrap_admin_password:
        return

    maker = session_maker or async_session_maker
    async with maker() as session:
        user_count = await session.scalar(select(func.count()).select_from(User))
        if user_count:
            return

        admin = User(
            username=settings.bootstrap_admin_username,
            hashed_password=hash_password(settings.bootstrap_admin_password),
            role="admin",
            is_active=True,
        )
        session.add(admin)
        await session.commit()
