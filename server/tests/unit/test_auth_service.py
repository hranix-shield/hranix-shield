from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.config import Settings
from app.db.models import User
from app.services.auth import (
    LOCKOUT_DURATION_MINUTES,
    MAX_FAILED_LOGIN_ATTEMPTS,
    TokenError,
    create_access_token,
    decode_access_token,
    hash_password,
    is_account_locked,
    register_failed_login,
    register_successful_login,
    resolve_jwt_secret,
    verify_password,
)

OLD_PUBLIC_PLACEHOLDER_SECRET = "dev-insecure-secret-change-me"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _make_user(**overrides) -> User:
    defaults = dict(
        id=1,
        username="alice",
        hashed_password=hash_password("correct horse battery staple"),
        role="viewer",
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
    )
    defaults.update(overrides)
    return User(**defaults)


@pytest.mark.unit
def test_hash_password_is_not_plaintext():
    hashed = hash_password("s3cr3t")

    assert hashed != "s3cr3t"
    assert verify_password("s3cr3t", hashed)
    assert not verify_password("wrong", hashed)


@pytest.mark.unit
def test_access_token_roundtrip():
    token = create_access_token(username="alice", role="admin")

    payload = decode_access_token(token)

    assert payload["sub"] == "alice"
    assert payload["role"] == "admin"


@pytest.mark.unit
def test_decode_rejects_garbage_token():
    with pytest.raises(TokenError):
        decode_access_token("not-a-real-token")


@pytest.mark.unit
def test_decode_rejects_expired_token():
    token = create_access_token(username="alice", role="viewer", expires_seconds=-1)

    with pytest.raises(TokenError):
        decode_access_token(token)


@pytest.mark.unit
def test_is_account_locked_false_when_locked_until_unset():
    user = _make_user(locked_until=None)

    assert not is_account_locked(user)


@pytest.mark.unit
def test_is_account_locked_true_while_in_the_future():
    user = _make_user(locked_until=_utcnow() + timedelta(minutes=5))

    assert is_account_locked(user)


@pytest.mark.unit
def test_is_account_locked_false_once_expired():
    user = _make_user(locked_until=_utcnow() - timedelta(seconds=1))

    assert not is_account_locked(user)


@pytest.mark.unit
def test_register_failed_login_below_threshold_does_not_lock():
    user = _make_user(failed_login_attempts=0, locked_until=None)

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS - 1):
        register_failed_login(user)

    assert user.failed_login_attempts == MAX_FAILED_LOGIN_ATTEMPTS - 1
    assert user.locked_until is None


@pytest.mark.unit
def test_register_failed_login_at_threshold_locks_account():
    user = _make_user(failed_login_attempts=0, locked_until=None)
    now = _utcnow()

    for _ in range(MAX_FAILED_LOGIN_ATTEMPTS):
        register_failed_login(user, now=now)

    assert user.failed_login_attempts == MAX_FAILED_LOGIN_ATTEMPTS
    assert user.locked_until is not None
    assert user.locked_until >= now + timedelta(minutes=LOCKOUT_DURATION_MINUTES - 1)


@pytest.mark.unit
def test_register_successful_login_clears_lock_state():
    user = _make_user(failed_login_attempts=4, locked_until=_utcnow())

    register_successful_login(user)

    assert user.failed_login_attempts == 0
    assert user.locked_until is None


# --- resolve_jwt_secret: A-3 security fix (2026-07-14) ---
#
# Settings.jwt_secret used to default to a fixed string committed in this
# AGPL-licensed repo's source. The architect proved live that anyone who read
# the source could forge a valid admin JWT with that string, with no call to
# /auth/login and no knowledge of any password. The fix: jwt_secret now
# defaults to None, and resolve_jwt_secret() generates+persists a random
# secret on first use instead of ever falling back to an in-code constant.
# These tests use an explicit tmp `secret_file` throughout so they never touch
# the real project's data/.jwt_secret.


@pytest.mark.unit
def test_resolve_jwt_secret_prefers_explicit_setting_over_file(tmp_path: Path):
    secret_file = tmp_path / ".jwt_secret"
    settings = Settings(_env_file=None, jwt_secret="explicit-configured-secret")

    resolved = resolve_jwt_secret(settings, secret_file=secret_file)

    assert resolved == "explicit-configured-secret"
    assert not secret_file.exists()


@pytest.mark.unit
def test_resolve_jwt_secret_generates_and_persists_when_unset(tmp_path: Path):
    secret_file = tmp_path / ".jwt_secret"
    settings = Settings(_env_file=None, jwt_secret=None)

    resolved = resolve_jwt_secret(settings, secret_file=secret_file)

    assert secret_file.exists()
    assert secret_file.read_text().strip() == resolved
    assert resolved != OLD_PUBLIC_PLACEHOLDER_SECRET
    assert len(resolved) >= 32


@pytest.mark.unit
def test_resolve_jwt_secret_is_stable_across_independent_settings_instances(tmp_path: Path):
    """Simulates surviving a restart: two independent Settings() constructions
    (as a fresh process would produce), neither with JWT_SECRET set, must
    resolve to the same persisted secret rather than regenerating one each time
    (which would invalidate every previously issued token on every restart).
    """
    secret_file = tmp_path / ".jwt_secret"
    settings_before_restart = Settings(_env_file=None, jwt_secret=None)
    settings_after_restart = Settings(_env_file=None, jwt_secret=None)

    first = resolve_jwt_secret(settings_before_restart, secret_file=secret_file)
    second = resolve_jwt_secret(settings_after_restart, secret_file=secret_file)

    assert first == second
    assert first != OLD_PUBLIC_PLACEHOLDER_SECRET
