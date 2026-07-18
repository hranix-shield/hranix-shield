import pytest
from fastapi import HTTPException

from app.db.models import User
from app.dependencies import _extract_bearer_token, require_role


def _make_user(role: str) -> User:
    return User(
        id=1,
        username="alice",
        hashed_password="unused",
        role=role,
        is_active=True,
        failed_login_attempts=0,
        locked_until=None,
    )


@pytest.mark.unit
def test_extract_bearer_token_missing_header():
    with pytest.raises(HTTPException) as exc_info:
        _extract_bearer_token(None)

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {"error": "not_authenticated"}


@pytest.mark.unit
def test_extract_bearer_token_wrong_scheme():
    with pytest.raises(HTTPException) as exc_info:
        _extract_bearer_token("Basic sometoken")

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == {"error": "not_authenticated"}


@pytest.mark.unit
def test_extract_bearer_token_valid():
    assert _extract_bearer_token("Bearer abc123") == "abc123"


@pytest.mark.unit
async def test_require_role_admin_allows_admin():
    check = require_role("admin")

    result = await check(user=_make_user("admin"))

    assert result.role == "admin"


@pytest.mark.unit
async def test_require_role_admin_rejects_viewer():
    check = require_role("admin")

    with pytest.raises(HTTPException) as exc_info:
        await check(user=_make_user("viewer"))

    assert exc_info.value.status_code == 403
    assert exc_info.value.detail == {"error": "insufficient_role"}


@pytest.mark.unit
async def test_require_role_viewer_allows_admin_too():
    check = require_role("viewer")

    result = await check(user=_make_user("admin"))

    assert result.role == "admin"
