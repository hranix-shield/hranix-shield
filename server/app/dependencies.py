from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.db.session import get_session
from app.services.auth import TokenError, decode_access_token

_BEARER_SCHEME = "bearer"
_ROLE_LEVELS = {"viewer": 0, "admin": 1}


def _extract_bearer_token(authorization: str | None) -> str:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated"},
        )

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != _BEARER_SCHEME or not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "not_authenticated"},
        )

    return token


async def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    session: AsyncSession = Depends(get_session),
) -> User:
    token = _extract_bearer_token(authorization)

    try:
        payload = decode_access_token(token)
    except TokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token"},
        ) from exc

    username = payload.get("sub")
    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token"},
        )

    user = await session.scalar(select(User).where(User.username == username))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_token"},
        )

    return user


def require_role(role: str):
    required_level = _ROLE_LEVELS.get(role, 0)

    async def _check_role(user: Annotated[User, Depends(get_current_user)]) -> User:
        user_level = _ROLE_LEVELS.get(user.role, -1)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"error": "insufficient_role"},
            )
        return user

    return _check_role
