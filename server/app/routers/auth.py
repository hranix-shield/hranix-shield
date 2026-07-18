from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.db.session import get_session
from app.dependencies import get_current_user
from app.services.auth import (
    create_access_token,
    is_account_locked,
    register_failed_login,
    register_successful_login,
    verify_password,
)
from app.services.event_bus import EventBus, Topic, get_event_bus

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserOut(BaseModel):
    model_config = {"from_attributes": True}

    id: int
    username: str
    role: str
    is_active: bool


@router.post("/login", response_model=TokenResponse)
async def login(
    credentials: LoginRequest,
    session: AsyncSession = Depends(get_session),
    bus: EventBus = Depends(get_event_bus),
) -> TokenResponse:
    user = await session.scalar(select(User).where(User.username == credentials.username))
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_credentials"},
        )

    if is_account_locked(user):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "account_locked"},
        )

    if not verify_password(credentials.password, user.hashed_password):
        register_failed_login(user)
        # register_failed_login only ever sets locked_until when it was None
        # before this call (is_account_locked() above already short-circuits
        # any already-locked account) — so this flags exactly the attempt
        # that *causes* the lock, not every failed attempt nor later ones.
        just_locked = user.locked_until is not None
        await session.commit()
        if just_locked:
            await bus.publish(
                Topic.SECURITY_ALERT,
                {"reason": "account_locked", "username": user.username},
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "invalid_credentials"},
        )

    register_successful_login(user)
    await session.commit()

    token = create_access_token(username=user.username, role=user.role)
    return TokenResponse(access_token=token)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(user: User = Depends(get_current_user)) -> TokenResponse:
    token = create_access_token(username=user.username, role=user.role)
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
