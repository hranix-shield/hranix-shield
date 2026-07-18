from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import User
from app.services.auth import hash_password


async def create_user(
    session_maker: async_sessionmaker[AsyncSession],
    *,
    username: str,
    password: str,
    role: str = "viewer",
    is_active: bool = True,
) -> User:
    async with session_maker() as session:
        user = User(
            username=username,
            hashed_password=hash_password(password),
            role=role,
            is_active=is_active,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user
