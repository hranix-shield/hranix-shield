from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import get_settings


def create_engine(database_url: str | None = None) -> AsyncEngine:
    url = database_url or get_settings().resolved_database_url
    return create_async_engine(url, future=True)


def create_session_maker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


engine: AsyncEngine = create_engine()
async_session_maker: async_sessionmaker[AsyncSession] = create_session_maker(engine)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
