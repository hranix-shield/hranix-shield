import asyncio
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.asyncio import create_async_engine

from app.app_factory import create_app

SERVER_DIR = Path(__file__).resolve().parents[2]
ALEMBIC_INI = SERVER_DIR / "alembic.ini"

EXPECTED_TABLES = {"users", "events", "backup_jobs"}


def _alembic_config_for(db_path: Path) -> Config:
    alembic_cfg = Config(str(ALEMBIC_INI))
    alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite+aiosqlite:///{db_path}")
    return alembic_cfg


@pytest.mark.integration
def test_alembic_upgrade_creates_expected_tables(tmp_path):
    db_path = tmp_path / "test_assistant.db"

    command.upgrade(_alembic_config_for(db_path), "head")

    sync_engine = create_engine(f"sqlite:///{db_path}")
    try:
        tables = set(inspect(sync_engine).get_table_names())
    finally:
        sync_engine.dispose()

    assert EXPECTED_TABLES.issubset(tables)


@pytest.mark.integration
def test_app_starts_and_queries_migrated_tables(tmp_path):
    db_path = tmp_path / "test_assistant_app.db"
    command.upgrade(_alembic_config_for(db_path), "head")

    app = create_app()
    assert isinstance(app, FastAPI)

    async def _query_all_tables() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
        try:
            async with engine.connect() as conn:
                for table in EXPECTED_TABLES:
                    result = await conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                    assert result.scalar() == 0
        finally:
            await engine.dispose()

    asyncio.run(_query_all_tables())


@pytest.mark.integration
def test_alembic_downgrade_drops_tables(tmp_path):
    db_path = tmp_path / "test_assistant_downgrade.db"
    alembic_cfg = _alembic_config_for(db_path)

    command.upgrade(alembic_cfg, "head")
    command.downgrade(alembic_cfg, "base")

    sync_engine = create_engine(f"sqlite:///{db_path}")
    try:
        tables = set(inspect(sync_engine).get_table_names())
    finally:
        sync_engine.dispose()

    assert EXPECTED_TABLES.isdisjoint(tables)
