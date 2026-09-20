"""av_settings

Revision ID: 9a35fb212730
Revises: b8f7bd15ec6d
Create Date: 2026-08-02 22:45:38.610326

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9a35fb212730'
down_revision: Union[str, Sequence[str], None] = 'b8f7bd15ec6d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Note: autogenerate also proposed dropping/recreating an unrelated
    # blocked_ports index as a unique constraint (a cosmetic SQLite
    # reporting difference from a prior migration, not a real model
    # change) — deliberately excluded here, out of scope for this task.
    op.create_table('av_settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('full_scan_schedule_enabled', sa.Boolean(), nullable=False),
    sa.Column('full_scan_hour', sa.Integer(), nullable=False),
    sa.Column('full_scan_minute', sa.Integer(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('av_settings')
