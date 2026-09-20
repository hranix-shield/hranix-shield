"""scan_history

Revision ID: 6beabfe366df
Revises: 7f14a21c6a2b
Create Date: 2026-07-19 12:22:41.418374

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6beabfe366df'
down_revision: Union[str, Sequence[str], None] = '7f14a21c6a2b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('scan_history',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('scan_type', sa.String(length=20), nullable=False),
    sa.Column('path', sa.String(length=1024), nullable=True),
    sa.Column('scanned_count', sa.Integer(), nullable=False),
    sa.Column('infected_count', sa.Integer(), nullable=False),
    sa.Column('started_at', sa.DateTime(), nullable=False),
    sa.Column('finished_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_scan_history_finished_at',
        'scan_history',
        ['finished_at'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scan_history_finished_at', table_name='scan_history')
    op.drop_table('scan_history')
