"""blocked_ports

Revision ID: 630d1a6aee7f
Revises: 6beabfe366df
Create Date: 2026-07-23 16:48:15.120163

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '630d1a6aee7f'
down_revision: Union[str, Sequence[str], None] = '6beabfe366df'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('blocked_ports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=10), nullable=True),
    sa.Column('process_name', sa.String(length=255), nullable=True),
    sa.Column('blocked_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_blocked_ports_port',
        'blocked_ports',
        ['port'],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_blocked_ports_port', table_name='blocked_ports')
    op.drop_table('blocked_ports')
