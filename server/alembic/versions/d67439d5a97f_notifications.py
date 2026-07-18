"""A-13: notifications table

Revision ID: d67439d5a97f
Revises: ba7f4afe1312
Create Date: 2026-07-14 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd67439d5a97f'
down_revision: Union[str, Sequence[str], None] = 'ba7f4afe1312'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('notifications',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('topic', sa.String(length=255), nullable=False),
    sa.Column('payload', sa.JSON(), nullable=True),
    sa.Column('critical', sa.Boolean(), nullable=False),
    sa.Column('channels', sa.JSON(), nullable=True),
    sa.Column('suppressed_quiet_hours', sa.Boolean(), nullable=False),
    sa.Column('email_sent', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('(CURRENT_TIMESTAMP)'), nullable=False),
    sa.Column('read_at', sa.DateTime(), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.Column('escalated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('notifications')
