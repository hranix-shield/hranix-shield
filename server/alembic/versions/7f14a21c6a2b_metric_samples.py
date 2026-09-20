"""A-26: metric_samples table

Revision ID: 7f14a21c6a2b
Revises: d67439d5a97f
Create Date: 2026-07-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f14a21c6a2b'
down_revision: Union[str, Sequence[str], None] = 'd67439d5a97f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('metric_samples',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('console_id', sa.String(length=50), nullable=False),
    sa.Column('metric', sa.String(length=100), nullable=False),
    sa.Column('value', sa.Float(), nullable=False),
    sa.Column('sampled_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_metric_samples_console_metric_sampled_at',
        'metric_samples',
        ['console_id', 'metric', 'sampled_at'],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_metric_samples_console_metric_sampled_at', table_name='metric_samples')
    op.drop_table('metric_samples')
