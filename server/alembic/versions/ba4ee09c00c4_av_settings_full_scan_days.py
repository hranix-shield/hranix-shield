"""av_settings_full_scan_days

Revision ID: ba4ee09c00c4
Revises: 9a35fb212730
Create Date: 2026-08-02 23:47:10.743533

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ba4ee09c00c4'
down_revision: Union[str, Sequence[str], None] = '9a35fb212730'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Note: autogenerate also proposed the same unrelated blocked_ports
    # index/unique-constraint cosmetic diff test_a17/9a35fb212730 already
    # excluded — not a real model change, deliberately left out here too.
    #
    # server_default='[0, 1, 2, 3, 4, 5, 6]' (all 7 days) on a NOT NULL
    # column added to an already-populated table: any row that already
    # existed (e.g. an operator who already configured a daily schedule
    # before this column existed) must keep firing every day, not silently
    # stop — see AvSettings.full_scan_days's own docstring.
    op.add_column(
        'av_settings',
        sa.Column('full_scan_days', sa.JSON(), nullable=False, server_default='[0, 1, 2, 3, 4, 5, 6]'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('av_settings', 'full_scan_days')
