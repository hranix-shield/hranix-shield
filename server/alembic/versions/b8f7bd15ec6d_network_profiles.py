"""network_profiles

Revision ID: b8f7bd15ec6d
Revises: 630d1a6aee7f
Create Date: 2026-07-23 16:54:12.449156

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8f7bd15ec6d'
down_revision: Union[str, Sequence[str], None] = '630d1a6aee7f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('network_profiles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('network_key', sa.String(length=300), nullable=False),
    sa.Column('display_name', sa.String(length=300), nullable=False),
    sa.Column('id_kind', sa.String(length=20), nullable=False),
    sa.Column('category', sa.String(length=20), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(
        'ix_network_profiles_network_key',
        'network_profiles',
        ['network_key'],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_network_profiles_network_key', table_name='network_profiles')
    op.drop_table('network_profiles')
