"""add blocked_ips table (A-52)

Revision ID: 151b67ce5acb
Revises: ba4ee09c00c4
Create Date: 2026-08-17 21:42:57.399073

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '151b67ce5acb'
down_revision: Union[str, Sequence[str], None] = 'ba4ee09c00c4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    A-52: only `blocked_ips` is this migration's actual work — autogenerate
    also proposed dropping `ix_blocked_ports_port`/adding an unnamed unique
    constraint on `blocked_ports.port` instead, a pre-existing SQLAlchemy-
    vs-live-schema representational difference this task never touched
    (`BlockedPort` itself is unmodified) — deliberately excluded here, not
    silently carried along in an unrelated migration."""
    op.create_table('blocked_ips',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=False),
    sa.Column('country', sa.String(length=2), nullable=True),
    sa.Column('process_name', sa.String(length=255), nullable=True),
    sa.Column('reason', sa.String(length=255), nullable=True),
    sa.Column('blocked_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('ip')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('blocked_ips')
