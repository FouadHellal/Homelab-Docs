"""taskora_state.last_tick_at: when atlas last checked for something to send (ADR-043)

Revision ID: 0008
Revises: 0007
Create Date: 2026-11-05
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("taskora_state") as b:
        b.add_column(sa.Column("last_tick_at", UTCDateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("taskora_state") as b:
        b.drop_column("last_tick_at")
