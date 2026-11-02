"""incidents: acknowledge, snooze, reminders (ADR-041)

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-02
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("incidents") as b:
        b.add_column(sa.Column("acknowledged_at", UTCDateTime(), nullable=True))
        b.add_column(sa.Column("acknowledged_by", sa.String(64), nullable=True))
        b.add_column(sa.Column("snoozed_until", UTCDateTime(), nullable=True))
        b.add_column(sa.Column("last_reminded_at", UTCDateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("incidents") as b:
        b.drop_column("last_reminded_at")
        b.drop_column("snoozed_until")
        b.drop_column("acknowledged_by")
        b.drop_column("acknowledged_at")
