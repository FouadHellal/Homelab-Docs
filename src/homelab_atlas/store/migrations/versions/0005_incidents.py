"""incidents (ADR-040): deduplicated ongoing conditions and their notifications

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-02
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "incidents",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("key", sa.String(128), nullable=False),
        sa.Column("kind", sa.String(48), nullable=False),
        sa.Column("title", sa.String(256), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("entity_key", sa.String(256), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("opened_at", UTCDateTime(), nullable=False),
        sa.Column("last_seen_at", UTCDateTime(), nullable=False),
        sa.Column("resolved_at", UTCDateTime(), nullable=True),
        sa.Column("notified_open_at", UTCDateTime(), nullable=True),
        sa.Column("notified_resolved_at", UTCDateTime(), nullable=True),
    )
    op.create_index("ix_incidents_key", "incidents", ["key"])
    op.create_index("ix_incidents_resolved_at", "incidents", ["resolved_at"])


def downgrade() -> None:
    op.drop_index("ix_incidents_resolved_at", "incidents")
    op.drop_index("ix_incidents_key", "incidents")
    op.drop_table("incidents")
