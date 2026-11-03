"""Taskora integration: incident ticket links (outbox) and sync state (ADR-042)

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-03
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "taskora_links",
        sa.Column("incident_id", sa.Integer(), sa.ForeignKey("incidents.id"), primary_key=True),
        sa.Column("revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("sent_revision", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("digest", sa.String(64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("next_attempt_at", UTCDateTime(), nullable=True),
        sa.Column("error_kind", sa.String(16), nullable=True),
        sa.Column("last_error", sa.String(256), nullable=True),
        sa.Column("delivered_at", UTCDateTime(), nullable=True),
        sa.Column("persisting", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ack_source", sa.String(16), nullable=True),
        sa.Column("ticket_id", sa.Integer(), nullable=True),
        sa.Column("ticket_number", sa.String(32), nullable=True),
        sa.Column("ticket_path", sa.String(32), nullable=True),
        sa.Column("ticket_status", sa.String(64), nullable=True),
        sa.Column("ticket_category", sa.String(16), nullable=True),
        sa.Column("ticket_priority", sa.String(64), nullable=True),
        sa.Column("ticket_assignee", sa.String(128), nullable=True),
        sa.Column("synced_at", UTCDateTime(), nullable=True),
        sa.Column("created_at", UTCDateTime(), nullable=False),
    )
    op.create_index("ix_taskora_links_sent_revision", "taskora_links", ["sent_revision"])
    op.create_table(
        "taskora_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("feed_cursor", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_ok_at", UTCDateTime(), nullable=True),
        sa.Column("last_feed_at", UTCDateTime(), nullable=True),
        sa.Column("last_error", sa.String(256), nullable=True),
        sa.Column("inventory_at", UTCDateTime(), nullable=True),
        sa.Column("inventory_mode", sa.String(16), nullable=True),
        sa.Column("inventory_result", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("taskora_state")
    op.drop_index("ix_taskora_links_sent_revision", "taskora_links")
    op.drop_table("taskora_links")
