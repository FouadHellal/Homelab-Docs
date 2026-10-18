"""web users, server-side sessions, annotations index

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-18
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(64), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(256), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("last_login", UTCDateTime(), nullable=True),
        sa.Column("failed_logins", sa.Integer(), nullable=False),
        sa.Column("locked_until", UTCDateTime(), nullable=True),
    )
    op.create_table(
        "web_sessions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("csrf", sa.String(64), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("last_seen", UTCDateTime(), nullable=False),
        sa.Column("expires_at", UTCDateTime(), nullable=False),
    )
    op.create_index("ix_web_sessions_user_id", "web_sessions", ["user_id"])
    op.create_table(
        "annotations",
        sa.Column("entity_key", sa.String(256), primary_key=True),
        sa.Column("owner", sa.String(128), nullable=True),
        sa.Column("purpose", sa.String(512), nullable=True),
        sa.Column("criticality", sa.String(16), nullable=True),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("links", sa.JSON(), nullable=False),
        sa.Column("notes", sa.String(8192), nullable=True),
        sa.Column("acknowledged", sa.Boolean(), nullable=False),
        sa.Column("source_file", sa.String(256), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("annotations")
    op.drop_index("ix_web_sessions_user_id", "web_sessions")
    op.drop_table("web_sessions")
    op.drop_table("users")
