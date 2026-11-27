"""Portal: shortcut categories, shortcuts and settings (ADR-049)

Additive only: three new tables, nothing existing is touched. No shortcuts are created here:
an installation's own bookmarks come from its private `config/portal-seed.yaml`, imported
once at startup (web/portal.py), so nobody's links live in this public repository. The portal
starts private (nothing shown before login), exactly like atlas before this revision.

Revision ID: 0009
Revises: 0008
Create Date: 2026-11-27
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "portal_categories",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
    )
    op.create_table(
        "portal_links",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "category_id", sa.Integer(), sa.ForeignKey("portal_categories.id"), nullable=False
        ),
        sa.Column("name", sa.String(80), nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("description", sa.String(160), nullable=False, server_default=""),
        sa.Column("icon", sa.String(64), nullable=False, server_default=""),
        sa.Column("favorite", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("public", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("position", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", UTCDateTime(), nullable=False),
        sa.Column("updated_at", UTCDateTime(), nullable=False),
    )
    op.create_index("ix_portal_links_category_id", "portal_links", ["category_id"])
    settings = op.create_table(
        "portal_settings",
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.String(256), nullable=False),
    )

    op.bulk_insert(settings, [{"key": "public", "value": "0"}])


def downgrade() -> None:
    op.drop_table("portal_settings")
    op.drop_index("ix_portal_links_category_id", "portal_links")
    op.drop_table("portal_links")
    op.drop_table("portal_categories")
