"""initial schema: scans, runs, entities, blobs, snapshots, facets, events

Revision ID: 0001
Revises:
Create Date: 2026-10-18
"""

import sqlalchemy as sa
from alembic import op

from homelab_atlas.store.tables import UTCDateTime

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("started_at", UTCDateTime(), nullable=False),
        sa.Column("finished_at", UTCDateTime(), nullable=True),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("label", sa.String(64), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
    )
    op.create_table(
        "blobs",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("body", sa.JSON(), nullable=False),
    )
    op.create_table(
        "entities",
        sa.Column("key", sa.String(256), primary_key=True),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(256), nullable=False),
        sa.Column("first_seen", UTCDateTime(), nullable=False),
        sa.Column("last_seen", UTCDateTime(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=True),
    )
    op.create_table(
        "collector_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("target", sa.String(128), nullable=False),
        sa.Column("collector", sa.String(32), nullable=False),
        sa.Column("entity_key", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("errors", sa.JSON(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
    )
    op.create_index("ix_collector_runs_scan_id", "collector_runs", ["scan_id"])
    op.create_index(
        "ix_collector_runs_target", "collector_runs", ["target", "collector", "scan_id"]
    )
    op.create_table(
        "snapshots",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("entity_key", sa.String(256), sa.ForeignKey("entities.key"), nullable=False),
        sa.Column("collector", sa.String(32), nullable=False),
        sa.Column("sha256", sa.String(64), sa.ForeignKey("blobs.sha256"), nullable=False),
        sa.UniqueConstraint("scan_id", "entity_key", "collector"),
    )
    op.create_index("ix_snapshots_entity", "snapshots", ["entity_key", "collector", "scan_id"])
    op.create_table(
        "facets",
        sa.Column("entity_key", sa.String(256), sa.ForeignKey("entities.key"), primary_key=True),
        sa.Column("collector", sa.String(32), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("data", sa.JSON(), nullable=False),
    )
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("scan_id", sa.Integer(), sa.ForeignKey("scans.id"), nullable=False),
        sa.Column("entity_key", sa.String(256), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("path", sa.String(512), nullable=False),
        sa.Column("old", sa.JSON(), nullable=True),
        sa.Column("new", sa.JSON(), nullable=True),
        sa.Column("summary", sa.String(512), nullable=False),
        sa.Column("created_at", UTCDateTime(), nullable=False),
    )
    op.create_index("ix_events_scan_id", "events", ["scan_id"])
    op.create_index("ix_events_entity_key", "events", ["entity_key"])


def downgrade() -> None:
    for table in ("events", "facets", "snapshots", "collector_runs", "entities", "blobs", "scans"):
        op.drop_table(table)
