"""entity parents and facet targets (multi-entity collectors)

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-18
"""

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("entities") as batch:
        batch.add_column(sa.Column("parent_key", sa.String(256), nullable=True))
        batch.create_index("ix_entities_parent_key", ["parent_key"])
    with op.batch_alter_table("facets") as batch:
        batch.add_column(sa.Column("target", sa.String(128), nullable=False, server_default=""))
        batch.create_index("ix_facets_target", ["target"])


def downgrade() -> None:
    with op.batch_alter_table("facets") as batch:
        batch.drop_index("ix_facets_target")
        batch.drop_column("target")
    with op.batch_alter_table("entities") as batch:
        batch.drop_index("ix_entities_parent_key")
        batch.drop_column("parent_key")
