"""entity correlation (same_as)

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-18
"""

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("entities") as batch:
        batch.add_column(sa.Column("same_as", sa.String(256), nullable=True))
        batch.create_index("ix_entities_same_as", ["same_as"])


def downgrade() -> None:
    with op.batch_alter_table("entities") as batch:
        batch.drop_index("ix_entities_same_as")
        batch.drop_column("same_as")
