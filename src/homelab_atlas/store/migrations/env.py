"""Alembic environment: programmatic use only (connection passed via config.attributes)."""

from alembic import context

from homelab_atlas.store.tables import Base

connection = context.config.attributes.get("connection")
if connection is None:
    raise RuntimeError("run migrations via homelab_atlas.store.db.migrate()")

context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    render_as_batch=True,  # SQLite ALTER TABLE support
    compare_type=True,
)
with context.begin_transaction():
    context.run_migrations()
