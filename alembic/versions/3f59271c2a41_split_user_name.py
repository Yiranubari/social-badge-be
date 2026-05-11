"""split_user_name

Revision ID: 3f59271c2a41
Revises: 91c668fd22f3
Create Date: 2026-05-10 15:18:05.331677

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "3f59271c2a41"
down_revision: str | None = "91c668fd22f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # 1. Add columns as nullable first to avoid issues with existing data
    op.add_column(
        "users", sa.Column("first_name", sa.String(length=200), nullable=True)
    )
    op.add_column("users", sa.Column("last_name", sa.String(length=200), nullable=True))

    # 2. Migrate data from 'name' to 'first_name' and 'last_name'
    connection = op.get_bind()
    users = connection.execute(sa.text("SELECT id, name FROM users")).fetchall()
    for user_id, name in users:
        parts = name.split(maxsplit=1)
        first_name = parts[0]
        last_name = parts[1] if len(parts) > 1 else ""
        connection.execute(
            sa.text(
                "UPDATE users SET first_name = :first_name, "
                "last_name = :last_name WHERE id = :id"
            ),
            {"first_name": first_name, "last_name": last_name, "id": user_id},
        )

    # 3. Make the new columns non-nullable
    op.alter_column("users", "first_name", nullable=False)
    op.alter_column("users", "last_name", nullable=False)

    # 4. Drop the old column
    op.drop_column("users", "name")


def downgrade() -> None:
    # 1. Add back the name column as nullable
    op.add_column("users", sa.Column("name", sa.String(length=200), nullable=True))

    # 2. Combine first_name and last_name back into name
    connection = op.get_bind()
    users = connection.execute(
        sa.text("SELECT id, first_name, last_name FROM users")
    ).fetchall()
    for user_id, first_name, last_name in users:
        name = f"{first_name} {last_name}".strip()
        connection.execute(
            sa.text("UPDATE users SET name = :name WHERE id = :id"),
            {"name": name, "id": user_id},
        )

    # 3. Make name non-nullable
    op.alter_column("users", "name", nullable=False)

    # 4. Drop the new columns
    op.drop_column("users", "last_name")
    op.drop_column("users", "first_name")