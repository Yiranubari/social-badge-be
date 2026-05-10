"""add_provider_user_id_to_auth_providers

Revision ID: a9f1c5d2e7b4
Revises: 236bc1f3b79f
Create Date: 2026-05-09 12:45:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a9f1c5d2e7b4"
down_revision: str | None = "236bc1f3b79f"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "auth_providers",
        sa.Column("provider_user_id", sa.String(length=255), nullable=True),
    )
    op.create_unique_constraint(
        "uq_provider_provider_user_id",
        "auth_providers",
        ["provider", "provider_user_id"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_provider_provider_user_id",
        "auth_providers",
        type_="unique",
    )
    op.drop_column("auth_providers", "provider_user_id")
