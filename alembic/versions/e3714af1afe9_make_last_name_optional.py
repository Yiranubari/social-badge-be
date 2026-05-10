"""make_last_name_optional

Revision ID: e3714af1afe9
Revises: 3f59271c2a41
Create Date: 2026-05-10 16:08:34.540553

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "e3714af1afe9"
down_revision: str | None = "3f59271c2a41"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "users", "last_name", existing_type=sa.String(length=200), nullable=True
    )


def downgrade() -> None:
    # Note: This might fail if there are existing NULL values
    op.alter_column(
        "users", "last_name", existing_type=sa.String(length=200), nullable=False
    )
