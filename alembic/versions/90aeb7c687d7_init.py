"""init

Revision ID: 90aeb7c687d7
Revises:
Create Date: 2026-04-28 17:24:32.638374

"""

from collections.abc import Sequence

revision: str = "90aeb7c687d7"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
