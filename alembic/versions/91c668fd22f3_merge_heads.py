"""merge_heads

Revision ID: 91c668fd22f3
Revises: a9f1c5d2e7b4, c92cb51c6be2
Create Date: 2026-05-10 15:15:55.421360

"""

from collections.abc import Sequence

revision: str = "91c668fd22f3"
down_revision: str | Sequence[str] | None = ("a9f1c5d2e7b4", "c92cb51c6be2")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
