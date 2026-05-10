import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User


class AuthProvider(Base):
    """Tracks which authentication providers are linked to a user account."""

    __tablename__ = "auth_providers"
    __table_args__ = (UniqueConstraint("provider", "user_id", name="uq_provider_user"),)

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    provider: Mapped[str] = mapped_column(String(50))
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
    )
    label: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )

    user: Mapped["User"] = relationship(back_populates="auth_providers")
