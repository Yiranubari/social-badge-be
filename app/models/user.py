import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.auth_provider import AuthProvider
    from app.models.refresh_tokens import RefreshToken


class User(Base):
    """Organiser account created during signup or OAuth sign-in."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid7,
    )
    first_name: Mapped[str] = mapped_column(String(200))
    last_name: Mapped[str] = mapped_column(String(200))
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    profile_photo_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    auth_providers: Mapped[list["AuthProvider"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )

    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
    )
