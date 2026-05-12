import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

from app.models.base import Base

if TYPE_CHECKING:
    from app.modules.templates.models.organiser_templates_model import OrganiserTemplate


class PlatformTemplate(Base):
    __tablename__ = "platform_templates"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid7, index=True, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    canvas_data: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    thumbnail_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), nullable=True
    )

    # Relationship to OrganiserTemplate
    organiser_templates: Mapped[list["OrganiserTemplate"]] = relationship(
        "OrganiserTemplate",
        back_populates="platform_template",
        cascade="all, delete-orphan",
    )
