import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.user import User
    from app.modules.templates.models.badges_model import Badge
    from app.modules.templates.models.platform_templates_model import PlatformTemplate
    from app.modules.templates.models.template_hashtags_model import TemplateHashtag


class OrganiserTemplate(Base):
    __tablename__ = "organiser_templates"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid7, index=True, nullable=False
    )
    organizer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    platform_template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("platform_templates.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    canvas_data: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    default_caption: Mapped[str | None] = mapped_column(String(255), nullable=True)
    destination_link: Mapped[str] = mapped_column(String(255), nullable=True)
    thumbnail_url: Mapped[str] = mapped_column(String(255), nullable=True)
    access_type: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    is_published: Mapped[bool] = mapped_column(Boolean, default=False)
    published_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    share_slug: Mapped[str | None] = mapped_column(
        String(255), unique=True, nullable=True
    )
    created_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), nullable=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship back to the User
    organiser: Mapped["User"] = relationship(
        "User", back_populates="organiser_templates"
    )

    # Relationship to PlatformTemplate
    platform_template: Mapped["PlatformTemplate"] = relationship(
        "PlatformTemplate",
        back_populates="organiser_templates",
    )

    # Relationships to child tables
    badges: Mapped[list["Badge"]] = relationship(
        "Badge",
        back_populates="organiser_template",
        cascade="all, delete-orphan",
    )

    hashtags: Mapped[list["TemplateHashtag"]] = relationship(
        "TemplateHashtag",
        back_populates="organiser_template",
        cascade="all, delete-orphan",
    )
