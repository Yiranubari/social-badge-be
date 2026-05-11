from app.models.base import Base
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String, Text, func, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

if TYPE_CHECKING:
    from app.modules.templates.models.organiser_templates_model import OrganiserTemplate

class Badge(Base):
    __tablename__ = "badges"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7, index=True, nullable=False)
    template_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("organiser_templates.id", ondelete="CASCADE"), index=True, nullable=False)
    participant_name: Mapped[str] = mapped_column(String(255), nullable=False)
    profile_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    badge_image_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), onupdate=func.now(), nullable=True)


    # Relationship back to the OrganiserTemplate
    organiser_template: Mapped["OrganiserTemplate"] = relationship("OrganiserTemplate", back_populates="badges")