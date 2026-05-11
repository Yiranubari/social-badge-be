import uuid
from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship
from uuid_utils import uuid7

from app.models.base import Base

if TYPE_CHECKING:
    from app.modules.templates.models.organiser_templates_model import OrganiserTemplate


class TemplateHashtag(Base):
    __tablename__ = "template_hashtags"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid7, index=True, nullable=False
    )
    template_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organiser_templates.id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    hashtag: Mapped[str] = mapped_column(String(255), index=True, nullable=False)

    # Relationship back to the OrganiserTemplate
    organiser_template: Mapped["OrganiserTemplate"] = relationship(
        "OrganiserTemplate", back_populates="hashtags"
    )
