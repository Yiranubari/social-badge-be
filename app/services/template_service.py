import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PlatformTemplateNotFoundError
from app.models import OrganiserTemplate, PlatformTemplate

logger = logging.getLogger(__name__)


async def create_template_instance(
    session: AsyncSession,
    organizer_id: UUID,
    platform_template_id: UUID,
) -> OrganiserTemplate:
    """Create a new organiser template instance from a platform template.

    The platform template itself is read-only and never modified.
    Title and canvas_data are copied from the platform template so the
    new instance has sensible defaults.
    """
    result = await session.execute(
        select(PlatformTemplate).where(PlatformTemplate.id == platform_template_id)
    )
    platform_template = result.scalars().first()
    if platform_template is None:
        raise PlatformTemplateNotFoundError

    instance = OrganiserTemplate(
        organizer_id=organizer_id,
        platform_template_id=platform_template_id,
        title=platform_template.title,
        canvas_data=platform_template.canvas_data or {},
    )
    session.add(instance)
    await session.flush()
    await session.commit()
    await session.refresh(instance)

    logger.info(
        "Created template instance %s for organiser %s",
        instance.id,
        organizer_id,
    )
    return instance