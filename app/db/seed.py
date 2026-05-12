"""Seed script for reference data.

Run with: uv run python -m app.db.seed
"""

import asyncio
import logging

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models import PlatformTemplate
logger = logging.getLogger(__name__)


PLATFORM_TEMPLATES_SEED = [
    {
        "title": "Creative",
        "canvas_data": {"layout": "creative-v1"},
        "thumbnail_url": None,
    },
    {
        "title": "Professional",
        "canvas_data": {"layout": "professional-v1"},
        "thumbnail_url": None,
    },
    {
        "title": "Minimal",
        "canvas_data": {"layout": "minimal-v1"},
        "thumbnail_url": None,
    },
    {
        "title": "Bold",
        "canvas_data": {"layout": "bold-v1"},
        "thumbnail_url": None,
    },
]


async def seed_platform_templates() -> None:
    """Insert the four platform templates if they don't already exist."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(PlatformTemplate))
        existing = result.scalars().all()
        if existing:
            logger.info("Platform templates already seeded (%d found).", len(existing))
            return

        for data in PLATFORM_TEMPLATES_SEED:
            session.add(PlatformTemplate(**data))
            await session.flush()

        await session.commit()
        logger.info("Seeded %d platform templates.", len(PLATFORM_TEMPLATES_SEED))


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    await seed_platform_templates()


if __name__ == "__main__":
    asyncio.run(main())