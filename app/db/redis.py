from collections.abc import AsyncGenerator

from redis.asyncio import ConnectionPool, Redis

from app.core.config import settings

redis_pool = ConnectionPool.from_url(
    str(settings.REDIS_URL),
    decode_responses=True,
)


async def get_redis_client() -> AsyncGenerator[Redis]:
    client = Redis(connection_pool=redis_pool)
    try:
        yield client
    finally:
        await client.aclose()
