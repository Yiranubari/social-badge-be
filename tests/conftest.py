import os
from collections.abc import AsyncIterator

import pytest
from fakeredis import FakeAsyncRedis
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

# Must be set before app imports: Settings() is constructed at import time
# and raises ValidationError if SECRET_KEY is missing.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-not-for-production")

from app.core.config import settings
from app.db.redis import get_redis_client
from app.db.session import get_session
from app.main import app  # noqa: E402
from app.models.base import Base


def create_db_engine() -> AsyncEngine:
    db_url = str(settings.DATABASE_URL)

    # Force the use of the 'test' database to avoid dropping main database tables!
    if not db_url.endswith("/test"):
        db_url = db_url.rsplit("/", 1)[0] + "/test"

    test_engine = create_async_engine(
        db_url,
        poolclass=NullPool,
    )
    return test_engine


@pytest.fixture(scope="session")
async def setup_db() -> AsyncIterator[None]:
    test_engine = create_db_engine()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await test_engine.dispose()


@pytest.fixture
async def db_session(setup_db: None) -> AsyncIterator[AsyncSession]:
    test_engine = create_db_engine()

    TestingSessionLocal = async_sessionmaker(
        test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with TestingSessionLocal() as session:
        yield session

    async with test_engine.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            await conn.execute(table.delete())

    await test_engine.dispose()


@pytest.fixture
def fake_redis() -> FakeAsyncRedis:
    return FakeAsyncRedis(decode_responses=True)


@pytest.fixture(autouse=True)
def reset_limiter() -> None:
    from app.core.rate_limit import limiter

    limiter.reset()


@pytest.fixture
async def client(
    db_session: AsyncSession, fake_redis: FakeAsyncRedis
) -> AsyncIterator[AsyncClient]:
    async def override_get_session() -> AsyncIterator[AsyncSession]:
        yield db_session

    async def override_get_redis() -> AsyncIterator[FakeAsyncRedis]:
        yield fake_redis

    app.dependency_overrides[get_session] = override_get_session
    app.dependency_overrides[get_redis_client] = override_get_redis

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()


@pytest.fixture
def valid_signup_payload() -> dict[str, str]:
    return {
        "first_name": "API Test",
        "last_name": "User",
        "email": "apitest@example.com",
        "password": "StrongPassword1!",  # noqa: S106
    }
