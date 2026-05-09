import pytest
from httpx import AsyncClient
from sqlalchemy import select
from app.models.user import User
from app.api.deps import RedisClient, DBSession


@pytest.fixture
def verification_token() -> str:
    return "valid-test-token-123"


@pytest.mark.asyncio
async def test_verify_email_success(
    client: AsyncClient,
    session: DBSession,
    redis: RedisClient,
    verification_token: str,
) -> None:
    user = User(
        name="Verify Me",
        email="verify@example.com",
        hashed_password="...",
        is_email_verified=False,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    token_key = f"verification_token:{verification_token}"
    await redis.set(token_key, str(user.id))

    response = await client.post(
        f"/api/v1/auth/verify-email?token={verification_token}"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Email verified"
    assert data["data"]["next"] == "onboarding"

    await session.refresh(user)
    assert user.is_email_verified is True
    assert await redis.get(token_key) is None


@pytest.mark.asyncio
async def test_verify_email_expired_or_invalid_token(
    client: AsyncClient,
    verification_token: str,
) -> None:
    response = await client.post(
        f"/api/v1/auth/verify-email?token={verification_token}"
    )

    assert response.status_code == 401
    assert (
        response.json()["message"]
        == "Token has expired. Please request a new verification email"
    )


@pytest.mark.asyncio
async def test_verify_email_already_verified(
    client: AsyncClient,
    session: DBSession,
    redis: RedisClient,
    verification_token: str,
) -> None:
    user = User(
        name="Already Done",
        email="done@example.com",
        hashed_password="...",
        is_email_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    await redis.set(f"verification_token:{verification_token}", str(user.id))

    response = await client.post(
        f"/api/v1/auth/verify-email?token={verification_token}"
    )

    assert response.status_code == 400
    assert response.json()["message"] == "User already verified"
