import pytest
from httpx import AsyncClient

from app.api.deps import DBSession, RedisClient
from app.models.user import User


@pytest.fixture
def verification_token() -> str:
    return "valid-test-token-123"


@pytest.mark.asyncio
async def test_verify_email_success(
    client: AsyncClient,
    db_session: DBSession,
    fake_redis: RedisClient,
    verification_token: str,
) -> None:
    user = User(
        name="Verify Me",
        email="verify_success@example.com",
        password_hash="...",  # noqa: S106
        is_email_verified=False,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token_key = f"verification_token:{verification_token}"
    await fake_redis.set(token_key, str(user.id))

    response = await client.post(
        f"/api/v1/auth/verify-email?token={verification_token}"
    )

    assert response.status_code == 200
    assert response.json()["message"] == "Email verified"
    await db_session.refresh(user)
    assert user.is_email_verified is True
    assert await fake_redis.get(token_key) is None


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
    db_session: DBSession,
    fake_redis: RedisClient,
    verification_token: str,
) -> None:
    user = User(
        name="Already Done",
        email="already_verified@example.com",
        password_hash="...",  # noqa: S106
        is_email_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    token_key = f"verification_token:{verification_token}"
    await fake_redis.set(token_key, str(user.id))

    response = await client.post(
        f"/api/v1/auth/verify-email?token={verification_token}"
    )

    assert response.status_code == 400
    assert "already verified" in response.json()["message"].lower()
