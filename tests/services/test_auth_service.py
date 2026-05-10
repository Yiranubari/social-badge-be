from unittest.mock import AsyncMock, patch

import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    EmailConflictError,
    InvalidPasswordResetTokenError,
)
from app.core.security import hash_password, verify_password
from app.core.token import (
    generate_token,
    get_password_reset_user_id,
    store_password_reset_token,
)
from app.models.auth_provider import AuthProvider
from app.models.user import User
from app.schemas.auth import ResetPasswordRequest, SignupRequest
from app.services.auth_service import reset_password, signup


def _make_payload(email: str = "jane@example.com") -> SignupRequest:
    return SignupRequest(
        name="Jane Doe",
        email=email,
        password="StrongPassword1!",  # noqa: S106
    )


def _make_reset_payload(token: str) -> ResetPasswordRequest:
    return ResetPasswordRequest(
        token=token,
        new_password="NewStrongPassword123!",  # noqa: S106
        confirm_password="NewStrongPassword123!",  # noqa: S106
    )


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_creates_user(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("create@example.com")
    await signup(db_session, fake_redis, payload)

    result = await db_session.execute(
        select(User).where(User.email == "create@example.com")
    )
    user = result.scalars().first()
    assert user is not None
    assert user.name == "Jane Doe"


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_hashes_password(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("hash@example.com")
    await signup(db_session, fake_redis, payload)

    result = await db_session.execute(
        select(User).where(User.email == "hash@example.com")
    )
    user = result.scalars().first()
    assert user is not None
    assert user.password_hash is not None
    assert verify_password(payload.password, user.password_hash) is True


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_creates_email_auth_provider(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("provider@example.com")
    await signup(db_session, fake_redis, payload)

    result = await db_session.execute(
        select(User).where(User.email == "provider@example.com")
    )
    user = result.scalars().first()
    assert user is not None

    provider_result = await db_session.execute(
        select(AuthProvider).where(AuthProvider.user_id == user.id)
    )
    provider = provider_result.scalars().first()
    assert provider is not None
    assert provider.provider == "email"


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_stores_verification_token(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("token@example.com")
    await signup(db_session, fake_redis, payload)

    keys = await fake_redis.keys("verify:*")
    assert len(keys) == 1


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_sends_verification_email(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("email@example.com")
    await signup(db_session, fake_redis, payload)

    mock_email.assert_called_once()
    assert mock_email.call_args[0][0] == "email@example.com"


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_rejects_duplicate_email(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_payload("duplicate@example.com")
    await signup(db_session, fake_redis, payload)

    duplicate = _make_payload("duplicate@example.com")
    with pytest.raises(EmailConflictError):
        await signup(db_session, fake_redis, duplicate)


async def test_reset_password_updates_user_password(
    db_session: AsyncSession, fake_redis: FakeAsyncRedis
) -> None:
    user = User(
        name="Reset User",
        email="reset@example.com",
        password_hash=hash_password("OldStrongPassword123!"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    raw_token, token_hash = generate_token()
    await store_password_reset_token(fake_redis, token_hash, str(user.id))

    await reset_password(db_session, fake_redis, _make_reset_payload(raw_token))

    result = await db_session.execute(select(User).where(User.id == user.id))
    updated_user = result.scalars().first()

    assert updated_user is not None
    assert updated_user.password_hash is not None
    assert verify_password("NewStrongPassword123!", updated_user.password_hash) is True
    assert verify_password("OldStrongPassword123!", updated_user.password_hash) is False


async def test_reset_password_consumes_reset_token(
    db_session: AsyncSession, fake_redis: FakeAsyncRedis
) -> None:
    user = User(
        name="Token User",
        email="token-reset@example.com",
        password_hash=hash_password("OldStrongPassword123!"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    raw_token, token_hash = generate_token()
    await store_password_reset_token(fake_redis, token_hash, str(user.id))

    await reset_password(
        db_session,
        fake_redis,
        _make_reset_payload(raw_token),
    )

    remaining_user_id = await get_password_reset_user_id(fake_redis, token_hash)

    assert remaining_user_id is None


async def test_reset_password_rejects_invalid_token(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    payload = _make_reset_payload("missing-token")

    with pytest.raises(InvalidPasswordResetTokenError):
        await reset_password(db_session, fake_redis, payload)


async def test_reset_password_rejects_token_for_missing_user(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    raw_token, token_hash = generate_token()
    missing_user_id = "550e8400-e29b-41d4-a716-446655440000"

    await store_password_reset_token(fake_redis, token_hash, missing_user_id)

    with pytest.raises(InvalidPasswordResetTokenError):
        await reset_password(
            db_session,
            fake_redis,
            _make_reset_payload(raw_token),
        )


async def test_reset_password_rejects_malformed_user_id(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    raw_token, token_hash = generate_token()
    await store_password_reset_token(fake_redis, token_hash, "not-a-uuid")

    with pytest.raises(InvalidPasswordResetTokenError):
        await reset_password(
            db_session,
            fake_redis,
            _make_reset_payload(raw_token),
        )
