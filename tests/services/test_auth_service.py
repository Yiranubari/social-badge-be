from unittest.mock import AsyncMock, patch

import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EmailConflictError, EmailDeliveryError
from app.core.security import verify_password
from app.models.auth_provider import AuthProvider
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, SignupRequest
from app.services.auth_service import request_password_reset, signup


def _make_payload(email: str = "jane@example.com") -> SignupRequest:
    return SignupRequest(
        name="Jane Doe",
        email=email,
        password="StrongPassword1!",  # noqa: S106
    )


def _make_forgot_payload(email: str = "jane@example.com") -> ForgotPasswordRequest:
    return ForgotPasswordRequest(email=email)


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


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_request_password_reset_stores_token_for_existing_user(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    signup_payload = _make_payload("reset@example.com")
    with patch(
        "app.services.auth_service.send_verification_email", new_callable=AsyncMock
    ):
        await signup(db_session, fake_redis, signup_payload)

    forgot_payload = _make_forgot_payload("reset@example.com")
    await request_password_reset(db_session, fake_redis, forgot_payload)

    keys = await fake_redis.keys("pwd_reset:*")
    assert len(keys) == 1


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_request_password_reset_sends_email_to_existing_user(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    signup_payload = _make_payload("sendmail@example.com")
    with patch(
        "app.services.auth_service.send_verification_email", new_callable=AsyncMock
    ):
        await signup(db_session, fake_redis, signup_payload)

    forgot_payload = _make_forgot_payload("sendmail@example.com")
    await request_password_reset(db_session, fake_redis, forgot_payload)

    mock_email.assert_called_once()
    assert mock_email.call_args[0][0] == "sendmail@example.com"


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_request_password_reset_silent_for_unknown_email(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    forgot_payload = _make_forgot_payload("unknown@example.com")
    await request_password_reset(db_session, fake_redis, forgot_payload)

    keys = await fake_redis.keys("pwd_reset:*")
    assert len(keys) == 0
    mock_email.assert_not_called()


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_request_password_reset_swallows_email_failure(
    mock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    mock_email.side_effect = EmailDeliveryError("Failed to send")

    signup_payload = _make_payload("failreset@example.com")
    with patch(
        "app.services.auth_service.send_verification_email", new_callable=AsyncMock
    ):
        await signup(db_session, fake_redis, signup_payload)

    forgot_payload = _make_forgot_payload("failreset@example.com")
    # Should NOT raise — the service swallows EmailDeliveryError silently
    await request_password_reset(db_session, fake_redis, forgot_payload)
