from unittest.mock import AsyncMock, patch

import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import (
    AccountLockedError,
    EmailConflictError,
    EmailDeliveryError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
)
from app.core.security import hash_password, verify_password
from app.models.auth_provider import AuthProvider
from app.models.refresh_tokens import RefreshToken
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, LoginRequest, SignupRequest
from app.services.auth_service import (
    check_lockout,
    increment_failed_attempts,
    request_password_reset,
    reset_attempts,
    signin,
    signup,
)


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


# ---------------------------------------------------------------------------
# signin helpers
# ---------------------------------------------------------------------------


async def _create_verified_user(
    session: AsyncSession,
    email: str = "signin@example.com",
    password: str = "StrongPassword1!",  # noqa: S107
) -> User:
    user = User(
        name="Signin User",
        email=email,
        password_hash=hash_password(password),
        is_email_verified=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _create_unverified_user(
    session: AsyncSession,
    email: str = "unverified@example.com",
    password: str = "StrongPassword1!",  # noqa: S107
) -> User:
    user = User(
        name="Unverified User",
        email=email,
        password_hash=hash_password(password),
        is_email_verified=False,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


def _login(email: str, password: str = "StrongPassword1!") -> LoginRequest:  # noqa: S107
    return LoginRequest(email=email, password=password)


# ---------------------------------------------------------------------------
# signin tests
# ---------------------------------------------------------------------------


async def test_signin_returns_user_and_tokens(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "ok@example.com")

    user, access_token, refresh_token = await signin(
        db_session, fake_redis, _login("ok@example.com")
    )

    assert user.email == "ok@example.com"
    assert access_token
    assert refresh_token


async def test_signin_stores_hashed_refresh_token_in_db(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "store@example.com")

    _, _, raw_refresh = await signin(
        db_session, fake_redis, _login("store@example.com")
    )

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.token_hash != raw_refresh)
        if False
        else select(RefreshToken)
        .join(User, RefreshToken.user_id == User.id)
        .where(User.email == "store@example.com")
    )
    tokens = result.scalars().all()
    assert len(tokens) == 1
    # Raw token must NOT be stored — only the hash
    assert tokens[0].token_hash != raw_refresh


async def test_signin_resets_failed_attempts_on_success(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "reset@example.com")
    key = "failed_login:reset@example.com"
    await fake_redis.set(key, "3")

    await signin(db_session, fake_redis, _login("reset@example.com"))

    assert await fake_redis.get(key) is None


async def test_signin_wrong_email_raises_invalid_credentials(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    with pytest.raises(InvalidCredentialsError):
        await signin(db_session, fake_redis, _login("ghost@example.com"))


async def test_signin_wrong_password_raises_invalid_credentials(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "wrongpw@example.com")

    with pytest.raises(InvalidCredentialsError):
        await signin(
            db_session,
            fake_redis,
            _login("wrongpw@example.com", password="WrongPassword1!"),  # noqa: S106
        )


async def test_signin_unverified_email_raises_email_not_verified(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_unverified_user(db_session, "noverify@example.com")

    with pytest.raises(EmailNotVerifiedError):
        await signin(db_session, fake_redis, _login("noverify@example.com"))


@patch("app.services.auth_service.send_account_lock_email", new_callable=AsyncMock)
async def test_signin_locks_after_max_failed_attempts(
    mock_lock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "lockme@example.com")
    bad = _login("lockme@example.com", password="WrongPassword1!")  # noqa: S106

    for _ in range(settings.MAX_LOGIN_ATTEMPTS - 1):
        with pytest.raises(InvalidCredentialsError):
            await signin(db_session, fake_redis, bad)

    with pytest.raises(AccountLockedError):
        await signin(db_session, fake_redis, bad)


@patch("app.services.auth_service.send_account_lock_email", new_callable=AsyncMock)
async def test_signin_sends_lock_email_on_lockout(
    mock_lock_email: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await _create_verified_user(db_session, "lockmail@example.com")
    bad = _login("lockmail@example.com", password="WrongPassword1!")  # noqa: S106

    for _ in range(settings.MAX_LOGIN_ATTEMPTS):
        with pytest.raises((InvalidCredentialsError, AccountLockedError)):
            await signin(db_session, fake_redis, bad)

    mock_lock_email.assert_called_once_with("lockmail@example.com")


# ---------------------------------------------------------------------------
# check_lockout / increment_failed_attempts / reset_attempts tests
# ---------------------------------------------------------------------------


async def test_check_lockout_passes_when_under_limit(
    fake_redis: FakeAsyncRedis,
) -> None:
    key = "failed_login:under@example.com"
    await fake_redis.set(key, str(settings.MAX_LOGIN_ATTEMPTS - 1))
    # Should not raise
    await check_lockout(fake_redis, "under@example.com")


async def test_check_lockout_raises_when_at_max(
    fake_redis: FakeAsyncRedis,
) -> None:
    key = "failed_login:locked@example.com"
    await fake_redis.set(key, str(settings.MAX_LOGIN_ATTEMPTS))

    with pytest.raises(AccountLockedError):
        await check_lockout(fake_redis, "locked@example.com")


async def test_check_lockout_passes_when_no_key(
    fake_redis: FakeAsyncRedis,
) -> None:
    # Should not raise for a fresh email
    await check_lockout(fake_redis, "fresh@example.com")


async def test_increment_failed_attempts_returns_count(
    fake_redis: FakeAsyncRedis,
) -> None:
    count = await increment_failed_attempts(fake_redis, "count@example.com")
    assert count == 1
    count = await increment_failed_attempts(fake_redis, "count@example.com")
    assert count == 2


async def test_increment_failed_attempts_sets_expiry_on_first(
    fake_redis: FakeAsyncRedis,
) -> None:
    await increment_failed_attempts(fake_redis, "expiry@example.com")
    ttl = await fake_redis.ttl("failed_login:expiry@example.com")
    assert ttl > 0


async def test_reset_attempts_clears_redis_key(
    fake_redis: FakeAsyncRedis,
) -> None:
    key = "failed_login:clear@example.com"
    await fake_redis.set(key, "4")

    await reset_attempts(fake_redis, "clear@example.com")

    assert await fake_redis.get(key) is None


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
