from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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
    GoogleOAuthError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
)
from app.core.security import hash_password, verify_password
from app.core.token import (
    generate_token,
    get_password_reset_user_id,
    store_google_oauth_state,
    store_password_reset_token,
)
from app.models.auth_provider import AuthProvider
from app.models.refresh_tokens import RefreshToken
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    ResetPasswordRequest,
    SignupRequest,
)
from app.services.auth_service import (
    _exchange_google_code,
    _extract_google_id_token_subject,
    _fetch_google_userinfo,
    _validate_google_subject_consistency,
    authenticate_with_google,
    build_google_auth_url,
    check_lockout,
    increment_failed_attempts,
    request_password_reset,
    reset_attempts,
    reset_password,
    signin,
    signup,
)


def _make_payload(email: str = "jane@example.com") -> SignupRequest:
    return SignupRequest(
        first_name="Jane",
        last_name="Doe",
        email=email,
        password="StrongPassword1!",  # noqa: S106
    )


def _make_reset_payload(token: str) -> ResetPasswordRequest:
    return ResetPasswordRequest(
        token=token,
        new_password="NewStrongPassword123!",  # noqa: S106
        confirm_password="NewStrongPassword123!",  # noqa: S106
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
    assert user.first_name == "Jane"
    assert user.last_name == "Doe"


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


# ---------------------------------------------------------------------------
# signin helpers
# ---------------------------------------------------------------------------


async def _create_verified_user(
    session: AsyncSession,
    email: str = "signin@example.com",
    password: str = "StrongPassword1!",  # noqa: S107
) -> User:
    user = User(
        first_name="Signin",
        last_name="User",
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
        first_name="Unverified",
        last_name="User",
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
        select(RefreshToken)
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


async def test_build_google_auth_url_stores_state(fake_redis: FakeAsyncRedis) -> None:
    auth_url = await build_google_auth_url(fake_redis)

    assert "accounts.google.com" in auth_url
    state = auth_url.split("state=")[1].split("&")[0]
    stored_state = await fake_redis.get(f"oauth:google:state:{state}")
    assert stored_state == "1"


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_creates_new_user(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {
        "access_token": "token",
        "id_token": "header.eyJzdWIiOiAiZ29vZ2xlLXN1Yi1uZXctdXNlciJ9.signature",
    }
    mock_userinfo.return_value = {
        "sub": "google-sub-new-user",
        "email": "google@example.com",
        "name": "Google User",
        "picture": "https://example.com/photo.jpg",
    }

    user, is_new_user = await authenticate_with_google(
        db_session, fake_redis, "auth-code", "valid-state"
    )

    assert is_new_user is True
    assert user.email == "google@example.com"
    assert user.first_name == "Google"
    assert user.last_name == "User"
    assert user.is_email_verified is True
    assert user.profile_photo_url == "https://example.com/photo.jpg"

    provider_result = await db_session.execute(
        select(AuthProvider).where(AuthProvider.user_id == user.id)
    )
    provider = provider_result.scalars().first()
    assert provider is not None
    assert provider.provider == "google"
    assert provider.provider_user_id == "google-sub-new-user"


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_links_existing_user(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    existing_user = User(
        first_name="Existing",
        last_name="User",
        email="existing@example.com",
        is_email_verified=True,
    )
    db_session.add(existing_user)
    await db_session.commit()
    await db_session.refresh(existing_user)

    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {
        "access_token": "token",
        "id_token": (
            "header.eyJzdWIiOiAiZ29vZ2xlLXN1Yi1leGlzdGluZy11c2VyIn0.signature"
        ),
    }
    mock_userinfo.return_value = {
        "sub": "google-sub-existing-user",
        "email": "existing@example.com",
        "name": "Existing User",
        "picture": "https://example.com/google-photo.jpg",
    }

    user, is_new_user = await authenticate_with_google(
        db_session, fake_redis, "auth-code", "valid-state"
    )

    assert is_new_user is False
    assert user.id == existing_user.id
    assert user.is_email_verified is True
    assert user.profile_photo_url == "https://example.com/google-photo.jpg"

    provider_result = await db_session.execute(
        select(AuthProvider).where(
            AuthProvider.user_id == existing_user.id,
            AuthProvider.provider == "google",
        )
    )
    provider = provider_result.scalars().first()
    assert provider is not None
    assert provider.provider_user_id == "google-sub-existing-user"


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_rejects_unverified_password_account(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    existing_user = User(
        first_name="Hijacked",
        last_name="User",
        email="victim@example.com",
        password_hash="hashed-password",  # noqa: S106
        is_email_verified=False,
    )
    db_session.add(existing_user)
    await db_session.commit()

    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {
        "access_token": "token",
        "id_token": "header.eyJzdWIiOiAiZ29vZ2xlLXN1Yi12aWN0aW0ifQ.signature",
    }
    mock_userinfo.return_value = {
        "sub": "google-sub-victim",
        "email": "victim@example.com",
        "name": "Victim User",
        "picture": "https://example.com/victim.jpg",
    }

    with pytest.raises(
        GoogleOAuthError,
        match="An unverified password account already exists for this email",
    ) as exc_info:
        await authenticate_with_google(
            db_session, fake_redis, "auth-code", "valid-state"
        )

    assert exc_info.value.status_code == 409

    provider_result = await db_session.execute(
        select(AuthProvider).where(
            AuthProvider.user_id == existing_user.id,
            AuthProvider.provider == "google",
        )
    )
    provider = provider_result.scalars().first()
    assert provider is None


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_prefers_existing_google_subject_link(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    existing_user = User(
        first_name="Linked",
        last_name="User",
        email="linked@example.com",
        is_email_verified=True,
    )
    db_session.add(existing_user)
    await db_session.flush()
    db_session.add(
        AuthProvider(
            provider="google",
            provider_user_id="google-linked-subject",
            user_id=existing_user.id,
            label="Google",
        )
    )
    await db_session.commit()
    await db_session.refresh(existing_user)

    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {
        "access_token": "token",
        "id_token": ("header.eyJzdWIiOiAiZ29vZ2xlLWxpbmtlZC1zdWJqZWN0In0.signature"),
    }
    mock_userinfo.return_value = {
        "sub": "google-linked-subject",
        "email": "linked@example.com",
        "name": "Linked User",
        "picture": "https://example.com/linked.jpg",
    }

    user, is_new_user = await authenticate_with_google(
        db_session, fake_redis, "auth-code", "valid-state"
    )

    assert is_new_user is False
    assert user.id == existing_user.id


async def test_authenticate_with_google_rejects_invalid_state(
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    with pytest.raises(GoogleOAuthError, match="Invalid or expired Google OAuth state"):
        await authenticate_with_google(db_session, fake_redis, "auth-code", "missing")


@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_propagates_userinfo_errors(
    mock_exchange: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {"access_token": "token", "id_token": None}

    with patch(
        "app.services.auth_service._fetch_google_userinfo",
        new_callable=AsyncMock,
        side_effect=GoogleOAuthError("Google account email is not verified"),
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google account email is not verified"
        ):
            await authenticate_with_google(
                db_session, fake_redis, "auth-code", "valid-state"
            )


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_propagates_token_exchange_errors(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.side_effect = GoogleOAuthError(
        "Google token exchange failed", status_code=401
    )

    with pytest.raises(GoogleOAuthError, match="Google token exchange failed") as exc:
        await authenticate_with_google(
            db_session, fake_redis, "auth-code", "valid-state"
        )

    assert exc.value.status_code == 401
    mock_userinfo.assert_not_called()


@patch("app.services.auth_service._fetch_google_userinfo", new_callable=AsyncMock)
@patch("app.services.auth_service._exchange_google_code", new_callable=AsyncMock)
async def test_authenticate_with_google_rejects_mismatched_id_token_subject(
    mock_exchange: AsyncMock,
    mock_userinfo: AsyncMock,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    await store_google_oauth_state(fake_redis, "valid-state")
    mock_exchange.return_value = {
        "access_token": "token",
        "id_token": "header.eyJzdWIiOiAib25lLXN1YiJ9.signature",
    }
    mock_userinfo.return_value = {
        "sub": "different-sub",
        "email": "google@example.com",
        "name": "Google User",
        "picture": "https://example.com/photo.jpg",
    }

    with pytest.raises(
        GoogleOAuthError,
        match="Google token subject did not match the user info response",
    ):
        await authenticate_with_google(
            db_session, fake_redis, "auth-code", "valid-state"
        )


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (
            {
                "sub": "google-sub",
                "email": "user@example.com",
                "email_verified": False,
                "name": "User",
            },
            "Google account email is not verified",
        ),
        (
            {
                "sub": "google-sub",
                "email": "user@example.com",
                "name": "User",
            },
            "Google account email is not verified",
        ),
        (
            {
                "sub": "google-sub",
                "email": "",
                "email_verified": True,
                "name": "User",
            },
            "Google account did not provide an email address",
        ),
        (
            {
                "sub": "google-sub",
                "email_verified": True,
                "name": "User",
            },
            "Google account did not provide an email address",
        ),
        (
            {
                "sub": "google-sub",
                "email": "user@example.com",
                "email_verified": True,
                "name": "",
            },
            "Google account did not provide a valid display name",
        ),
        (
            {
                "sub": "google-sub",
                "email": "user@example.com",
                "email_verified": True,
            },
            "Google account did not provide a valid display name",
        ),
    ],
)
async def test_fetch_google_userinfo_rejects_invalid_payloads(
    payload: dict[str, object],
    expected_message: str,
) -> None:
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = payload

    with patch(
        "app.services.auth_service.httpx.AsyncClient.get",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        with pytest.raises(GoogleOAuthError, match=expected_message):
            await _fetch_google_userinfo("token")


async def test_exchange_google_code_maps_http_status_error() -> None:
    request = httpx.Request("POST", "https://oauth2.googleapis.com/token")
    response = httpx.Response(status_code=401, request=request)
    status_error = httpx.HTTPStatusError(
        "Unauthorized",
        request=request,
        response=response,
    )

    with patch(
        "app.services.auth_service.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=status_error,
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google token exchange failed"
        ) as exc:
            await _exchange_google_code("bad-code")

    assert exc.value.status_code == 401


async def test_exchange_google_code_maps_transport_error() -> None:
    with patch(
        "app.services.auth_service.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        side_effect=httpx.ConnectError("network down"),
    ):
        with pytest.raises(
            GoogleOAuthError, match="Could not reach Google token endpoint"
        ) as exc:
            await _exchange_google_code("bad-code")

    assert exc.value.status_code == 502


async def test_exchange_google_code_returns_optional_id_token() -> None:
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "access_token": "access-token",
        "id_token": "header.payload.signature",
    }

    with patch(
        "app.services.auth_service.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        payload = await _exchange_google_code("auth-code")

    assert payload == {
        "access_token": "access-token",
        "id_token": "header.payload.signature",
    }


async def test_exchange_google_code_rejects_invalid_id_token_type() -> None:
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = {
        "access_token": "access-token",
        "id_token": 123,
    }

    with patch(
        "app.services.auth_service.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google token response included an invalid ID token"
        ):
            await _exchange_google_code("auth-code")


async def test_exchange_google_code_rejects_non_object_payload() -> None:
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = ["not", "an", "object"]

    with patch(
        "app.services.auth_service.httpx.AsyncClient.post",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google token response was not a JSON object"
        ):
            await _exchange_google_code("auth-code")


@pytest.mark.parametrize(
    ("id_token", "expected_message"),
    [
        ("not-a-jwt", "Google token response included a malformed ID token"),
        (
            "header.e30.signature",
            "Google token response did not include a valid subject",
        ),
        (
            "header.W10.signature",
            "Google token response did not include a valid subject",
        ),
    ],
)
def test_extract_google_id_token_subject_rejects_invalid_tokens(
    id_token: str, expected_message: str
) -> None:
    with pytest.raises(GoogleOAuthError, match=expected_message):
        _extract_google_id_token_subject(id_token)


def test_validate_google_subject_consistency_accepts_missing_id_token() -> None:
    _validate_google_subject_consistency(None, "userinfo-sub")


def test_validate_google_subject_consistency_accepts_matching_subjects() -> None:
    _validate_google_subject_consistency(
        "header.eyJzdWIiOiAidXNlcmluZm8tc3ViIn0.signature",
        "userinfo-sub",
    )


def test_validate_google_subject_consistency_rejects_mismatch() -> None:
    with pytest.raises(
        GoogleOAuthError,
        match="Google token subject did not match the user info response",
    ):
        _validate_google_subject_consistency(
            "header.eyJzdWIiOiAib25lLXN1YiJ9.signature",
            "different-sub",
        )


async def test_fetch_google_userinfo_maps_http_status_error() -> None:
    request = httpx.Request("GET", "https://www.googleapis.com/oauth2/v3/userinfo")
    response = httpx.Response(status_code=403, request=request)
    status_error = httpx.HTTPStatusError(
        "Forbidden",
        request=request,
        response=response,
    )

    with patch(
        "app.services.auth_service.httpx.AsyncClient.get",
        new_callable=AsyncMock,
        side_effect=status_error,
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google user info lookup failed"
        ) as exc:
            await _fetch_google_userinfo("bad-token")

    assert exc.value.status_code == 403


async def test_fetch_google_userinfo_rejects_non_object_payload() -> None:
    mock_response = MagicMock()
    mock_response.raise_for_status.return_value = None
    mock_response.json.return_value = ["not", "an", "object"]

    with patch(
        "app.services.auth_service.httpx.AsyncClient.get",
        new_callable=AsyncMock,
        return_value=mock_response,
    ):
        with pytest.raises(
            GoogleOAuthError, match="Google user info response was not a JSON object"
        ):
            await _fetch_google_userinfo("token")


async def test_fetch_google_userinfo_maps_transport_error() -> None:
    with patch(
        "app.services.auth_service.httpx.AsyncClient.get",
        new_callable=AsyncMock,
        side_effect=httpx.ConnectError("network down"),
    ):
        with pytest.raises(
            GoogleOAuthError, match="Could not reach Google user info endpoint"
        ) as exc:
            await _fetch_google_userinfo("bad-token")

    assert exc.value.status_code == 502
