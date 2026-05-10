from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fakeredis import FakeAsyncRedis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EmailConflictError, EmailDeliveryError, GoogleOAuthError
from app.core.security import verify_password
from app.core.token import store_google_oauth_state
from app.models.auth_provider import AuthProvider
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, SignupRequest
from app.services.auth_service import (
    _exchange_google_code,
    _extract_google_id_token_subject,
    _fetch_google_userinfo,
    _validate_google_subject_consistency,
    authenticate_with_google,
    build_google_auth_url,
    request_password_reset,
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
        name="Existing User",
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
        name="Hijacked User",
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
        name="Linked User",
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
