import asyncio
import base64
import binascii
import json
import logging
from urllib.parse import urlencode
from uuid import UUID

import httpx
from fastapi import Response
from redis.asyncio import Redis
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
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
    create_access_token,
    create_refresh_token,
    generate_token,
    get_google_oauth_state,
    get_password_reset_user_id,
    hash_token,
    store_google_oauth_state,
    store_password_reset_token,
    store_verification_token,
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
from app.services.email_service import (
    send_account_lock_email,
    send_password_reset_email,
    send_verification_email,
)

logger = logging.getLogger(__name__)
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"  # noqa: S105
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_SCOPES = ("openid", "email", "profile")

FAILED_LOGIN_PREFIX = "failed_login:"

# Stable dummy hash used to equalize CPU cost between known/unknown users
# and prevent timing-based account enumeration.
_DUMMY_PASSWORD_HASH = hash_password("dummy-password-for-timing-equalization")


async def signup(
    session: AsyncSession,
    redis: Redis,
    payload: SignupRequest,
) -> tuple[User, bool]:
    """Orchestrate user creation, provider linkage, and email verification."""
    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalars().first() is not None:
        raise EmailConflictError

    password_hash = await asyncio.to_thread(hash_password, payload.password)

    user = User(
        first_name=payload.first_name,
        last_name=payload.last_name,
        email=payload.email,
        password_hash=password_hash,
    )
    session.add(user)

    try:
        await session.flush()
    except IntegrityError as err:
        await session.rollback()
        raise EmailConflictError from err

    auth_provider = AuthProvider(
        provider="email",
        user_id=user.id,
        label="Email and Password",
    )
    session.add(auth_provider)

    raw_token, token_hash = generate_token()
    await store_verification_token(redis, token_hash, str(user.id))

    await session.commit()

    email_sent = True
    try:
        await send_verification_email(payload.email, raw_token)
    except EmailDeliveryError:
        email_sent = False

    return user, email_sent


async def reset_password(
    session: AsyncSession,
    redis: Redis,
    payload: ResetPasswordRequest,
) -> None:
    """Reset a user's password and invalidate existing sessions."""
    token_hash = hash_token(payload.token)
    user_id = await get_password_reset_user_id(redis, token_hash)

    if user_id is None:
        raise InvalidPasswordResetTokenError

    try:
        parsed_user_id = UUID(user_id)
    except ValueError as exc:
        raise InvalidPasswordResetTokenError from exc

    result = await session.execute(select(User).where(User.id == parsed_user_id))
    user = result.scalars().first()

    if user is None:
        raise InvalidPasswordResetTokenError

    user.password_hash = await asyncio.to_thread(hash_password, payload.new_password)
    await session.execute(
        delete(RefreshToken).where(RefreshToken.user_id == parsed_user_id)
    )
    await session.flush()
    await session.refresh(user)
    await session.commit()


async def signin(
    session: AsyncSession,
    redis: Redis,
    payload: LoginRequest,
) -> tuple[User, str, str]:
    """Handle user login and rate limiting against invalid attempts."""

    await check_lockout(redis, payload.email)

    existing = await session.execute(select(User).where(User.email == payload.email))
    existing_user = existing.scalars().first()
    if not existing_user:
        # Equalize timing with the wrong-password branch to avoid leaking
        # whether the email is registered.
        await asyncio.to_thread(verify_password, payload.password, _DUMMY_PASSWORD_HASH)
        attempts = await increment_failed_attempts(redis, payload.email)

        if attempts >= settings.MAX_LOGIN_ATTEMPTS:
            raise AccountLockedError("Account locked due to too many failed attempts.")

        raise InvalidCredentialsError

    if not existing_user.password_hash or not await asyncio.to_thread(
        verify_password, payload.password, existing_user.password_hash
    ):
        attempts = await increment_failed_attempts(redis, payload.email)

        if attempts >= settings.MAX_LOGIN_ATTEMPTS:
            try:
                await send_account_lock_email(existing_user.email)
            except EmailDeliveryError:
                pass
            raise AccountLockedError("Account locked due to too many failed attempts.")

        raise InvalidCredentialsError

    await reset_attempts(redis, payload.email)

    if not existing_user.is_email_verified:
        raise EmailNotVerifiedError

    access_token = create_access_token(existing_user.id)
    raw_refresh_token, expire = create_refresh_token(existing_user.id)

    refresh_token = RefreshToken(
        user_id=existing_user.id,
        token_hash=hash_token(raw_refresh_token),
        expires_at=expire,
    )
    session.add(refresh_token)

    await session.commit()

    return existing_user, access_token, raw_refresh_token


def set_refresh_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=settings.REFRESH_COOKIE,
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
    )


async def check_lockout(redis: Redis, identifier: str) -> None:
    key = f"{FAILED_LOGIN_PREFIX}{identifier}"
    attempts = await redis.get(key)

    if attempts and int(attempts) >= settings.MAX_LOGIN_ATTEMPTS:
        ttl = await redis.ttl(key)
        minutes = max(1, ttl // 60) if ttl and ttl > 0 else 1
        raise AccountLockedError(f"Account locked. Try again in {minutes} minute(s).")


async def increment_failed_attempts(redis: Redis, identifier: str) -> int:
    key = f"{FAILED_LOGIN_PREFIX}{identifier}"
    count = await redis.incr(key)

    if count == 1:
        # Set expiration only on the first failed attempt
        await redis.expire(key, settings.LOCKOUT_WINDOW)
    return int(count)


async def reset_attempts(redis: Redis, identifier: str) -> None:
    await redis.delete(f"{FAILED_LOGIN_PREFIX}{identifier}")


async def request_password_reset(
    session: AsyncSession,
    redis: Redis,
    payload: ForgotPasswordRequest,
) -> None:
    """Generate a password reset token and email it to the user.

    Silently no-ops if no user exists with the given email to prevent
    email enumeration attacks. Email delivery failures are also
    swallowed silently for the same reason.
    """

    result = await session.execute(select(User).where(User.email == payload.email))
    user = result.scalars().first()

    if user is None:
        return

    raw_token, token_hash = generate_token()
    await store_password_reset_token(redis, token_hash, str(user.id))

    try:
        await send_password_reset_email(payload.email, raw_token)
    except EmailDeliveryError:
        logger.warning("Failed to send password reset email to %s", payload.email)


async def build_google_auth_url(redis: Redis) -> str:
    """
    Returns Google Auth URL with params and a stored state for CSRF protection.
    """
    state, _ = generate_token()
    await store_google_oauth_state(redis, state)

    params = urlencode(
        {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(GOOGLE_SCOPES),
            "state": state,
        }
    )
    return f"{GOOGLE_AUTH_URL}?{params}"


async def authenticate_with_google(
    session: AsyncSession,
    redis: Redis,
    code: str,
    state: str,
) -> tuple[User, bool]:
    """
    Handles the Google OAuth callback by validating state, exchanging code for token,
    fetching user info, and upserting the user record.
    """
    state_is_valid = await get_google_oauth_state(redis, state)
    if not state_is_valid:
        raise GoogleOAuthError("Invalid or expired Google OAuth state")

    token_payload = await _exchange_google_code(code)
    user_info = await _fetch_google_userinfo(token_payload["access_token"])  # type: ignore
    _validate_google_subject_consistency(
        token_payload.get("id_token"), user_info["sub"]
    )
    user, is_new_user = await _upsert_google_user(session, user_info)
    return user, is_new_user


async def _exchange_google_code(code: str) -> dict[str, str | None]:
    """
    Exchanges the authorization code for an access token
    by calling Google's token endpoint.
    """
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.post(
                GOOGLE_TOKEN_URL,
                data={
                    "client_id": settings.GOOGLE_CLIENT_ID,
                    "client_secret": settings.GOOGLE_CLIENT_SECRET,
                    "code": code,
                    "grant_type": "authorization_code",
                    "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                },
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GoogleOAuthError(
                "Google token exchange failed",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.HTTPError as exc:
            raise GoogleOAuthError(
                "Could not reach Google token endpoint",
                status_code=502,
            ) from exc

    payload = response.json()
    if not isinstance(payload, dict):
        raise GoogleOAuthError("Google token response was not a JSON object")
    access_token = payload.get("access_token")
    if not isinstance(access_token, str) or not access_token:
        raise GoogleOAuthError("Google token response did not include an access token")
    id_token = payload.get("id_token")
    if id_token is not None and (not isinstance(id_token, str) or not id_token):
        raise GoogleOAuthError("Google token response included an invalid ID token")
    return {"access_token": access_token, "id_token": id_token}


async def _fetch_google_userinfo(access_token: str) -> dict[str, str | bool | None]:
    """Fetches the user's profile information from Google using the access token."""
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise GoogleOAuthError(
                "Google user info lookup failed",
                status_code=exc.response.status_code,
            ) from exc
        except httpx.HTTPError as exc:
            raise GoogleOAuthError(
                "Could not reach Google user info endpoint",
                status_code=502,
            ) from exc

    payload = response.json()
    if not isinstance(payload, dict):
        raise GoogleOAuthError("Google user info response was not a JSON object")
    subject = payload.get("sub")
    email = payload.get("email")
    email_verified = payload.get("email_verified")
    name = payload.get("name")

    if not isinstance(subject, str) or not subject:
        raise GoogleOAuthError("Google account did not provide a stable account ID")
    if not isinstance(email, str) or not email:
        raise GoogleOAuthError("Google account did not provide an email address")
    if email_verified is not True:
        raise GoogleOAuthError("Google account email is not verified")
    if not isinstance(name, str) or not name.strip():
        raise GoogleOAuthError("Google account did not provide a valid display name")

    picture = payload.get("picture")
    picture_url = picture if isinstance(picture, str) and picture else None

    return {
        "sub": subject,
        "email": email,
        "name": name.strip(),
        "picture": picture_url,
    }


def _validate_google_subject_consistency(
    id_token: str | None, userinfo_subject: str | bool | None
) -> None:
    """Cross-check the token and userinfo subjects when Google returns both."""
    if id_token is None:
        return

    token_subject = _extract_google_id_token_subject(id_token)
    if token_subject != userinfo_subject:
        raise GoogleOAuthError(
            "Google token subject did not match the user info response"
        )


def _extract_google_id_token_subject(id_token: str) -> str:
    """Read the JWT payload subject for consistency checks.

    This is intentionally limited to subject extraction so we can compare
    the token endpoint identity with the userinfo identity without adding
    a separate JWT verification dependency.
    """
    segments = id_token.split(".")
    if len(segments) != 3:
        raise GoogleOAuthError("Google token response included a malformed ID token")

    payload_segment = segments[1]
    padding = "=" * (-len(payload_segment) % 4)

    try:
        payload_bytes = base64.urlsafe_b64decode(payload_segment + padding)
        payload = json.loads(payload_bytes)
    except (binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GoogleOAuthError(
            "Google token response included a malformed ID token"
        ) from exc

    if not isinstance(payload, dict):
        raise GoogleOAuthError("Google token response did not include a valid subject")

    subject = payload.get("sub")
    if not isinstance(subject, str) or not subject:
        raise GoogleOAuthError("Google token response did not include a valid subject")
    return subject


async def _upsert_google_user(
    session: AsyncSession,
    user_info: dict[str, str | bool | None],
) -> tuple[User, bool]:
    """
    Finds or creates a User record based on Google user info,
    and ensures an AuthProvider record exists.
    """
    google_subject = str(user_info["sub"])
    email = str(user_info["email"])
    name = str(user_info["name"])
    picture = user_info["picture"]

    provider_result = await session.execute(
        select(AuthProvider).where(
            AuthProvider.provider == "google",
            AuthProvider.provider_user_id == google_subject,
        )
    )
    provider = provider_result.scalars().first()

    if provider is not None:
        user = await session.get(User, provider.user_id)
        if user is None:
            raise GoogleOAuthError("Linked Google account references a missing user")
        is_new_user = False
    else:
        existing_result = await session.execute(select(User).where(User.email == email))
        user = existing_result.scalars().first()
        is_new_user = user is None

        if user is None:
            names = name.split(maxsplit=1) if name and name.strip() else []
            if names:
                first_name = names[0]
                last_name = names[1] if len(names) > 1 else None
            else:
                first_name = email.split("@")[0]
                last_name = None

            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password_hash=None,
                is_email_verified=True,
                profile_photo_url=picture if isinstance(picture, str) else None,
            )
            session.add(user)
            await session.flush()
        else:
            if user.password_hash is not None and not user.is_email_verified:
                raise GoogleOAuthError(
                    (
                        "An unverified password account already exists for this email. "
                        "Please sign in with your password and verify your email "
                        "before linking Google."
                    ),
                    status_code=409,
                )

            user.is_email_verified = True
            if isinstance(picture, str):
                user.profile_photo_url = picture

    if provider is None:
        session.add(
            AuthProvider(
                provider="google",
                provider_user_id=google_subject,
                user_id=user.id,
                label="Google",
            )
        )

    await session.commit()
    await session.refresh(user)
    return user, is_new_user
