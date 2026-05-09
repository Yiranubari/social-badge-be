from fastapi import Response
from redis.asyncio import Redis
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
from app.core.token import (
    create_access_token,
    create_refresh_token,
    generate_token,
    hash_token,
    store_verification_token,
)
from app.models.auth_provider import AuthProvider
from app.models.refresh_tokens import RefreshToken
from app.models.user import User
from app.schemas.auth import LoginRequest, SignupRequest
from app.services.email_service import send_account_lock_email, send_verification_email

FAILED_LOGIN_PREFIX = "failed_login:"


async def signup(
    session: AsyncSession,
    redis: Redis,
    payload: SignupRequest,
) -> tuple[User, bool]:
    """Orchestrate user creation, provider linkage, and email verification."""
    existing = await session.execute(select(User).where(User.email == payload.email))
    if existing.scalars().first() is not None:
        raise EmailConflictError

    password_hash = hash_password(payload.password)

    user = User(
        name=payload.name,
        email=payload.email,
        password_hash=password_hash,
    )
    session.add(user)
    await session.flush()

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
        attempts = await increment_failed_attempts(redis, payload.email)

        if attempts >= settings.MAX_LOGIN_ATTEMPTS:
            raise AccountLockedError("Account locked due to too many failed attempts.")

        raise InvalidCredentialsError

    if not verify_password(payload.password, existing_user.password_hash or ""):
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


async def check_lockout(redis: Redis, identifier: str):
    key = f"{FAILED_LOGIN_PREFIX}{identifier}"
    attempts = await redis.get(key)

    if attempts and int(attempts) >= settings.MAX_LOGIN_ATTEMPTS:
        ttl = await redis.ttl(key)
        minutes = max(1, ttl // 60) if ttl and ttl > 0 else 1
        raise AccountLockedError(f"Account locked. Try again in {minutes} minute(s).")


async def increment_failed_attempts(redis: Redis, identifier: str):
    key = f"{FAILED_LOGIN_PREFIX}{identifier}"
    count = await redis.incr(key)

    if count == 1:
        # Set expiration only on the first failed attempt
        await redis.expire(key, settings.LOCKOUT_WINDOW)
    return count


async def reset_attempts(redis: Redis, identifier: str):
    await redis.delete(f"{FAILED_LOGIN_PREFIX}{identifier}")
