from uuid import UUID

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    EmailConflictError,
    EmailDeliveryError,
    InvalidPasswordResetTokenError,
)
from app.core.security import hash_password
from app.core.token import (
    generate_token,
    get_password_reset_user_id,
    hash_token,
    store_verification_token,
)
from app.models.auth_provider import AuthProvider
from app.models.user import User
from app.schemas.auth import ResetPasswordRequest, SignupRequest
from app.services.email_service import send_verification_email


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

    user.password_hash = hash_password(payload.new_password)

    await session.commit()
