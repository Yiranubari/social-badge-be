import asyncio
import logging

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EmailConflictError, EmailDeliveryError
from app.core.security import hash_password
from app.core.token import (
    generate_token,
    store_password_reset_token,
    store_verification_token,
)
from app.models.auth_provider import AuthProvider
from app.models.user import User
from app.schemas.auth import ForgotPasswordRequest, SignupRequest
from app.services.email_service import (
    send_password_reset_email,
    send_verification_email,
)

logger = logging.getLogger(__name__)


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
        name=payload.name,
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
