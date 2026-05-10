import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from jose import jwt
from redis.asyncio import Redis

from app.core.config import settings

TOKEN_PREFIX = "verify:"  # noqa: S105
PASSWORD_RESET_PREFIX = "pwd_reset:"  # noqa: S105


def generate_token() -> tuple[str, str]:
    """Return a (raw_token, token_hash) pair.

    The raw token is sent to the user via email.
    Only the hash is stored in Redis so a leaked store does not
    compromise pending verifications.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hash_token(raw_token)
    return raw_token, token_hash


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def store_verification_token(
    redis: Redis,
    token_hash: str,
    user_id: str,
) -> None:
    ttl_seconds = settings.VERIFICATION_TOKEN_TTL_MINUTES * 60
    await redis.set(f"{TOKEN_PREFIX}{token_hash}", user_id, ex=ttl_seconds)


async def get_verified_user_id(
    redis: Redis,
    token_hash: str,
) -> str | None:
    """Look up and consume a verification token.

    Returns the associated user_id if the token is still valid,
    otherwise None.  Deletes the token on successful lookup
    because verification tokens are single-use.
    """
    key = f"{TOKEN_PREFIX}{token_hash}"
    user_id = await redis.get(key)
    if user_id is not None:
        await redis.delete(key)
        return str(user_id)
    return None


def create_access_token(user_id: UUID) -> str:
    """Generate and return a JWT access token."""

    expire = datetime.now(UTC) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(UTC),
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_refresh_token(user_id: UUID) -> tuple[str, datetime]:
    """Generate and return a JWT refresh token."""

    expire = datetime.now(UTC) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(UTC),
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(
        payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    ), expire


async def store_password_reset_token(
    redis: Redis,
    token_hash: str,
    user_id: str,
) -> None:
    """Store a password reset token in Redis with a TTL."""
    ttl_seconds = settings.PASSWORD_RESET_TOKEN_TTL_MINUTES * 60
    await redis.set(f"{PASSWORD_RESET_PREFIX}{token_hash}", user_id, ex=ttl_seconds)


async def get_password_reset_user_id(
    redis: Redis,
    token_hash: str,
) -> str | None:
    """Look up and consume a password reset token.

    Returns the associated user_id if the token is still valid,
    otherwise None.  Deletes the token on successful lookup
    because password reset tokens are single-use.
    """
    key = f"{PASSWORD_RESET_PREFIX}{token_hash}"
    user_id = await redis.get(key)
    if user_id is not None:
        await redis.delete(key)
        return str(user_id)
    return None
