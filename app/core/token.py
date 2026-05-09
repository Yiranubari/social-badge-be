import hashlib
import secrets

from redis.asyncio import Redis

from app.core.config import settings

TOKEN_PREFIX = "verify:"  # noqa: S105
GOOGLE_STATE_PREFIX = "oauth:google:state:"


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


async def store_google_oauth_state(redis: Redis, state: str) -> None:
    ttl_seconds = settings.GOOGLE_OAUTH_STATE_TTL_MINUTES * 60
    await redis.set(f"{GOOGLE_STATE_PREFIX}{state}", "1", ex=ttl_seconds)


async def get_google_oauth_state(redis: Redis, state: str) -> bool:
    key = f"{GOOGLE_STATE_PREFIX}{state}"
    stored = await redis.getdel(key)
    if stored is None:
        return False

    return True
