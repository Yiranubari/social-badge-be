import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fakeredis import FakeAsyncRedis
from jose import jwt

from app.core.config import settings
from app.core.token import (
    create_access_token,
    create_refresh_token,
    generate_token,
    get_verified_user_id,
    hash_token,
    store_verification_token,
)


@pytest.fixture
def fake_redis() -> FakeAsyncRedis:
    return FakeAsyncRedis(decode_responses=True)


def test_generate_token_returns_distinct_pair() -> None:
    raw, hashed = generate_token()
    assert raw != hashed


def test_hash_token_is_deterministic() -> None:
    raw, _ = generate_token()
    assert hash_token(raw) == hash_token(raw)


def test_consecutive_tokens_are_unique() -> None:
    raw_a, _ = generate_token()
    raw_b, _ = generate_token()
    assert raw_a != raw_b


async def test_stored_token_is_retrievable(fake_redis: FakeAsyncRedis) -> None:
    raw, token_hash = generate_token()
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    await store_verification_token(fake_redis, token_hash, user_id)

    result = await get_verified_user_id(fake_redis, token_hash)
    assert result == user_id


async def test_token_is_deleted_after_retrieval(fake_redis: FakeAsyncRedis) -> None:
    """Verification tokens are single-use."""
    raw, token_hash = generate_token()
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    await store_verification_token(fake_redis, token_hash, user_id)
    await get_verified_user_id(fake_redis, token_hash)

    second_lookup = await get_verified_user_id(fake_redis, token_hash)
    assert second_lookup is None


async def test_expired_token_returns_none(fake_redis: FakeAsyncRedis) -> None:
    raw, token_hash = generate_token()
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    # Store with 1-second TTL and wait for expiry
    await fake_redis.set(f"verify:{token_hash}", user_id, ex=1)

    await asyncio.sleep(1.5)

    result = await get_verified_user_id(fake_redis, token_hash)
    assert result is None


async def test_invalid_token_returns_none(fake_redis: FakeAsyncRedis) -> None:
    result = await get_verified_user_id(fake_redis, "nonexistent_hash")
    assert result is None


# ---------------------------------------------------------------------------
# JWT access token tests
# ---------------------------------------------------------------------------


def test_create_access_token_has_correct_subject() -> None:
    user_id = uuid4()
    token = create_access_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)


def test_create_access_token_has_exp_and_iat() -> None:
    user_id = uuid4()
    token = create_access_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert "exp" in payload
    assert "iat" in payload


def test_create_access_token_expires_in_configured_minutes() -> None:
    user_id = uuid4()
    before = datetime.now(UTC)
    token = create_access_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    exp = datetime.fromtimestamp(payload["exp"], tz=UTC)
    expected = before + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    assert abs((exp - expected).total_seconds()) < 5


def test_different_users_get_different_access_tokens() -> None:
    token_a = create_access_token(uuid4())
    token_b = create_access_token(uuid4())
    assert token_a != token_b


# ---------------------------------------------------------------------------
# JWT refresh token tests
# ---------------------------------------------------------------------------


def test_create_refresh_token_has_correct_subject() -> None:
    user_id = uuid4()
    token, _ = create_refresh_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)


def test_create_refresh_token_has_type_refresh() -> None:
    user_id = uuid4()
    token, _ = create_refresh_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["type"] == "refresh"


def test_create_refresh_token_returns_expire_datetime() -> None:
    user_id = uuid4()
    before = datetime.now(UTC)
    _, expire = create_refresh_token(user_id)
    assert isinstance(expire, datetime)
    expected = before + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    assert abs((expire - expected).total_seconds()) < 5


def test_create_refresh_token_is_decodable() -> None:
    user_id = uuid4()
    token, _ = create_refresh_token(user_id)
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == str(user_id)
    assert "exp" in payload
    assert "iat" in payload


def test_refresh_token_type_differs_from_access_token() -> None:
    user_id = uuid4()
    access = create_access_token(user_id)
    refresh, _ = create_refresh_token(user_id)
    access_payload = jwt.decode(
        access, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    refresh_payload = jwt.decode(
        refresh, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    assert "type" not in access_payload
    assert refresh_payload["type"] == "refresh"
