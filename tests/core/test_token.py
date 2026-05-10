import asyncio

import pytest
from fakeredis import FakeAsyncRedis

from app.core.token import (
    generate_token,
    get_password_reset_user_id,
    get_verified_user_id,
    hash_token,
    store_password_reset_token,
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


async def test_stored_password_reset_token_is_retrievable(
    fake_redis: FakeAsyncRedis,
) -> None:
    raw_token, token_hash = generate_token()
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    await store_password_reset_token(fake_redis, token_hash, user_id)
    first_lookup = await get_password_reset_user_id(fake_redis, token_hash)
    second_lookup = await get_password_reset_user_id(fake_redis, token_hash)

    assert raw_token != token_hash
    assert first_lookup == user_id
    assert second_lookup is None


async def test_expired_password_reset_token_returns_none(
    fake_redis: FakeAsyncRedis,
) -> None:
    raw_token, token_hash = generate_token()
    user_id = "550e8400-e29b-41d4-a716-446655440000"

    await fake_redis.set(f"reset:{token_hash}", user_id, ex=1)
    await asyncio.sleep(1.5)

    result = await get_password_reset_user_id(fake_redis, token_hash)

    assert raw_token != token_hash
    assert result is None


async def test_invalid_password_reset_token_returns_none(
    fake_redis: FakeAsyncRedis,
) -> None:
    result = await get_password_reset_user_id(fake_redis, "missing_hash")

    assert result is None
