from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.refresh_tokens import RefreshToken
from app.models.user import User


def _future_expiry(days: int = 7) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


async def _create_user(session: AsyncSession, email: str) -> User:
    user = User(first_name="Token", last_name="Owner", email=email)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def test_refresh_token_creation(db_session: AsyncSession) -> None:
    user = await _create_user(db_session, "rt_create@example.com")
    token = RefreshToken(
        user_id=user.id,
        token_hash="abc123hash",  # noqa: S106
        expires_at=_future_expiry(),
    )
    db_session.add(token)
    await db_session.commit()
    await db_session.refresh(token)

    assert token.id is not None
    assert token.user_id == user.id
    assert token.token_hash == "abc123hash"  # noqa: S105
    assert token.created_at is not None
    assert token.expires_at is not None


async def test_refresh_token_defaults(db_session: AsyncSession) -> None:
    user = await _create_user(db_session, "rt_defaults@example.com")
    token = RefreshToken(
        user_id=user.id,
        token_hash="defaulthash",  # noqa: S106
        expires_at=_future_expiry(),
    )
    db_session.add(token)
    await db_session.commit()
    await db_session.refresh(token)

    assert token.is_revoked is False


async def test_refresh_token_cascade_delete_on_user_delete(
    db_session: AsyncSession,
) -> None:
    user = await _create_user(db_session, "rt_cascade@example.com")
    token = RefreshToken(
        user_id=user.id,
        token_hash="todelete",  # noqa: S106
        expires_at=_future_expiry(),
    )
    db_session.add(token)
    await db_session.commit()
    token_id = token.id

    await db_session.delete(user)
    await db_session.commit()

    result = await db_session.execute(
        select(RefreshToken).where(RefreshToken.id == token_id)
    )
    assert result.scalars().first() is None


async def test_user_refresh_tokens_relationship(db_session: AsyncSession) -> None:
    user = await _create_user(db_session, "rt_rel@example.com")
    for i in range(2):
        token = RefreshToken(
            user_id=user.id,
            token_hash=f"hash{i}",
            expires_at=_future_expiry(),
        )
        db_session.add(token)
        await db_session.commit()

    stmt = (
        select(User)
        .options(selectinload(User.refresh_tokens))
        .where(User.id == user.id)
    )
    result = await db_session.execute(stmt)
    db_user = result.scalars().first()

    assert db_user is not None
    assert len(db_user.refresh_tokens) == 2
    assert all(rt.user_id == user.id for rt in db_user.refresh_tokens)


async def test_refresh_token_requires_user_id(db_session: AsyncSession) -> None:
    """token_hash without a valid user_id should violate FK constraint."""
    import uuid

    from sqlalchemy.exc import IntegrityError

    token = RefreshToken(
        user_id=uuid.uuid4(),  # non-existent user
        token_hash="orphan",  # noqa: S106
        expires_at=_future_expiry(),
    )
    db_session.add(token)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()
