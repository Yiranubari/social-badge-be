import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.security import hash_password
from app.models.auth_provider import AuthProvider
from app.models.user import User


async def test_user_creation(db_session: AsyncSession) -> None:
    hashed_password = hash_password("hashed_password")
    user = User(
        name="Test User",
        email="test@example.com",
        password_hash=hashed_password,
    )
    db_session.add(user)

    await db_session.commit()
    await db_session.refresh(user)

    assert user.id is not None
    assert user.name == "Test User"
    assert user.email == "test@example.com"
    assert user.password_hash == hashed_password
    assert user.is_email_verified is False
    assert user.created_at is not None
    assert user.updated_at is not None


async def test_user_email_unique(db_session: AsyncSession) -> None:
    user1 = User(name="User 1", email="unique@example.com")
    db_session.add(user1)
    await db_session.commit()

    user2 = User(name="User 2", email="unique@example.com")
    db_session.add(user2)
    with pytest.raises(IntegrityError):
        await db_session.commit()

    await db_session.rollback()


async def test_user_auth_provider_relationship(db_session: AsyncSession) -> None:
    user = User(name="Test User", email="provider@example.com")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    provider = AuthProvider(
        provider="email", user_id=user.id, label="Email and Password"
    )
    db_session.add(provider)
    await db_session.commit()

    # Query user and load relationship eagerly to avoid MissingGreenlet on lazy load
    stmt = (
        select(User)
        .options(selectinload(User.auth_providers))
        .where(User.id == user.id)
    )
    result = await db_session.execute(stmt)
    db_user = result.scalars().first()

    assert db_user is not None
    assert db_user.auth_providers is not None
    assert len(db_user.auth_providers) == 1
    assert db_user.auth_providers[0].provider == "email"

    stmt_provider = select(AuthProvider).where(AuthProvider.user_id == user.id)
    result_provider = await db_session.execute(stmt_provider)
    db_provider = result_provider.scalars().first()

    assert db_provider is not None

    assert db_provider.provider == "email"
    assert db_provider.user_id == user.id

    await db_session.delete(db_user)
    await db_session.commit()

    result_provider = await db_session.execute(stmt_provider)
    db_provider_after_delete = result_provider.scalars().first()
    assert db_provider_after_delete is None
