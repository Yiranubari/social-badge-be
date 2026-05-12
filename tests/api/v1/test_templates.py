import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.core.token import create_access_token
from app.models import PlatformTemplate, User


@pytest.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create a verified user for authenticated requests."""
    user = User(
        first_name="Test",
        last_name="Organiser",
        email="organiser@example.com",
        password_hash=hash_password("StrongPassword1!"),
        is_email_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict[str, str]:
    """Return a Bearer token header for the test user."""
    token = create_access_token(test_user.id)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def platform_template(db_session: AsyncSession) -> PlatformTemplate:
    """Seed a single platform template for tests."""
    template = PlatformTemplate(
        title="Test Layout",
        canvas_data={"layout": "test-v1"},
        thumbnail_url=None,
    )
    db_session.add(template)
    await db_session.commit()
    await db_session.refresh(template)
    return template


async def test_create_instance_success(
    client: AsyncClient,
    auth_headers: dict[str, str],
    platform_template: PlatformTemplate,
    test_user: User,
) -> None:
    response = await client.post(
        "/api/v1/templates/instances",
        headers=auth_headers,
        json={"platform_template_id": str(platform_template.id)},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Template instance created successfully."
    assert data["data"]["platform_template_id"] == str(platform_template.id)
    assert data["data"]["organizer_id"] == str(test_user.id)
    assert "instance_id" in data["data"]
    assert "created_at" in data["data"]


async def test_create_instance_unauthenticated(
    client: AsyncClient, platform_template: PlatformTemplate
) -> None:
    response = await client.post(
        "/api/v1/templates/instances",
        json={"platform_template_id": str(platform_template.id)},
    )
    assert response.status_code in (401, 403)


async def test_create_instance_platform_template_not_found(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    fake_id = uuid.uuid4()
    response = await client.post(
        "/api/v1/templates/instances",
        headers=auth_headers,
        json={"platform_template_id": str(fake_id)},
    )
    assert response.status_code == 404
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Platform template not found."


async def test_create_instance_missing_field(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    response = await client.post(
        "/api/v1/templates/instances",
        headers=auth_headers,
        json={},
    )
    assert response.status_code == 422