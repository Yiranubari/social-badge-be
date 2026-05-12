import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password
from app.core.token import create_access_token
from app.models import OrganiserTemplate, PlatformTemplate, User


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


@pytest.fixture
async def organiser_template(
    db_session: AsyncSession,
    test_user: User,
    platform_template: PlatformTemplate,
) -> OrganiserTemplate:
    """Seed an organiser template owned by test_user."""
    template = OrganiserTemplate(
        organizer_id=test_user.id,
        platform_template_id=platform_template.id,
        title="My Test Event",
        canvas_data={"layout": "test-v1"},
    )
    db_session.add(template)
    await db_session.commit()
    await db_session.refresh(template)
    return template


async def test_publish_template_success(
    client: AsyncClient,
    auth_headers: dict[str, str],
    organiser_template: OrganiserTemplate,
) -> None:
    response = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Template published successfully."
    assert data["data"]["is_published"] is True
    assert data["data"]["share_slug"] is not None
    assert len(data["data"]["share_slug"]) == 12
    assert data["data"]["published_at"] is not None


async def test_publish_template_unauthenticated(
    client: AsyncClient, organiser_template: OrganiserTemplate
) -> None:
    response = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
    )
    assert response.status_code in (401, 403)


async def test_publish_template_not_found(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    fake_id = uuid.uuid4()
    response = await client.post(
        f"/api/v1/templates/{fake_id}/publish",
        headers=auth_headers,
    )
    assert response.status_code == 404
    assert response.json()["message"] == "Template not found."


async def test_publish_template_not_owner(
    client: AsyncClient,
    db_session: AsyncSession,
    platform_template: PlatformTemplate,
) -> None:
    """A different user cannot publish someone else's template."""
    owner = User(
        first_name="Owner",
        last_name="User",
        email="owner@example.com",
        password_hash=hash_password("StrongPassword1!"),
        is_email_verified=True,
    )
    other = User(
        first_name="Other",
        last_name="User",
        email="other@example.com",
        password_hash=hash_password("StrongPassword1!"),
        is_email_verified=True,
    )
    db_session.add(owner)
    await db_session.flush()
    db_session.add(other)
    await db_session.flush()
    await db_session.commit()
    await db_session.refresh(owner)
    await db_session.refresh(other)

    template = OrganiserTemplate(
        organizer_id=owner.id,
        platform_template_id=platform_template.id,
        title="Owner's Event",
        canvas_data={"layout": "test-v1"},
    )
    db_session.add(template)
    await db_session.commit()
    await db_session.refresh(template)

    other_token = create_access_token(other.id)
    response = await client.post(
        f"/api/v1/templates/{template.id}/publish",
        headers={"Authorization": f"Bearer {other_token}"},
    )
    assert response.status_code == 403
    assert response.json()["message"] == "You do not own this template."


async def test_publish_template_already_published(
    client: AsyncClient,
    auth_headers: dict[str, str],
    organiser_template: OrganiserTemplate,
) -> None:
    await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    response = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    assert response.status_code == 409
    assert response.json()["message"] == "Template is already published."


async def test_unpublish_template_success(
    client: AsyncClient,
    auth_headers: dict[str, str],
    organiser_template: OrganiserTemplate,
) -> None:
    publish_response = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    original_slug = publish_response.json()["data"]["share_slug"]

    response = await client.post(
        f"/api/v1/templates/{organiser_template.id}/unpublish",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Template unpublished successfully."
    assert data["data"]["is_published"] is False
    assert data["data"]["share_slug"] == original_slug
    assert data["data"]["published_at"] is None


async def test_republish_preserves_slug(
    client: AsyncClient,
    auth_headers: dict[str, str],
    organiser_template: OrganiserTemplate,
) -> None:
    first = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    original_slug = first.json()["data"]["share_slug"]

    await client.post(
        f"/api/v1/templates/{organiser_template.id}/unpublish",
        headers=auth_headers,
    )
    second = await client.post(
        f"/api/v1/templates/{organiser_template.id}/publish",
        headers=auth_headers,
    )
    assert second.status_code == 200
    assert second.json()["data"]["share_slug"] == original_slug


async def test_unpublish_template_not_found(
    client: AsyncClient, auth_headers: dict[str, str]
) -> None:
    fake_id = uuid.uuid4()
    response = await client.post(
        f"/api/v1/templates/{fake_id}/unpublish",
        headers=auth_headers,
    )
    assert response.status_code == 404
