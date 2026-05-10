import uuid
from datetime import UTC, datetime
from unittest.mock import ANY, AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import AsyncClient

from app.core.exceptions import EmailDeliveryError, GoogleOAuthError
from app.models.user import User


@pytest.fixture
def valid_signup_payload() -> dict[str, str]:
    return {
        "name": "API Test User",
        "email": "apitest@example.com",
        "password": "StrongPassword1!",  # noqa: S106
    }


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_endpoint_success(
    mock_email: AsyncMock, client: AsyncClient, valid_signup_payload: dict[str, str]
) -> None:
    response = await client.post("/api/v1/auth/signup", json=valid_signup_payload)
    assert response.status_code == 201
    data = response.json()
    assert data["message"] == (
        "Registration successful. Please check your email to verify your account."
    )
    assert data["data"]["name"] == "API Test User"
    assert data["data"]["email"] == "apitest@example.com"
    mock_email.assert_called_once()


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_endpoint_conflict(
    mock_email: AsyncMock, client: AsyncClient, valid_signup_payload: dict[str, str]
) -> None:
    await client.post("/api/v1/auth/signup", json=valid_signup_payload)

    response = await client.post("/api/v1/auth/signup", json=valid_signup_payload)
    assert response.status_code == 409
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Email is already registered"


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_endpoint_email_delivery_failure(
    mock_email: AsyncMock, client: AsyncClient
) -> None:
    mock_email.side_effect = EmailDeliveryError("Failed to send")

    payload = {
        "name": "Fail User",
        "email": "fail@example.com",
        "password": "StrongPassword1!",  # noqa: S106
    }
    response = await client.post("/api/v1/auth/signup", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert "Account created." in data["message"]
    assert data["data"]["email"] == "fail@example.com"


@pytest.mark.asyncio
async def test_signup_endpoint_validation_error(client: AsyncClient) -> None:
    payload = {
        "name": "Short",
        "email": "not-an-email",
        "password": "weak",  # noqa: S106
    }
    response = await client.post("/api/v1/auth/signup", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert "message" in data


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
async def test_signup_endpoint_rate_limit(
    mock_email: AsyncMock, client: AsyncClient, valid_signup_payload: dict[str, str]
) -> None:
    for _ in range(10):
        await client.post("/api/v1/auth/signup", json=valid_signup_payload)

    # 11th request should be rate-limited
    response = await client.post("/api/v1/auth/signup", json=valid_signup_payload)
    assert response.status_code == 429
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Rate limit exceeded"


@patch("app.services.auth_service.send_verification_email", new_callable=AsyncMock)
@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_forgot_password_endpoint_existing_email(
    mock_reset_email: AsyncMock,
    mock_verify_email: AsyncMock,
    client: AsyncClient,
    valid_signup_payload: dict[str, str],
) -> None:
    await client.post("/api/v1/auth/signup", json=valid_signup_payload)

    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": valid_signup_payload["email"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == (
        "If an account with that email exists, a password reset email has been sent."
    )
    mock_reset_email.assert_called_once()


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_forgot_password_endpoint_nonexistent_email(
    mock_reset_email: AsyncMock, client: AsyncClient
) -> None:
    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "nobody@example.com"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == (
        "If an account with that email exists, a password reset email has been sent."
    )
    mock_reset_email.assert_not_called()


async def test_forgot_password_endpoint_validation_error(client: AsyncClient) -> None:
    response = await client.post(
        "/api/v1/auth/forgot-password",
        json={"email": "not-an-email"},
    )
    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"


@patch("app.services.auth_service.send_password_reset_email", new_callable=AsyncMock)
async def test_forgot_password_endpoint_rate_limit(
    mock_reset_email: AsyncMock, client: AsyncClient
) -> None:
    payload = {"email": "ratelimit@example.com"}
    for _ in range(10):
        await client.post("/api/v1/auth/forgot-password", json=payload)

    response = await client.post("/api/v1/auth/forgot-password", json=payload)
    assert response.status_code == 429
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Rate limit exceeded"


async def test_google_login_redirects_to_google(client: AsyncClient) -> None:
    response = await client.get("/api/v1/auth/google", follow_redirects=False)

    assert response.status_code == 307
    redirect_url = response.headers["location"]
    parsed = urlparse(redirect_url)
    query = parse_qs(parsed.query)

    assert parsed.scheme == "https"
    assert parsed.netloc == "accounts.google.com"
    assert parsed.path == "/o/oauth2/v2/auth"
    assert query["response_type"] == ["code"]
    assert query["client_id"]
    assert query["redirect_uri"]
    assert query["scope"]
    assert query["access_type"] == ["offline"]
    assert query["prompt"] == ["consent"]
    assert query["state"]
    assert query["state"][0]


@patch("app.api.v1.endpoints.auth.authenticate_with_google", new_callable=AsyncMock)
async def test_google_callback_success(
    mock_authenticate: AsyncMock, client: AsyncClient
) -> None:
    user = User(
        id=uuid.uuid4(),
        name="Google User",
        email="google@example.com",
        is_email_verified=True,
        profile_photo_url="https://example.com/photo.jpg",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    mock_authenticate.return_value = (user, False)

    response = await client.get(
        "/api/v1/auth/google/callback?code=test-code&state=test-state"
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Google authentication successful."
    assert data["data"]["email"] == "google@example.com"
    mock_authenticate.assert_awaited_once_with(
        ANY,
        ANY,
        "test-code",
        "test-state",
    )


@patch("app.api.v1.endpoints.auth.authenticate_with_google", new_callable=AsyncMock)
async def test_google_callback_returns_error_response(
    mock_authenticate: AsyncMock, client: AsyncClient
) -> None:
    mock_authenticate.side_effect = GoogleOAuthError(
        "Invalid or expired Google OAuth state"
    )

    response = await client.get(
        "/api/v1/auth/google/callback?code=test-code&state=test-state"
    )

    assert response.status_code == 400
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Invalid or expired Google OAuth state"
    mock_authenticate.assert_awaited_once_with(
        ANY,
        ANY,
        "test-code",
        "test-state",
    )
