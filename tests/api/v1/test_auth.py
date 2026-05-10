from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient

from app.core.exceptions import EmailDeliveryError


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
