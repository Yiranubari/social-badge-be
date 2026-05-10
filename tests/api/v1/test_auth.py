from unittest.mock import AsyncMock, patch

import pytest
from fakeredis import FakeAsyncRedis
from httpx import AsyncClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import EmailDeliveryError
from app.core.security import hash_password, verify_password
from app.core.token import generate_token, store_password_reset_token
from app.models.user import User
from app.schemas.auth import ResetPasswordRequest


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


def test_reset_password_request() -> None:
    data = {
        "token": "reset-token",
        "new_password": "NewStrongPassword123!",
        "confirm_password": "NewStrongPassword123!",
    }

    req = ResetPasswordRequest(**data)

    assert req.token == "reset-token"  # noqa: S105
    assert req.new_password == "NewStrongPassword123!"  # noqa: S105
    assert req.confirm_password == "NewStrongPassword123!"  # noqa: S105


def test_reset_password_request_rejects_password_mismatch() -> None:
    data = {
        "token": "reset-token",
        "new_password": "NewStrongPassword123!",
        "confirm_password": "DifferentStrongPassword123!",
    }

    with pytest.raises(ValidationError) as exc_info:
        ResetPasswordRequest(**data)

    assert "Passwords do not match" in str(exc_info.value)


@pytest.mark.parametrize(
    "invalid_password,expected_error",
    [
        ("short1!", "Password must be at least 8 characters long"),
        ("nouppercase123!", "Password must contain at least one uppercase letter"),
        ("NOLOWERCASE123!", "Password must contain at least one lowercase letter"),
        ("NoNumbersHere!", "Password must contain at least one number"),
        ("NoSpecialChar123", "Password must contain at least one special character"),
    ],
)
def test_reset_password_request_invalid(
    invalid_password: str,
    expected_error: str,
) -> None:
    data = {
        "token": "reset-token",
        "new_password": invalid_password,
        "confirm_password": invalid_password,
    }

    with pytest.raises(ValidationError) as exc_info:
        ResetPasswordRequest(**data)

    assert expected_error in str(exc_info.value)


def test_reset_password_request_rejects_empty_token() -> None:
    data = {
        "token": "",
        "new_password": "NewStrongPassword123!",
        "confirm_password": "NewStrongPassword123!",
    }

    with pytest.raises(ValidationError):
        ResetPasswordRequest(**data)


async def test_reset_password_endpoint_success(
    client: AsyncClient,
    db_session: AsyncSession,
    fake_redis: FakeAsyncRedis,
) -> None:
    user = User(
        name="API Reset User",
        email="api-reset@example.com",
        password_hash=hash_password("OldStrongPassword123!"),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    raw_token, token_hash = generate_token()
    await store_password_reset_token(fake_redis, token_hash, str(user.id))

    response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": raw_token,
            "new_password": "NewStrongPassword123!",
            "confirm_password": "NewStrongPassword123!",
        },
    )

    await db_session.refresh(user)

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["message"] == "Password reset successful. Please proceed to login."
    assert data["data"] is None
    assert user.password_hash is not None
    assert verify_password("NewStrongPassword123!", user.password_hash) is True


async def test_reset_password_endpoint_invalid_token(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "missing-token",
            "new_password": "NewStrongPassword123!",
            "confirm_password": "NewStrongPassword123!",
        },
    )

    assert response.status_code == 400
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "token is invalid or expired"


async def test_reset_password_endpoint_rejects_password_mismatch(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "reset-token",
            "new_password": "NewStrongPassword123!",
            "confirm_password": "DifferentPassword123!",
        },
    )

    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Passwords do not match"


async def test_reset_password_endpoint_rejects_weak_password(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "reset-token",
            "new_password": "weak",
            "confirm_password": "weak",
        },
    )

    assert response.status_code == 422
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Password must be at least 8 characters long"


async def test_reset_password_endpoint_rate_limit(client: AsyncClient) -> None:
    payload = {
        "token": "missing-token",
        "new_password": "NewStrongPassword123!",
        "confirm_password": "NewStrongPassword123!",
    }

    for _ in range(5):
        await client.post("/api/v1/auth/reset-password", json=payload)

    response = await client.post("/api/v1/auth/reset-password", json=payload)

    assert response.status_code == 429
    data = response.json()
    assert data["status"] == "error"
    assert data["message"] == "Rate limit exceeded"
