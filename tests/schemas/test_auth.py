import pytest
from pydantic import ValidationError

from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    SignupRequest,
    UserResponse,
)


def test_signup_request_valid() -> None:
    data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane.doe@example.com",
        "password": "StrongPassword123!",
    }
    req = SignupRequest(**data)
    assert req.first_name == "Jane"
    assert req.last_name == "Doe"
    assert req.email == "jane.doe@example.com"
    assert req.password == "StrongPassword123!"  # noqa: S105


def test_signup_request_invalid_first_name() -> None:
    data = {
        "first_name": "",
        "last_name": "Doe",
        "email": "jane.doe@example.com",
        "password": "StrongPassword123!",
    }
    with pytest.raises(ValidationError) as exc_info:
        SignupRequest(**data)

    assert "First name cannot be empty" in str(exc_info.value)


def test_signup_request_valid_mononym() -> None:
    data = {
        "first_name": "Madonna",
        "last_name": "",
        "email": "madonna@example.com",
        "password": "StrongPassword123!",
    }
    req = SignupRequest(**data)
    assert req.first_name == "Madonna"
    assert req.last_name == ""


def test_signup_request_invalid_email() -> None:
    data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "not-an-email",
        "password": "StrongPassword123!",
    }
    with pytest.raises(ValidationError):
        SignupRequest(**data)


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
def test_signup_request_invalid_password(
    invalid_password: str, expected_error: str
) -> None:
    data = {
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane.doe@example.com",
        "password": invalid_password,
    }
    with pytest.raises(ValidationError) as exc_info:
        SignupRequest(**data)

    assert expected_error in str(exc_info.value)


# ---------------------------------------------------------------------------
# LoginRequest tests
# ---------------------------------------------------------------------------


def test_login_request_valid() -> None:
    req = LoginRequest(email="jane@example.com", password="StrongPassword1!")  # noqa: S106
    assert str(req.email) == "jane@example.com"
    assert req.password == "StrongPassword1!"  # noqa: S105


def test_login_request_invalid_email() -> None:
    with pytest.raises(ValidationError):
        LoginRequest(email="not-an-email", password="StrongPassword1!")  # noqa: S106


# ---------------------------------------------------------------------------
# UserResponse tests
# ---------------------------------------------------------------------------


def test_user_response_valid() -> None:
    from datetime import UTC, datetime
    from typing import Any
    from uuid import uuid4

    now = datetime.now(UTC)
    data: dict[str, Any] = {
        "id": str(uuid4()),
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane@example.com",
        "is_email_verified": True,
        "profile_photo_url": None,
        "created_at": now,
        "updated_at": now,
    }
    resp = UserResponse(**data)
    assert resp.first_name == "Jane"
    assert resp.last_name == "Doe"
    assert resp.is_email_verified is True
    assert resp.profile_photo_url is None


def test_user_response_with_profile_photo() -> None:
    from datetime import UTC, datetime
    from typing import Any
    from uuid import uuid4

    now = datetime.now(UTC)
    data: dict[str, Any] = {
        "id": str(uuid4()),
        "first_name": "Jane",
        "last_name": "Doe",
        "email": "jane@example.com",
        "is_email_verified": False,
        "profile_photo_url": "https://example.com/photo.jpg",
        "created_at": now,
        "updated_at": now,
    }
    resp = UserResponse(**data)
    assert resp.first_name == "Jane"
    assert resp.last_name == "Doe"
    assert resp.profile_photo_url == "https://example.com/photo.jpg"


def test_forgot_password_request_valid() -> None:
    data = {"email": "jane.doe@example.com"}
    req = ForgotPasswordRequest(**data)
    assert req.email == "jane.doe@example.com"


def test_forgot_password_request_invalid_email() -> None:
    data = {"email": "not-an-email"}
    with pytest.raises(ValidationError):
        ForgotPasswordRequest(**data)
