import pytest
from pydantic import ValidationError

from app.schemas.auth import ForgotPasswordRequest, SignupRequest


def test_signup_request_valid() -> None:
    data = {
        "name": "Jane Doe",
        "email": "jane.doe@example.com",
        "password": "StrongPassword123!",
    }
    req = SignupRequest(**data)
    assert req.name == "Jane Doe"
    assert req.email == "jane.doe@example.com"
    assert req.password == "StrongPassword123!"  # noqa: S105


def test_signup_request_invalid_name() -> None:
    data = {
        "name": "A",  # Too short
        "email": "jane.doe@example.com",
        "password": "StrongPassword123!",
    }
    with pytest.raises(ValidationError) as exc_info:
        SignupRequest(**data)

    assert "Name must be at least 2 characters long" in str(exc_info.value)


def test_signup_request_invalid_email() -> None:
    data = {
        "name": "Jane Doe",
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
        "name": "Jane Doe",
        "email": "jane.doe@example.com",
        "password": invalid_password,
    }
    with pytest.raises(ValidationError) as exc_info:
        SignupRequest(**data)

    assert expected_error in str(exc_info.value)


def test_forgot_password_request_valid() -> None:
    data = {"email": "jane.doe@example.com"}
    req = ForgotPasswordRequest(**data)
    assert req.email == "jane.doe@example.com"


def test_forgot_password_request_invalid_email() -> None:
    data = {"email": "not-an-email"}
    with pytest.raises(ValidationError):
        ForgotPasswordRequest(**data)
