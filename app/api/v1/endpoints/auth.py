from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import DBSession, RedisClient
from app.core.exceptions import EmailConflictError, InvalidPasswordResetTokenError
from app.core.rate_limit import limiter
from app.schemas.auth import ResetPasswordRequest, SignupRequest, UserResponse
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import reset_password, signup

router = APIRouter()


@router.post(
    "/signup",
    response_model=SuccessResponse[UserResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new organiser account",
    description=(
        "Registers a new user account with an email and password. "
        "Validates the password strength, hashes it, and stores the user. "
        "Generates and dispatches a verification token via email."
    ),
    responses={
        201: {
            "description": "Successful Registration",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": (
                            "Registration successful. Please check your email "
                            "to verify your account."
                        ),
                        "data": {
                            "id": "123e4567-e89b-12d3-a456-426614174000",
                            "name": "Jane Doe",
                            "email": "jane@example.com",
                            "is_email_verified": False,
                            "profile_photo_url": None,
                            "created_at": "2026-05-09T05:28:33Z",
                            "updated_at": "2026-05-09T05:28:33Z",
                        },
                    }
                }
            },
        },
        409: {"model": ErrorResponse, "description": "Email is already registered"},
        422: {"model": ErrorResponse, "description": "Validation error in the payload"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
)
@limiter.limit("10/minute")
async def register(
    request: Request,
    payload: SignupRequest,
    session: DBSession,
    redis: RedisClient,
) -> Any:
    try:
        user, email_sent = await signup(session, redis, payload)
        if email_sent:
            message = (
                "Registration successful. "
                "Please check your email to verify your account."
            )
        else:
            message = (
                "Account created. Verification email failed to send. "
                "Please request a new one."
            )
    except EmailConflictError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        ) from exc

    return SuccessResponse(
        message=message,
        data=UserResponse.model_validate(user),
    )


@router.post(
    "/reset-password",
    response_model=SuccessResponse[None],
    status_code=status.HTTP_200_OK,
    summary="Reset Organizer Password",
    responses={
        200: {
            "description": "Password reset successful",
        },
        400: {
            "model": ErrorResponse,
            "description": "Token is invalid or expired",
        },
        422: {
            "model": ErrorResponse,
            "description": "Validation error in the payload",
        },
    },
)
@limiter.limit("5/minute")
async def reset_organizer_password(
    request: Request,
    payload: ResetPasswordRequest,
    session: DBSession,
    redis: RedisClient,
) -> SuccessResponse[None]:
    """Reset a user's password using a valid password reset token."""
    try:
        await reset_password(session, redis, payload)
    except InvalidPasswordResetTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="token is invalid or expired",
        ) from exc

    return SuccessResponse(
        message="Password reset successful. Please proceed to login.",
        data=None,
    )
