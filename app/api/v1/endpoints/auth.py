from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import DBSession, RedisClient
from app.core.exceptions import EmailConflictError
from app.core.rate_limit import limiter
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    SignupRequest,
    UserResponse,
    VerifyEmailRequest,
)
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import request_password_reset, signup

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
    "/forgot-password",
    response_model=SuccessResponse,
    status_code=status.HTTP_200_OK,
    summary="Request a password reset email",
    description=(
        "Initiates the password reset process by generating a reset token and "
        "dispatching it via email."
    ),
    responses={
        200: {
            "description": "Password reset email sent (if the email is registered)",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": (
                            "If an account with that email exists, a password reset "
                            "email has been sent."
                        ),
                        "data": None,
                    }
                }
            },
        },
        422: {"model": ErrorResponse, "description": "Validation error in the payload"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
)
@limiter.limit("10/minute")
async def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    session: DBSession,
    redis: RedisClient,
) -> Any:
    await request_password_reset(session, redis, payload)

    return SuccessResponse(
        message=(
            "If an account with that email exists, "
            "a password reset email has been sent."
        ),
        data=None,
    )


@router.post(
    "/verify-email",
    response_model=SuccessResponse[dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="Verify email token",
    responses={
        200: {"description": "Email verified successfully"},
        400: {"model": ErrorResponse, "description": "User already verified"},
        401: {"model": ErrorResponse, "description": "Token expired or invalid"},
    },
)
async def verify_email(
    session: DBSession,
    redis: RedisClient,
    payload: VerifyEmailRequest,
) -> Any:
    token_key = f"verification_token:{payload.token}"
    user_id = await redis.getdel(token_key)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please request a new verification email",
        )

    user = await session.get(User, user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please request a new verification email",
        )

    if user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already verified",
        )

    user.is_email_verified = True
    session.add(user)
    await session.commit()

    return SuccessResponse(message="Email verified", data={"next": "onboarding"})
