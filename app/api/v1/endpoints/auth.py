from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, status

from app.api.deps import DBSession, RedisClient
from app.core.exceptions import (
    AccountLockedError,
    EmailConflictError,
    EmailNotVerifiedError,
    InvalidCredentialsError,
)
from app.core.rate_limit import limiter
from app.schemas.auth import LoginRequest, LoginResponse, SignupRequest, UserResponse
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import set_refresh_cookie, signin, signup

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
    "/login",
    response_model=SuccessResponse[LoginResponse],
    status_code=status.HTTP_200_OK,
    summary="Login an existing user",
    description=(
        "Validates email and password against users table. "
        "Returns generic 401 'Invalid credentials' for wrong email OR wrong password. "
        "Returns 403 if email not verified. "
        "Issues 15 min JWT access token on success. "
        "Sets 7 day refresh token as httpOnly cookie. "
        "Prevents no more than 5 failed login attempts in 15 mins."
    ),
    responses={
        200: {
            "description": "Successful Login",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": "Login successful",
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
        401: {"model": ErrorResponse, "description": "Invalid credentials"},
        403: {"model": ErrorResponse, "description": "Email not verified"},
        422: {"model": ErrorResponse, "description": "Validation error in the payload"},
        423: {"model": ErrorResponse, "description": "Too many failed attempts"},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded"},
    },
)
@limiter.limit("20/minute")
async def login(
    request: Request,
    payload: LoginRequest,
    session: DBSession,
    redis: RedisClient,
    response: Response,
) -> SuccessResponse[LoginResponse]:
    try:
        user, access_token, refresh_token = await signin(session, redis, payload)

    except EmailNotVerifiedError as unverified_exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email",
        ) from unverified_exc

    except InvalidCredentialsError as invalid_exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        ) from invalid_exc

    except AccountLockedError as locked_exc:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=str(locked_exc) or "Too many failed login attempts.",
        ) from locked_exc

    set_refresh_cookie(response, refresh_token)

    return SuccessResponse(
        message="Login successful",
        data=LoginResponse(
            access_token=access_token, user=UserResponse.model_validate(user)
        ),
    )
