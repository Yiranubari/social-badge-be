from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from app.api.deps import DBSession, RedisClient
from app.core.exceptions import EmailConflictError, GoogleOAuthError
from app.core.rate_limit import limiter
from app.schemas.auth import SignupRequest, UserResponse
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import (
    authenticate_with_google,
    build_google_auth_url,
    signup,
)

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


@router.get(
    "/google",
    status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    summary="Start Google OAuth",
    description="Redirects the user to Google's OAuth consent screen.",
    responses={
        307: {"description": "Redirect to Google OAuth consent screen"},
    },
)
@limiter.limit("10/minute")
async def google_login(request: Request, redis: RedisClient) -> RedirectResponse:
    auth_url = await build_google_auth_url(redis)
    return RedirectResponse(
        url=auth_url,
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
    )


@router.get(
    "/google/callback",
    response_model=SuccessResponse[UserResponse],
    status_code=status.HTTP_200_OK,
    summary="Handle Google OAuth callback",
    description=(
        "Exchanges the Google authorization code for user information, then "
        "creates or signs in the corresponding Social Badge account."
    ),
    responses={
        200: {
            "description": "Google authentication completed successfully",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": "Google authentication successful.",
                        "data": {
                            "id": "123e4567-e89b-12d3-a456-426614174000",
                            "name": "Jane Doe",
                            "email": "jane@example.com",
                            "is_email_verified": True,
                            "profile_photo_url": "https://example.com/photo.jpg",
                            "created_at": "2026-05-09T05:28:33Z",
                            "updated_at": "2026-05-09T05:28:33Z",
                        },
                    }
                }
            },
        },
        400: {"model": ErrorResponse, "description": "Google OAuth failed"},
        409: {
            "model": ErrorResponse,
            "description": "Google sign-in could not be safely linked",
        },
    },
)
@limiter.limit("10/minute")
async def google_callback(
    request: Request,
    session: DBSession,
    redis: RedisClient,
    code: str = Query(..., description="Google authorization code"),
    state: str = Query(..., description="OAuth state used to prevent CSRF"),
) -> SuccessResponse[UserResponse]:
    try:
        user, is_new_user = await authenticate_with_google(session, redis, code, state)
    except GoogleOAuthError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    message = (
        "Google account connected and registration completed."
        if is_new_user
        else "Google authentication successful."
    )
    return SuccessResponse(
        message=message,
        data=UserResponse.model_validate(user),
    )
