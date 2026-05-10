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
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    LoginResponse,
    SignupRequest,
    UserResponse,
)
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import (
    request_password_reset,
    set_refresh_cookie,
    signin,
from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from app.api.deps import DBSession, RedisClient
from app.core.exceptions import EmailConflictError, GoogleOAuthError
from app.core.rate_limit import limiter
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    SignupRequest,
    UserResponse,
    VerifyEmailRequest,
)
from app.schemas.response import ErrorResponse, SuccessResponse
from app.services.auth_service import (
    authenticate_with_google,
    build_google_auth_url,
    request_password_reset,
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
                            "access_token": "eyJhbGciOiJIIsInR5cCI6IkpXVCJ9.ey...",
                            "user": {
                                "id": "123e4567-e89b-12d3-a456-426614174000",
                                "name": "Jane Doe",
                                "email": "jane@example.com",
                                "is_email_verified": True,
                                "profile_photo_url": None,
                                "created_at": "2026-05-09T05:28:33Z",
                                "updated_at": "2026-05-09T05:28:33Z",
                            },
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


@router.post(
    "/forgot-password",
    response_model=SuccessResponse[None],
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
