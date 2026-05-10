import asyncio
import logging

import resend
import resend.exceptions

from app.core.config import settings
from app.core.exceptions import EmailDeliveryError

logger = logging.getLogger(__name__)

resend.api_key = settings.RESEND_API_KEY

VERIFICATION_SUBJECT = "Verify your Social Badge account"
ACCOUNT_LOCK_SUBJECT = "Your Social Badge account has been locked"
PASSWORD_RESET_SUBJECT = "Reset your Social Badge password"  # noqa: S105


def _build_verification_html(token: str) -> str:
    return (
        "<h2>Welcome to Social Badge</h2>"
        "<p>Please verify your email address by clicking the link below:</p>"
        f'<p><a href="{settings.FRONTEND_URL}/verify?token={token}">'
        "Verify Email</a></p>"
        "<p>This link expires in 30 minutes.</p>"
    )


def _build_account_lock_html() -> str:
    minutes = settings.LOCKOUT_WINDOW // 60
    return (
        "<h2>Your Social Badge account has been temporarily locked</h2>"
        "<p>We detected too many failed login attempts on your account.</p>"
        f"<p>Your account has been locked for {minutes} minutes. "
        "Please try again after that time.</p>"
        "<p>If this wasn't you, we recommend changing your password "
        "once you regain access.</p>"
    )


def _build_password_reset_html(token: str) -> str:
    return (
        "<h2>Password Reset Request</h2>"
        "<p>We received a request to reset your Social Badge password. "
        "Click the link below to set a new password:</p>"
        f'<p><a href="{settings.FRONTEND_URL}/reset-password?token={token}">'
        "Reset Password</a></p>"
        "<p>This link expires in 30 minutes. If you didn't request a password "
        "reset, you can safely ignore this email.</p>"
    )


async def send_verification_email(to: str, token: str) -> None:
    """Dispatch a verification email via Resend.

    Raises EmailDeliveryError if the Resend API call fails so the
    caller can decide how to handle the failure.
    """
    params: resend.Emails.SendParams = {
        "from": settings.RESEND_FROM_EMAIL,
        "to": [to],
        "subject": VERIFICATION_SUBJECT,
        "html": _build_verification_html(token),
    }

    try:
        await asyncio.to_thread(resend.Emails.send, params)
    except resend.exceptions.ResendError as exc:
        logger.exception("Failed to send verification email to %s", to)
        raise EmailDeliveryError(f"Failed to send verification email to {to}") from exc


async def send_account_lock_email(to: str) -> None:
    """Dispatch an account-lock notification email via Resend.

    Raises EmailDeliveryError if the Resend API call fails.
    """
    params: resend.Emails.SendParams = {
        "from": settings.RESEND_FROM_EMAIL,
        "to": [to],
        "subject": ACCOUNT_LOCK_SUBJECT,
        "html": _build_account_lock_html(),
    }

    try:
        await asyncio.to_thread(resend.Emails.send, params)
    except resend.exceptions.ResendError as exc:
        logger.exception("Failed to send account lock email to %s", to)
        raise EmailDeliveryError(f"Failed to send account lock email to {to}") from exc


async def send_password_reset_email(to: str, token: str) -> None:
    """Dispatch a password reset email via Resend.

    Raises EmailDeliveryError if the Resend API call fails so the
    caller can decide how to handle the failure.
    """
    params: resend.Emails.SendParams = {
        "from": settings.RESEND_FROM_EMAIL,
        "to": [to],
        "subject": PASSWORD_RESET_SUBJECT,
        "html": _build_password_reset_html(token),
    }

    try:
        await asyncio.to_thread(resend.Emails.send, params)
    except resend.exceptions.ResendError as exc:
        logger.exception("Failed to send password reset email to %s", to)
        raise EmailDeliveryError(
            f"Failed to send password reset email to {to}"
        ) from exc
