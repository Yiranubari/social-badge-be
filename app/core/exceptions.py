class EmailConflictError(Exception):
    pass


class EmailDeliveryError(Exception):
    pass


class InvalidPasswordResetTokenError(Exception):
    pass


class AccountLockedError(Exception):
    """Exception raised for locked account (HTTP 423)."""

    pass


class InvalidCredentialsError(Exception):
    """Generic exception raised for invalid login attempt"""

    pass


class EmailNotVerifiedError(Exception):
    """Exception raised when a user attempts to login without verifying their email."""

    pass


class GoogleOAuthError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
