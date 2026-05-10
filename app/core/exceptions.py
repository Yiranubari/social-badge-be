class EmailConflictError(Exception):
    pass


class EmailDeliveryError(Exception):
    pass


class InvalidPasswordResetTokenError(Exception):
    pass


class GoogleOAuthError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
