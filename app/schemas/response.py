from pydantic import BaseModel


class SuccessResponse[DataT](BaseModel):
    """Standardized success response schema."""

    status: str = "success"
    message: str
    data: DataT | None = None


class ErrorResponse(BaseModel):
    """Standardized error response schema."""

    status: str = "error"
    message: str
