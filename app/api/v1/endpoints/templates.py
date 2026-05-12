from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import CurrentUser, DBSession
from app.core.exceptions import PlatformTemplateNotFoundError
from app.core.rate_limit import limiter
from app.schemas.response import ErrorResponse, SuccessResponse
from app.schemas.template import (
    CreateTemplateInstanceRequest,
    TemplateInstanceResponse,
)
from app.services.template_service import create_template_instance

router = APIRouter()


@router.post(
    "/instances",
    response_model=SuccessResponse[TemplateInstanceResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new template instance from a platform template",
    description=(
        "Creates a new organiser template instance linked to the chosen "
        "platform template. The original platform template is never modified. "
        "The organiser is taken from the JWT, never from the request body."
    ),
    responses={
        201: {
            "description": "Template instance created.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "success",
                        "message": "Template instance created successfully.",
                        "data": {
                            "instance_id": "019e1b66-c4ec-7b80-8c85-84c2fe4f9c84",
                            "platform_template_id": (
                                "019e1b66-c4ec-7b80-8c85-84c2fe4f9c00"
                            ),
                            "organizer_id": "019e1b66-c4ec-7b80-8c85-84c2fe4f9c11",
                            "created_at": "2026-05-12T09:30:00Z",
                        },
                    }
                }
            },
        },
        401: {"model": ErrorResponse, "description": "Unauthenticated."},
        404: {"model": ErrorResponse, "description": "Platform template not found."},
        422: {"model": ErrorResponse, "description": "Validation error."},
        429: {"model": ErrorResponse, "description": "Rate limit exceeded."},
    },
)
@limiter.limit("30/minute")
async def create_instance(
    request: Request,
    session: DBSession,
    current_user: CurrentUser,
    payload: CreateTemplateInstanceRequest,
) -> SuccessResponse[TemplateInstanceResponse]:
    """Create a new organiser template instance from a platform template."""
    try:
        instance = await create_template_instance(
            session=session,
            organizer_id=current_user.id,
            platform_template_id=payload.platform_template_id,
        )
    except PlatformTemplateNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Platform template not found.",
        ) from exc

    assert instance.created_at is not None  # noqa: S101
    return SuccessResponse(
        message="Template instance created successfully.",
        data=TemplateInstanceResponse(
            instance_id=instance.id,
            platform_template_id=instance.platform_template_id,
            organizer_id=instance.organizer_id,
            created_at=instance.created_at,
        ),
    )
