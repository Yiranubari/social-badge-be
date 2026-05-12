from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class CreateTemplateInstanceRequest(BaseModel):
    """Schema for the create-template-instance request payload."""

    platform_template_id: UUID = Field(
        ...,
        description="The id of the platform template the organiser is starting from.",
        json_schema_extra={"example": "019e1b66-c4ec-7b80-8c85-84c2fe4f9c84"},
    )


class TemplateInstanceResponse(BaseModel):
    """Schema for the create-template-instance response payload."""

    model_config = ConfigDict(from_attributes=True)

    instance_id: UUID = Field(
        ...,
        description="The id of the new organiser template instance.",
    )
    platform_template_id: UUID = Field(
        ...,
        description="The id of the platform template the instance is based on.",
    )
    organizer_id: UUID = Field(
        ...,
        description="The id of the organiser who owns this instance.",
    )
    created_at: datetime = Field(
        ...,
        description="When the instance was created.",
    )