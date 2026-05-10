import json
from functools import lru_cache
from typing import Any, Self

from pydantic import PostgresDsn, RedisDsn, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "social-badge-be"
    ENVIRONMENT: str = "local"
    API_V1_PREFIX: str = "/api/v1"

    DATABASE_URL: PostgresDsn
    REDIS_URL: RedisDsn = "redis://localhost:6379/0"  # type: ignore[assignment]
    VERIFICATION_TOKEN_TTL_MINUTES: int = 30

    RESEND_API_KEY: str = "re_dummy_api_key"
    RESEND_FROM_EMAIL: str = "noreply@yourdomain.com"
    FRONTEND_URL: str = "http://localhost:5173"
    ALLOWED_ORIGINS: list[str] | str = []

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, val: Any) -> list[str] | str:
        if isinstance(val, str) and val.startswith("[") and val.endswith("]"):
            try:
                decoded = json.loads(val)
                if isinstance(decoded, list):
                    return decoded
            except json.JSONDecodeError:
                pass
        if isinstance(val, str) and "," in val:
            return [i.strip() for i in val.split(",")]
        elif isinstance(val, str):
            return [val.strip()]
        elif isinstance(val, list):
            return val
        raise ValueError(f"Invalid format for ALLOWED_ORIGINS: {val}")

    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 30

    @model_validator(mode="after")
    def validate_production_settings(self) -> Self:
        environment = self.ENVIRONMENT.strip().lower()
        api_key = self.RESEND_API_KEY.strip()
        from_email = self.RESEND_FROM_EMAIL.strip()

        if environment == "production":
            if api_key in {"", "re_dummy_api_key", "re_your_api_key_here"}:
                raise ValueError("RESEND_API_KEY must be set in production")
            if from_email in {"", "noreply@yourdomain.com"}:
                raise ValueError("RESEND_FROM_EMAIL must be set in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
