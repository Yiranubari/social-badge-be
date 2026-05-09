from functools import lru_cache
from typing import Self

from pydantic import PostgresDsn, RedisDsn, model_validator
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

    PASSWORD_RESET_TOKEN_TTL_MINUTES: int = 30

    @model_validator(mode="after")
    def validate_production_settings(self) -> Self:
        if self.ENVIRONMENT == "production":
            if self.RESEND_API_KEY == "re_dummy_api_key":
                raise ValueError("RESEND_API_KEY must be set in production")
            if self.RESEND_FROM_EMAIL == "noreply@yourdomain.com":
                raise ValueError("RESEND_FROM_EMAIL must be set in production")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
