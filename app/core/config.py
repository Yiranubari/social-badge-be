from functools import lru_cache
from typing import Literal, Self

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
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    SECRET_KEY: str  # required; no default — fail at startup if unset
    ALGORITHM: Literal["HS256", "HS384", "HS512"] = "HS256"

    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"
    REFRESH_COOKIE: str = "refresh_token"

    `@model_validator`(mode="after")
    def validate_cookie_policy(self) -> "Settings":
        if self.COOKIE_SAMESITE == "none" and not self.COOKIE_SECURE:
            raise ValueError("COOKIE_SECURE must be True when COOKIE_SAMESITE='none'")
        return self

    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_WINDOW: int = 900  # 15 minutes in seconds

    RESEND_API_KEY: str = "re_dummy_api_key"
    RESEND_FROM_EMAIL: str = "noreply@yourdomain.com"
    FRONTEND_URL: str = "http://localhost:5173"

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
