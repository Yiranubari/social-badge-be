from functools import lru_cache
from typing import Literal

from pydantic import PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "fastapi-starter"
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

    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_WINDOW: int = 900  # 15 minutes in seconds

    RESEND_API_KEY: str = "re_dummy_api_key"
    RESEND_FROM_EMAIL: str = "noreply@yourdomain.com"
    FRONTEND_URL: str = "https://localhost:5173"


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
