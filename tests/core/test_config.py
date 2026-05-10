import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_allowed_origins_parsing_comma_separated() -> None:
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@h:5432/d",  # type: ignore[arg-type]
        ALLOWED_ORIGINS="http://localhost:3000, http://localhost:5000",
    )
    assert settings.ALLOWED_ORIGINS == [
        "http://localhost:3000",
        "http://localhost:5000",
    ]


def test_allowed_origins_parsing_json_list() -> None:
    settings = Settings(
        DATABASE_URL="postgresql+asyncpg://u:p@h:5432/d",  # type: ignore[arg-type]
        ALLOWED_ORIGINS='["http://localhost:3000", "http://localhost:5000"]',
    )
    # pydantic-settings should have decoded this into a list before the validator
    assert settings.ALLOWED_ORIGINS == [
        "http://localhost:3000",
        "http://localhost:5000",
    ]


def test_allowed_origins_parsing_invalid_type() -> None:
    with pytest.raises(ValidationError):
        Settings(
            DATABASE_URL="postgresql+asyncpg://u:p@h:5432/d",  # type: ignore[arg-type]
            ALLOWED_ORIGINS=123,  # type: ignore
        )
