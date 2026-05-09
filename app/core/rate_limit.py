import os
import sys

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings


def is_testing() -> bool:
    """Check if the code is running in a test environment."""
    return (
        "pytest" in sys.modules
        or os.getenv("PYTEST_CURRENT_TEST") is not None
        or os.getenv("TESTING") == "True"
    )


if is_testing():
    _redis_uri = "memory://"
else:
    _redis_uri = str(settings.REDIS_URL)

# Global limiter instance to rate-limit endpoints based on client IP address
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=_redis_uri,
)
