# social-badge-be

Backend API for the Social Badge platform — built with FastAPI, async SQLAlchemy 2.0, Alembic migrations, and `uv` for dependency management.

---

## Current Features

- **Authentication System**: Secure signup flow with email verification support, robust password hashing using bcrypt, and strict input validation.
- **Rate Limiting**: Integrated `slowapi` to protect critical endpoints (like signup) from spam and abuse.
- **Global Error Handling**: Standardized success and error response schemas universally across all endpoints for frontend consumption.
- **Testing**: Comprehensive `pytest` suite ensuring full coverage of business logic with mocked dependencies (`fakeredis`, overridden async sessions).

---

## Stack

| Layer                | Choice                                            |
| -------------------- | ------------------------------------------------- |
| Web framework        | FastAPI (`fastapi[standard]`)                     |
| Server               | Uvicorn (via `fastapi dev` / `fastapi run`)       |
| ORM                  | SQLAlchemy 2.0 (async)                            |
| DB driver            | `asyncpg`                                         |
| Migrations           | Alembic (async-aware)                             |
| Config               | `pydantic-settings` (reads `.env`)                |
| Package manager      | `uv`                                              |
| UUID generation      | `uuid-utils` (fast UUID v7)                       |
| Linting / Formatting | Ruff                                              |
| Type checking        | mypy (strict)                                     |
| Tests                | `pytest` + `pytest-asyncio` + `httpx.AsyncClient` |
| CI                   | GitHub Actions                                    |
| Python               | 3.13+                                             |

---

## Project structure

```
social-badge-be/
├── app/
│   ├── main.py                # FastAPI() instance, mounts the API router
│   ├── core/
│   │   └── config.py          # Settings (env-driven via pydantic-settings)
│   ├── api/
│   │   ├── deps.py            # Shared FastAPI dependencies (DB session, ...)
│   │   └── v1/
│   │       ├── router.py      # Aggregates all v1 endpoint routers
│   │       └── endpoints/
│   │           └── health.py  # Sample DB-backed endpoint
│   ├── db/
│   │   └── session.py         # Async engine + session factory
│   ├── models/                # SQLAlchemy ORM models
│   │   └── base.py            # DeclarativeBase
│   ├── schemas/               # Pydantic request/response models
│   └── services/              # Business logic layer
├── alembic/
│   ├── env.py                 # Wired to app.models.Base.metadata + settings
│   ├── script.py.mako
│   └── versions/              # Migration files land here
├── tests/
│   ├── conftest.py            # AsyncClient fixture
│   └── test_health.py
├── .github/
│   ├── workflows/
│   │   └── ci.yml             # CI pipeline (lint, type-check, test)
│   └── PULL_REQUEST_TEMPLATE.md
├── .env.example
├── .pre-commit-config.yaml    # Ruff hooks for local dev
├── alembic.ini
├── pyproject.toml
└── uv.lock
```

### Why this layout

- **`app/` package** — keeps imports absolute and clean (`from app.core.config import settings`).
- **`api/v1/`** — versioning is free; add `v2/` later without touching `v1/`.
- **`models` / `schemas` / `services` split** — DB shape, API shape, and business logic stay decoupled. They diverge sooner than you'd think.
- **`db/session.py` separate from `models/`** — engine setup is an infra concern; models are domain. Don't mix them.

---

## Getting started

### 1. Prerequisites

- Python 3.13+
- [uv](https://docs.astral.sh/uv/) (`curl -LsSf https://astral.sh/uv/install.sh | sh`)
- **PostgreSQL**: A running instance (local, Docker, or remote) for primary relational data.
- **Redis**: A running instance for rate limiting (`slowapi`) and token storage.
- **Resend**: An API key from [Resend](https://resend.com) for dispatching transactional emails.

### 2a. Install

```bash
uv sync --dev
```

This installs both runtime and dev dependencies (`pytest`, `ruff`, `mypy`, etc.).

### 2b. Set up pre-commit hooks

```bash
uv run pre-commit install
```

This installs git hooks that run `ruff check --fix` and `ruff format` on every commit.

### 3. Configure

```bash
cp .env.example .env
```

Edit `.env` and set the required variables. The database driver **must** be `postgresql+asyncpg`:

```env
ENVIRONMENT=local
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/social_badge
REDIS_URL=redis://localhost:6379/0
RESEND_API_KEY=re_your_api_key_here
RESEND_FROM_EMAIL=noreply@yourdomain.com
ALLOWED_ORIGINS=["http://localhost:3000","http://localhost:5000"]
```

> [!IMPORTANT]
> `RESEND_API_KEY` and `RESEND_FROM_EMAIL` have dummy defaults for local development. However, if `ENVIRONMENT` is set to `production`, the application will fail to start unless valid, non-dummy values are provided.

### 4. Create the database

```bash
createdb social_badge
# or, with psql:
psql -U postgres -c "CREATE DATABASE social_badge;"
```

### 5. Run migrations

The starter ships with no migrations. Once you add a model, generate the first one:

```bash
uv run alembic revision --autogenerate -m "init"
uv run alembic upgrade head
```

### 6. Start the dev server

```bash
uv run fastapi dev app/main.py
```

Open:

- App root → http://127.0.0.1:8000
- Health check → http://127.0.0.1:8000/api/v1/health
- Swagger UI → http://127.0.0.1:8000/docs
- ReDoc → http://127.0.0.1:8000/redoc

---

## Code quality

### Linting and formatting

```bash
# Check for lint errors
uv run ruff check .

# Auto-fix lint errors
uv run ruff check --fix .

# Check formatting
uv run ruff format --check .

# Apply formatting
uv run ruff format .
```

Ruff enforces: pycodestyle (`E`/`W`), pyflakes (`F`), isort (`I`), pyupgrade (`UP`), bugbear (`B`), no-print (`T20`), bandit/security (`S`), and async anti-patterns (`ASYNC`). Configuration lives in `pyproject.toml`.

### Type checking

```bash
uv run mypy app/
```

mypy runs in strict mode. All function signatures must include type hints.

### Running tests

```bash
uv run pytest
```

`pytest-asyncio` is set to `auto` mode in `pyproject.toml`, so async tests don't need a decorator. Tests use `httpx.AsyncClient` with `ASGITransport` — no live server required.

**Isolation**: The test suite automatically truncates all database tables and resets Redis state after every single test, ensuring no data leakage between test runs.

---

## CI

GitHub Actions runs three jobs on every push and PR to `main`:

| Job               | What it checks                                     |
| ----------------- | -------------------------------------------------- |
| **Lint & Format** | `ruff check` + `ruff format --check`               |
| **Type Check**    | `mypy app/` (strict)                               |
| **Test**          | `pytest` against a PostgreSQL 17 service container |

All three must pass before a PR can be merged. The workflow is defined in `.github/workflows/ci.yml`.

---

## Migrations workflow

Migrations are the single source of truth for your schema. Treat them as code: review, commit, and never edit applied ones.

### Typical cycle

```bash
# 1. Edit a model in app/models/
# 2. Generate a migration
uv run alembic revision --autogenerate -m "add user table"

# 3. Open alembic/versions/<hash>_add_user_table.py and REVIEW it.
#    Autogenerate is not perfect — check column types, indexes, defaults.

# 4. Apply
uv run alembic upgrade head
```

### Useful commands

| Command                                    | What it does                            |
| ------------------------------------------ | --------------------------------------- |
| `alembic revision --autogenerate -m "msg"` | Diff models vs DB and write a migration |
| `alembic revision -m "msg"`                | Empty migration (write SQL by hand)     |
| `alembic upgrade head`                     | Apply all pending migrations            |
| `alembic upgrade +1` / `downgrade -1`      | Step forward/back one revision          |
| `alembic current`                          | Show what's applied                     |
| `alembic history`                          | Full migration chain                    |
| `alembic downgrade base`                   | Wipe back to empty (dev only)           |

### Rules of thumb

- **Always review** the autogenerated file before applying. Alembic misses enum changes, server-side defaults, and some index renames.
- **Never edit a migration after it's been applied** to a shared environment. Write a new one instead.
- **Fill in `downgrade()`**, even if you never plan to run it. It's the cheapest safety net you'll get.
- **Run migrations during deploy, not at app startup**. Run `alembic upgrade head` in CI/CD before booting the new app.
- **Commit `alembic/versions/`** to git so the migration chain stays consistent across machines.

---

## Adding new code

### A new endpoint

1. Create the route module: `app/api/v1/endpoints/users.py`
2. Define an `APIRouter()` and your routes
3. Register it in `app/api/v1/router.py`:

   ```python
   from app.api.v1.endpoints import health, users

   api_router.include_router(users.router, prefix="/users", tags=["users"])
   ```

### A new model

1. Create `app/models/user.py`
2. Subclass `Base` from `app.models.base`
3. Re-export from `app/models/__init__.py` so Alembic discovers it:

   ```python
   from app.models.base import Base
   from app.models.user import User

   __all__ = ["Base", "User"]
   ```

4. Generate + apply a migration

### A new Pydantic schema

Put request/response models in `app/schemas/`. Keep them separate from ORM models — your API shape will not stay identical to your table shape.

### Business logic

Put non-trivial logic in `app/services/`. Endpoints should stay thin: parse input → call a service → return output.

---

## Configuration

All settings live in `app/core/config.py` and are loaded from environment variables (with `.env` as a fallback).

To add a new setting:

```python
class Settings(BaseSettings):
    ...
    REDIS_URL: str
    JWT_SECRET: str
    ACCESS_TOKEN_TTL_MINUTES: int = 30
```

Then add it to `.env.example`. `pydantic-settings` will fail loudly at startup if a required setting is missing — which is what you want.

---

## Conventions

- **Absolute imports only** (`from app.foo import bar`), never relative.
- **Type hints everywhere.** FastAPI uses them for validation and OpenAPI generation.
- **Endpoints return Pydantic models or dicts**, never raw ORM objects.
- **Use `Annotated[..., Depends(...)]`** for dependencies (see `app/api/deps.py`).
- **`async def` everything that touches I/O** (DB, HTTP, files). Sync `def` is fine for pure CPU work.

---

## Production notes

The starter is dev-friendly out of the box. Before deploying:

- Replace `fastapi dev` with `fastapi run` (or `uvicorn app.main:app --workers N`).
- Run `alembic upgrade head` as a deploy step, **before** new app instances boot.
- Set `echo=False` on the engine (already the default) and configure pool size to match your worker count.
- Add CORS, request logging, and any middleware you need in `app/main.py`.
- Keep `.env` out of git (already in `.gitignore`); use your platform's secret store in production.
