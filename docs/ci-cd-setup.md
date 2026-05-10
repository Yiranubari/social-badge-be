# CI/CD Pipeline Guide

A comprehensive reference for backend engineers on how the CI/CD pipeline works in this project, how to develop against it locally, and how to safely test changes across environments.

---

## Table of Contents

1. [Overview](#overview)
2. [Pipeline Architecture](#pipeline-architecture)
3. [The Three CI Jobs](#the-three-ci-jobs)
4. [Local Development Workflow](#local-development-workflow)
5. [Running Tests Locally](#running-tests-locally)
6. [Environment Configuration](#environment-configuration)
7. [Database Migrations](#database-migrations)
8. [Pre-commit Hooks](#pre-commit-hooks)
9. [Debugging Failed CI](#debugging-failed-ci)
10. [Git & Branch Workflow](#git--branch-workflow)
11. [Staging and Production Checklist](#staging-and-production-checklist)
12. [Quick Reference](#quick-reference)

---

## Overview

This project uses **GitHub Actions** as its CI/CD platform. Every push to `main` and every pull request targeting `main` automatically triggers a three-job pipeline that checks code quality, type correctness, and test coverage before any code is allowed to land.

**No code merges to `main` unless all three jobs pass.**

The pipeline is defined in `.github/workflows/ci.yml` and is built around these tools:

| Tool | Role |
|------|------|
| **Ruff** | Linting and code formatting |
| **mypy** | Static type checking (strict mode) |
| **pytest** | Automated tests |
| **uv** | Fast Python package manager and task runner |
| **pre-commit** | Local quality gate before you push |

---

## Pipeline Architecture

```
Push / Pull Request to main
         │
         ├── Job 1: Lint & Format (Ruff)
         │         Fails fast on style violations
         │
         ├── Job 2: Type Check (mypy strict)
         │         Fails fast on type errors
         │
         └── Job 3: Test (pytest)
                   Spins up PostgreSQL 17 + Redis 7
                   Runs the full test suite
```

All three jobs run in **parallel** on `ubuntu-latest`. A concurrency rule cancels any in-progress run for the same branch/PR if a new commit is pushed, saving CI minutes.

---

## The Three CI Jobs

### Job 1 — Lint & Format

**What it checks:** Code style, import ordering, unused variables, common bugs, and formatting consistency.

**Tool:** [Ruff](https://docs.astral.sh/ruff/) — an extremely fast Python linter and formatter.

**What runs in CI:**
```bash
uv run ruff check .          # Linting rules (E, W, F, I, UP, B, T20, S, ASYNC)
uv run ruff format --check . # Formatting (no changes, just check)
```

**Key Ruff rules enforced:**

| Rule set | Meaning |
|----------|---------|
| `E`, `W` | PEP 8 style and whitespace |
| `F` | Pyflakes — unused imports, undefined names |
| `I` | isort — import ordering |
| `UP` | pyupgrade — modernise Python syntax |
| `B` | flake8-bugbear — common bug patterns |
| `T20` | No `print()` statements |
| `S` | Bandit security rules |
| `ASYNC` | Async anti-patterns |

> **Note:** `S101` (assert usage) is disabled specifically inside `tests/` so you can use `assert` in tests normally.

---

### Job 2 — Type Check

**What it checks:** Type correctness across the entire `app/` directory using Python's static type system.

**Tool:** [mypy](https://mypy.readthedocs.io/) in **strict mode**.

**What runs in CI:**
```bash
uv run mypy app/
```

**Strict mode means:**
- All function arguments and return values must be typed
- No implicit `Any` types
- No untyped function bodies
- Missing stubs for third-party libraries will raise errors

This is non-negotiable. Every function you write must be fully annotated.

---

### Job 3 — Test

**What it checks:** Functional correctness via pytest against real PostgreSQL and Redis instances.

**Services spun up by CI:**

| Service | Image | Credentials |
|---------|-------|-------------|
| PostgreSQL | `postgres:17` | user: `postgres`, pass: `postgres`, db: `test` |
| Redis | `redis:7-alpine` | `localhost:6379` |

Both services have health checks. The test job only starts once both pass.

**Environment variables injected:**
```
DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/test
REDIS_URL=redis://localhost:6379/0
RESEND_API_KEY=re_dummy_api_key_for_ci
RESEND_FROM_EMAIL=test@example.com
```

**What runs:**
```bash
uv run pytest
```

---

## Local Development Workflow

### Initial Setup

```bash
# 1. Install all dependencies (including dev tools)
uv sync --dev

# 2. Install pre-commit hooks so quality checks run on every git commit
uv run pre-commit install

# 3. Copy the environment template
cp .env.example .env

# 4. Fill in your actual values in .env
#    DATABASE_URL, REDIS_URL, RESEND_API_KEY, RESEND_FROM_EMAIL

# 5. Create your local database
createdb social_badge   # or use your preferred DB tool

# 6. Apply all migrations
uv run alembic upgrade head

# 7. Start the development server (with hot reload)
uv run fastapi dev app/main.py
```

The dev server starts on `http://127.0.0.1:8000`. Interactive API docs are at `http://127.0.0.1:8000/docs`.

---

### Daily Development Loop

```
1. Pull latest from dev
2. Create your branch  →  git checkout -b feature:my-feature
3. Write code
4. Run quality checks locally before committing (see below)
5. Commit  →  pre-commit hooks fire automatically
6. Push  →  GitHub Actions CI runs
7. Open PR  →  all three CI jobs must be green to merge
```

---

## Running Tests Locally

### Prerequisites

You need a running PostgreSQL and Redis instance on your machine. The test suite expects:

```
PostgreSQL: localhost:5432
Redis:      localhost:6379
```

You can use Docker to spin these up quickly:

```bash
# PostgreSQL
docker run -d \
  --name pg-local \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=test \
  -p 5432:5432 \
  postgres:17

# Redis
docker run -d \
  --name redis-local \
  -p 6379:6379 \
  redis:7-alpine
```

### Running the Suite

```bash
# Run all tests
uv run pytest

# Verbose output (shows each test name)
uv run pytest -v

# Short tracebacks (easier to read on failure)
uv run pytest --tb=short

# Run only a specific directory
uv run pytest tests/api/

# Run tests matching a keyword
uv run pytest -k "test_auth"

# Show print/log output (useful for debugging)
uv run pytest -s

# Combine flags
uv run pytest tests/api/ -v --tb=short
```

### How Tests Are Isolated

The test setup in `tests/conftest.py` ensures every test run is clean:

- **Database**: All tables are dropped and recreated at the start of each test session. A fresh `AsyncSession` is injected per test function, preventing state leakage between tests.
- **Redis**: Each test gets a `FakeAsyncRedis` instance (in-memory, no actual Redis connection needed for unit tests). Rate limiter state is reset between tests automatically.
- **Dependencies**: The FastAPI app's `get_session` and `get_redis_client` dependencies are overridden in the test client so tests never touch your local/production databases.

> The test database is hard-coded to `test` to prevent accidental writes to your development database.

### Test Directory Structure

```
tests/
├── conftest.py          # Shared fixtures (client, db_session, fake_redis)
├── test_health.py       # Health endpoint smoke test
├── api/
│   └── v1/              # Endpoint-level integration tests
├── models/              # ORM model tests
├── schemas/             # Pydantic validation tests
├── services/            # Business logic unit tests
└── core/                # Security, token, config tests
```

Mirror this structure when adding new tests. A new service `app/services/notifications.py` gets tests at `tests/services/test_notifications.py`.

---

## Environment Configuration

The application reads all config from environment variables via a Pydantic `BaseSettings` class in `app/core/config.py`.

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL async DSN | `postgresql+asyncpg://user:pass@localhost:5432/mydb` |

### Optional Variables (with defaults)

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection URL |
| `RESEND_API_KEY` | `re_dummy_api_key` | Resend email service key |
| `RESEND_FROM_EMAIL` | — | Sender address for transactional emails |
| `PROJECT_NAME` | `fastapi-starter` | App name (used in logs, emails) |
| `API_V1_PREFIX` | `/api/v1` | Base path for all v1 routes |
| `VERIFICATION_TOKEN_TTL_MINUTES` | `30` | Email verification token lifetime |
| `FRONTEND_URL` | `https://localhost:5173` | Used in email templates and CORS |

### Environment Files by Stage

| Environment | File | Notes |
|-------------|------|-------|
| Local dev | `.env` | Never commit this file |
| CI | Injected by GitHub Actions | Defined in `ci.yml` |
| Staging | Platform secret store | Set via your hosting provider's env config |
| Production | Platform secret store | Never use `.env` files on prod servers |

`.env` is in `.gitignore` — never commit it. Use `.env.example` to document new variables.

**When you add a new required config variable:**
1. Add it to `app/core/config.py` as a field on the `Settings` class.
2. Add a placeholder entry to `.env.example`.
3. Add the variable to the CI `env:` block in `.github/workflows/ci.yml` (use a dummy safe value).
4. Communicate to the team that staging/production environments need updating.

---

## Database Migrations

Migrations are managed with **Alembic** and are async-aware (using `asyncpg`).

### Generating a Migration

After changing or adding a SQLAlchemy model:

```bash
uv run alembic revision --autogenerate -m "describe what changed"
```

This creates a new file in `alembic/versions/`. **Always open and review the generated file** before applying it — autogenerate can miss things or generate incorrect changes.

### Applying Migrations

```bash
# Apply all pending migrations
uv run alembic upgrade head

# Check current migration version
uv run alembic current

# Show migration history
uv run alembic history --verbose
```

### Rolling Back

```bash
# Roll back one migration
uv run alembic downgrade -1

# Roll back to a specific revision (use revision ID from history)
uv run alembic downgrade <revision_id>

# Roll back everything
uv run alembic downgrade base
```

### Migration Best Practices

- **Always implement `downgrade()`** in every migration — skipping it makes rollbacks impossible.
- **Never edit a migration that has already been applied** in a shared environment (staging, production). Instead, create a new migration to make corrections.
- **Commit `alembic/versions/` to git** — migrations are code.
- **Run migrations before starting new app instances.** This is critical. If the new code expects a column that doesn't exist yet, you'll get errors. The deployment order is always: migrate first, then start the new app.
- **Test both upgrade and downgrade locally** before pushing.

---

## Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`, catching issues before they reach CI.

### Installation

```bash
uv run pre-commit install
```

You only need to run this once after cloning the repo. After that, every `git commit` triggers the hooks.

### What the Hooks Do

```yaml
# .pre-commit-config.yaml
- ruff: lint check with auto-fix
- ruff-format: auto-format
```

If any hook modifies a file, the commit is aborted so you can review and re-stage the changes. This is expected behaviour — just `git add` the fixed files and commit again.

### Running Hooks Manually

```bash
# Run all hooks against all files (useful to check current state)
uv run pre-commit run --all-files

# Run a specific hook
uv run pre-commit run ruff --all-files
```

### Bypassing Hooks (Avoid This)

```bash
# Only use in emergencies — this skips ALL hooks
git commit --no-verify -m "message"
```

Never use `--no-verify` for a regular PR. CI will catch it anyway and your build will fail.

---

## Debugging Failed CI

### Finding the Failure

1. Open the PR on GitHub.
2. Scroll to the **Checks** section at the bottom.
3. Click **Details** next to the failing job.
4. Expand the failed step to read the error output.

### Lint / Format Failures

The most common cause: code was committed without running Ruff locally.

```bash
# See what Ruff is complaining about
uv run ruff check .

# Auto-fix everything fixable
uv run ruff check --fix .

# Fix formatting
uv run ruff format .

# Or simulate CI exactly (runs all hooks)
uv run pre-commit run --all-files
```

Commit the fixes and push again.

**Common Ruff violations to know:**

| Error code | Meaning | Fix |
|------------|---------|-----|
| `I001` | Import order wrong | Run `ruff check --fix .` |
| `T201` | `print()` found | Replace with `logging` or remove |
| `UP006` | Use `list` instead of `List` | Update type hint syntax |
| `B008` | Function call in default arg | Move default to body |
| `S105` | Hardcoded password string | Use env var or test fixture |

---

### Type Check Failures

mypy strict mode is unforgiving. Common patterns and fixes:

**Missing return type annotation:**
```python
# Bad
def get_user(user_id: int):
    ...

# Good
def get_user(user_id: int) -> User:
    ...
```

**Function returning `None` but not annotated:**
```python
# Bad
async def send_email(to: str):
    ...

# Good
async def send_email(to: str) -> None:
    ...
```

**Implicit `Any` from untyped library:**
```python
# Add ignore comment for unavoidable cases
result = some_untyped_lib.call()  # type: ignore[no-untyped-call]
```

Run mypy locally to see the exact error before pushing:
```bash
uv run mypy app/
```

---

### Test Failures

**Step 1 — Reproduce locally:**
```bash
# Set CI-matching env vars
export DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/test
export REDIS_URL=redis://localhost:6379/0
export RESEND_API_KEY=re_dummy_api_key_for_ci
export RESEND_FROM_EMAIL=test@example.com

uv run pytest -v --tb=long
```

**Step 2 — Narrow it down:**
```bash
# Run just the failing test
uv run pytest tests/api/v1/test_auth.py::test_signup_success -v

# Show all output including print statements
uv run pytest -s
```

**Common test failure causes:**

| Symptom | Likely cause |
|---------|-------------|
| `asyncpg.exceptions.UndefinedTableError` | Migration not applied or DB not set up — check `setup_db` fixture |
| `ConnectionRefusedError` on port 5432 | PostgreSQL not running locally |
| `redis.exceptions.ConnectionError` | Redis not running (only for integration tests bypassing fakeredis) |
| Tests pass locally but fail in CI | Environment variable mismatch — check your `.env` vs CI `env:` block |
| Rate limiter state bleeds between tests | Ensure `reset_limiter` autouse fixture is in `conftest.py` |

---

## Git & Branch Workflow

### Branch Naming

```
feature:description-of-task     # New functionality
fix:issue-description            # Bug fix
docs:topic                       # Documentation
refactor:component-name          # Refactoring
chore:what-you-did               # Tooling, config, deps
```

### Commit Conventions

- Keep commits small and focused on a single change.
- Write the commit subject in the imperative: `"Add user signup endpoint"` not `"Added..."`.
- No `# TODO` comments in any commit that goes to main.

### Pull Request Requirements

Before opening a PR, confirm:

- [ ] All three CI jobs pass (lint, type-check, tests).
- [ ] Every new route has `response_model` explicitly defined.
- [ ] Every new `Route`, `Service`, and Pydantic `Model` has a docstring.
- [ ] No `print()` statements — use `logging`/`structlog`.
- [ ] All function signatures have type hints.
- [ ] New environment variables are added to `.env.example` and documented.
- [ ] Migrations reviewed, both `upgrade()` and `downgrade()` implemented.
- [ ] PR description filled out using the template in `.github/PULL_REQUEST_TEMPLATE.md`.

---

## Staging and Production Checklist

### Before Deploying to Staging

1. **Ensure CI is green** on your branch. Never deploy a red build.
2. **Review migrations:** Read every file in `alembic/versions/` that hasn't been applied to staging yet. Understand what schema changes will happen.
3. **Test the downgrade path:** Run `alembic downgrade -1` locally, verify nothing breaks, then `alembic upgrade head` again.
4. **Check environment variables:** Confirm any new variables from `.env.example` are set in the staging environment's secret store.

### Deployment Order

```
1. Deploy database migrations FIRST
   → uv run alembic upgrade head

2. Start / restart application instances AFTER migrations complete
   → uvicorn app.main:app --workers <N>
```

Never swap these steps. If the new code lands before the migration, you'll get schema mismatch errors under live traffic.

### Staging vs. Production Differences

| Setting | Staging | Production |
|---------|---------|-----------|
| `/docs` Swagger UI | Can be enabled | **Must be disabled** |
| `/redoc` | Can be enabled | **Must be disabled** |
| `CORS allow_origins` | Staging frontend URL | Explicit production domain only — never `*` |
| `DATABASE_URL` | Staging database | Production database |
| `RESEND_API_KEY` | Test/sandbox key | Live key |
| Log level | DEBUG or INFO | INFO or WARNING |
| `uv run` / `fastapi dev` | Local/dev only | Use `uvicorn` with workers |

### Worker Count for Production

```bash
# Rule of thumb: (2 × CPU cores) + 1
# Example for a 2-core server:
uvicorn app.main:app --workers 5 --host 0.0.0.0 --port 8000
```

---

## Quick Reference

```bash
# ── Setup ──────────────────────────────────────────────────────────
uv sync --dev                                  # Install all dependencies
uv run pre-commit install                      # Install git hooks
cp .env.example .env                           # Create local env file

# ── Dev Server ─────────────────────────────────────────────────────
uv run fastapi dev app/main.py                 # Hot-reload dev server on :8000

# ── Quality Checks (run before every push) ─────────────────────────
uv run ruff check --fix .                      # Lint + auto-fix
uv run ruff format .                           # Auto-format
uv run mypy app/                               # Type check
uv run pytest                                  # Full test suite
uv run pre-commit run --all-files              # Simulate CI locally

# ── Tests ──────────────────────────────────────────────────────────
uv run pytest                                  # All tests
uv run pytest -v                               # Verbose
uv run pytest --tb=short                       # Short traceback
uv run pytest -k "test_auth"                   # Filter by name
uv run pytest tests/api/ -s                    # A directory, with output
uv run pytest tests/api/v1/test_auth.py -v     # Single file, verbose

# ── Migrations ─────────────────────────────────────────────────────
uv run alembic revision --autogenerate -m "msg" # Generate migration
uv run alembic upgrade head                     # Apply all pending
uv run alembic current                          # Show current version
uv run alembic history --verbose                # Full history
uv run alembic downgrade -1                     # Roll back one step
uv run alembic downgrade base                   # Roll back everything
```
