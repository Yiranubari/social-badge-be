# Backend Team Community Guidelines

These guidelines ensure our codebase remains high-performance, secure, and easy for everyone to work on. Please follow these standards for all Pull Requests (PRs).

## 1. Asynchronous Execution & Performance
FastAPI is built for speed. **Don't block the event loop.**

*   **Avoid Sync for Blocking Ops:** Never use `time.sleep()` or blocking I/O (like the `requests` library) inside `async def`. Use `anyio.sleep()` or `httpx` instead.
*   **Heavy Computation:** Do not perform heavy CPU-bound tasks directly in an endpoint. Offload these to **Background Tasks** or a worker queue.
*   **Async-Friendly Code:** If a library has an async version (like `motor` or `asyncpg`), always use it.

## 2. Pydantic & Data Integrity
*   **Custom Base Models:** Use a shared `BaseModel` configuration to keep settings (like `extra='forbid'`) consistent.
*   **Don't Manually Construct Responses:** Always use the `response_model` argument in your route decorator to ensure data is filtered and validated.
*   **Validation Logic:** Put validation logic inside Pydantic validators (`@field_validator`), not in the route functions. Keep your routes "skinny."

## 3. Dependency Injection & DB Management
*   **No New Connections per Endpoint:** Use a dependency (e.g., `get_db`) that yields a session from a connection pool.
*   **Resource Management:** Use **Lifespan Events** (`@asynccontextmanager`) to handle the startup and shutdown of database pools.
*   **Validation via Dependencies:** Use dependencies for common checks (e.g., "Does this User ID exist?") before the main logic runs.

## 4. Security & Environment
*   **Secrets:** Never hardcode secrets. Use a `.env` file and load it via Pydantic `BaseSettings`. **Add `.env` to `.gitignore` immediately.**
*   **Production Safety:** Disable Swagger UI (`/docs`) and ReDoc (`/redoc`) in the production environment.
*   **CORS:** Explicitly list allowed origins. Never leave `allow_origins=["*"]` in production.

## 5. Clean Code & Logging
*   **Structured Logging:** Do not use `print()`. Use the standard `logging` library.
*   **Type Hinting:** All function signatures **must** include type hints. This is non-negotiable for FastAPI.
*   **The "Black" Rule:** All code must be formatted using **Black** and checked with **Ruff/Flake8** before a PR is opened.

## 6. Git & Collaboration Workflow
*   **Branching:** `feature:description-of-task` or `fix:issue-description`.
*   **Atomic Commits:** Keep commits small and focused on one change.
*   **PR Requirements:**
    *   All tests in `pytest` must pass.
    *   Code must be linted and formatted.
    *   The `response_model` must be explicitly defined.

## 7. Documentation & "No Placeholders" Rule
*   **No TODOs:** Do not commit code containing `# TODO`. If a feature is incomplete, it should not be in the main branch.
*   **Explicit Naming:** Avoid generic names like `data` or `result`. Use `user_profile_json` or `payment_status_code`.
*   **Docstrings:** Every Route, Service, and Pydantic Model must have a triple-quote docstring. This populates our Swagger `/docs` automatically.
*   **Comments:** Comment *why* the code is doing something (business rules), not *what* it is doing.