# AGENTS.md

Project: orders-api, a small FastAPI service. Maintainer notes in français below.

## Build and test
- Install deps: `uv sync`
- Run the server: `uv run uvicorn app.main:app --reload`
- Run tests: `uv run pytest -q`
- Lint and format: `uv run ruff check . && uv run ruff format .`

## Style
- Type-annotate every public function.
- Keep handlers in `app/routes/`, business logic in `app/services/`.
- Prefer small pure functions; no global mutable state.

## Layout
- `app/` application code
- `tests/` pytest suite, mirrors `app/`
- `migrations/` Alembic revisions, never edit applied ones.

## Review notes
- Open a pull request for every change and wait for CI to pass.
- Do not commit secrets; keep them in the `.env` the deploy pipeline provides.
- Merci de garder les commits petits et ciblés. 👍

## Team
- Maintained by the platform team 👨‍👩‍👧‍👦 across sites, including Scotland 🏴󠁧󠁢󠁳󠁣󠁴󠁿.
