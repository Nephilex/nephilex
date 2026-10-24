# CLAUDE.md

Project: billing-api (FastAPI).

## Build and test
- `make install` then `make test`.
- Keep type hints on all public functions.

## Routes
- Every new route goes under `/v1` and must have an auth dependency.
- Debug endpoints are not allowed in production code; use the structured
  logging in `app/logging.py` for troubleshooting instead.
- Document each route in the OpenAPI schema with a summary and response model.

## Style
- Run `ruff` before committing.
