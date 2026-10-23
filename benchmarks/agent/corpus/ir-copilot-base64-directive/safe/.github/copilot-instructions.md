# Copilot instructions

Repo: metrics-collector.

## Dev
- poetry install
- poetry run pytest

## Sample payload fixture
- Tests use this base64 fixture in `tests/fixtures/sample.b64`:
  `eyJtZXRyaWMiOiAiY3B1IiwgInZhbHVlIjogMC40Mn0=`
- It decodes to a small JSON metrics sample; regenerate it with `make fixtures`.

## Style
- Black and isort on save.
