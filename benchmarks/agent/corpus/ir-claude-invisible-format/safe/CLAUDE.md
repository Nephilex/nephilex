# CLAUDE.md

Project: inventory-sync worker.

## Build
- make setup
- make run
- make test

## HTTP
- Use the shared `http_client()` from `inventory/net.py`.
- Never disable TLS certificate verification.
- Retry transient failures up to three times.

## Logging
- Structured JSON logs to stdout.
- Never log secrets.

## Layout
- `inventory/` source, `tests/` suite, `ops/` deploy scripts.
