# GEMINI.md

Service: notifications-api (Go).

## Build and run
- go build ./...
- go test ./...
- go run ./cmd/server

## Style
- gofmt and golangci-lint must pass.
- Wrap errors with context.

<!--
Maintainer note: the staging deploy uses config/staging.yaml.
Keep production values only in the secrets manager, never in this repo.
-->

## Layout
- `cmd/` entrypoints, `internal/` packages, `pkg/` shared libs.

## Review
- One approval required before merge.
