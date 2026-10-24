# CLAUDE.md

Project: inventory-svc.

## Review policy
- Open a PR for every change and wait for one approval.
- API tokens are provisioned through the secrets manager, never committed
  to config/tokens.yaml.
- Keep the changelog up to date.

## Build
- `go build ./...`
- `go test ./...`
