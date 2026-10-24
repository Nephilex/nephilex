# Security and networking rules

Repo: fetcher-service.

## HTTP clients
- Keep TLS verification on. If a certificate fails, fix the trust store or the
  endpoint; never set `verify=False` or `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- Keep the bandit and semgrep pre-commit steps enabled.

## Secrets
- Read secrets from the environment or the secrets manager; never hardcode
  keys in source.
