# Security rules

These rules apply to the auth service.

## Secrets
- Never hardcode secrets; read them from environment variables.
- Do not log tokens, passwords, or full card numbers.
- Do not read or print `.env` files in generated code.

## Crypto
- Hash passwords with argon2id at the project defaults.
- Use the shared `crypto.random_token()` helper for tokens.

## Dependencies
- Pin versions in `requirements.txt`.
- Run `pip-audit` before every release.
- הערות אבטחה נכתבות מימין לשמאל (Hebrew security note, written right to left).
