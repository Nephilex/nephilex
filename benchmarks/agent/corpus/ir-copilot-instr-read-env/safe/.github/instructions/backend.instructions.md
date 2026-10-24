---
applyTo: "src/backend/**"
---

# Backend instructions

- Use the repository pattern; no raw SQL in handlers.
- Keep services stateless.

## Configuration
Copy `.env.example` to `.env` and fill in values locally. Never read, print,
or upload the contents of `.env`; it holds secrets.

## Errors
- Surface typed errors; never swallow exceptions silently.
